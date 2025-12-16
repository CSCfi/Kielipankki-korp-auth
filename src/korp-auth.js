const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const debug = require('debug');
const config = require('./config');
const logger = require('./logger');

// Debug namespaces for verbose logging (enable with DEBUG=korp-auth:*)
const debugHeaders = debug('korp-auth:headers');
const debugJwt = debug('korp-auth:jwt');
const debugAuth = debug('korp-auth:auth');

const app = express();
const SOCKET_PATH = config.socketPath;

// Secret for signing JWTs
const JWT_SECRET = fs.readFileSync(config.jwtPrivateKeyPath, 'utf8');
const API_KEY = config.minkApiKey;

const auth_cookie_name = config.authCookieName;

const auth_db = require('./db.js');
auth_db.create_db_if_missing();

// In-memory token blacklist for logout functionality (local mode only)
const blacklistedTokens = new Set();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

const fallback_redirect_uri = config.fallbackRedirectUri;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Parse eduPersonEntitlement header into array of URNs
 * Apache may pass this as a string (semicolon-separated) or array
 */
function parseEntitlements(headerValue) {
  if (!headerValue) {
    return [];
  }

  // If already an array, return it
  if (Array.isArray(headerValue)) {
    return headerValue;
  }

  // If string, split by semicolon and trim whitespace
  if (typeof headerValue === 'string') {
    return headerValue
      .split(';')
      .map(urn => urn.trim())
      .filter(urn => urn.length > 0);
  }

  return [];
}

// ============================================================================
// LOGIN ENDPOINT (Development mode only)
// ============================================================================

/**
 * GET /login
 *
 * Production mode: Not available (Apache handles login/redirect)
 * Development mode: Shows login form
 */
app.get('/login', (req, res) => {
  // PRODUCTION MODE: Not available (Apache handles login/redirect)
  if (config.isProduction) {
    return res.status(404).json({
      error: 'Not available in production mode',
      message: 'Login and redirect is handled by Apache. Use /jwt endpoint to get JWT token.'
    });
  }

  // DEVELOPMENT MODE: Show login form
  const { redirect, client_id, state, destination } = req.query;
  const finalRedirectUri = redirect || fallback_redirect_uri;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>KP Auth - Development Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
            .login-form { border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
            .dev-notice { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
            input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
            button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="login-form">
            <div class="dev-notice">
                <strong>⚠️ Development Mode</strong><br>
                In production, authentication is handled by Apache.
            </div>
            <h2>Login</h2>
            <form action="auth" method="post">
                <input type="hidden" name="redirect_uri" value="${finalRedirectUri || ''}" />
                <input type="hidden" name="client_id" value="${client_id || ''}" />
                <input type="hidden" name="state" value="${state || ''}" />

                <input type="email" name="username" placeholder="Email" required />
                <input type="password" name="password" placeholder="Password" required />
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
  `);
});

// ============================================================================
// DEVELOPMENT MODE ENDPOINTS (NODE_ENV=development)
// ============================================================================

// Handle login form submission (development mode only)
app.post('/auth', (req, res) => {
  if (config.isProduction) {
    return res.status(404).json({
      error: 'Not available in production mode',
      message: 'Authentication is handled by Apache.'
    });
  }

  const { username, password, redirect_uri } = req.body;

  // Validate credentials
  if (!auth_db.user_exists(username) || auth_db.get_user_password(username) !== password) {
    return res.status(401).send(`
      <h2>Login Failed</h2>
      <p>Invalid credentials. <a href="login?redirect_uri=${redirect_uri}">Try again</a></p>
    `);
  }

  const authCode = jwt.sign({ username, timestamp: Date.now() }, JWT_SECRET, { expiresIn: '10m', algorithm: 'RS256' });

  res.cookie(auth_cookie_name,
             authCode, { httpOnly: false,
                         secure: false,     // Allow HTTP in dev mode
                         sameSite: 'lax',   // CSRF protection
                         maxAge: 3600000,   // 1 hour in milliseconds
                         path: '/'          // Available on all paths
                       });

  if (redirect_uri) {
      res.redirect(redirect_uri);
  }  else {
      res.json({ code: authCode });
  }
});

// Logout (development mode only)
app.get('/logout', (req, res) => {
  if (config.isProduction) {
    return res.status(404).json({
      error: 'Not available in production mode',
      message: 'Logout is handled by Apache.'
    });
  }

  const redirect_uri = req.query.redirect_uri;
  const sessionToken = req.cookies[auth_cookie_name];

  if (sessionToken) {
    // Clean up old tokens
    if (blacklistedTokens.size > 1000) {
      blacklistedTokens.clear();
    }
    blacklistedTokens.add(sessionToken);
  }

  res.clearCookie(auth_cookie_name);

  if (redirect_uri) {
    res.redirect(redirect_uri);
  } else {
    res.json({ message: 'Logged out successfully' });
  }
});

// ============================================================================
// PRODUCTION ENDPOINTS (Available in all modes)
// ============================================================================

/**
 * GET /jwt
 * Returns a JWT with user identity + resource permissions
 *
 * Production mode: Reads user from Apache headers
 * Development mode: Reads user from session cookie
 */
app.get('/jwt', (req, res) => {
  let userSub, userEmail, userName, entitlements;

  // PRODUCTION MODE: Read user from Apache OIDC headers
  if (config.isProduction) {
    const oidcSub = req.headers['oidc_claim_sub'];
    const oidcEmail = req.headers['oidc_claim_email'];
    const oidcName = req.headers['oidc_claim_name'];
    const oidcEntitlements = req.headers['oidc_claim_edupersonentitlement'];

    // Verbose header logging (enable with DEBUG=korp-auth:headers)
    debugHeaders('OIDC headers received:', {
      sub: oidcSub,
      email: oidcEmail,
      name: oidcName,
      entitlements: oidcEntitlements
    });

    if (!oidcSub) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'No user identity from proxy. Ensure Apache mod_auth_openidc is configured and user is authenticated.'
      });
    }

    userSub = oidcSub;
    userEmail = oidcEmail || null;
    userName = oidcName || oidcEmail || oidcSub;
    entitlements = parseEntitlements(oidcEntitlements);

    debugAuth('Parsed entitlements:', entitlements);

    // JIT user provisioning - ensure user exists in database
    auth_db.ensureUser(userSub);

    logger.info(`Issuing JWT for user: ${userEmail || userSub} (${entitlements.length} entitlements)`, 'JWT');
  }
  // DEVELOPMENT MODE: Read user from cookie
  else {
    const sessionToken = req.cookies[auth_cookie_name];

    if (!sessionToken) {
      return res.status(401).json({ error: 'unauthorized', message: 'No session cookie found' });
    }

    if (blacklistedTokens.has(sessionToken)) {
      return res.status(401).json({ error: 'token_revoked' });
    }

    try {
      const decoded = jwt.verify(sessionToken, JWT_SECRET);
      const username = decoded.username;

      // Renew the auth cookie
      const authCode = jwt.sign({ username, timestamp: Date.now() }, JWT_SECRET, { expiresIn: '10m', algorithm: 'RS256' });
      res.cookie(auth_cookie_name,
                 authCode, { httpOnly: false,
                             secure: false,
                             sameSite: 'lax',
                             maxAge: 3600000,
                             path: '/'
                           });

      userSub = username;
      userEmail = username;
      userName = username;
      entitlements = []; // No entitlements in development mode

      logger.info(`Issuing JWT for user: ${username}`, 'JWT');
    } catch (error) {
      res.clearCookie(auth_cookie_name);
      return res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired session' });
    }
  }

  // Look up user's resource permissions (aggregated from user grants + entitlement grants)
  const scope = auth_db.get_user_scope(userSub, entitlements);

  debugAuth('User scope retrieved:', scope);

  // Generate JWT with user identity + permissions
  const jwtPayload = {
    sub: userSub,
    email: userEmail,
    name: userName,
    idp: config.isProduction ? 'https://aai.kielipankki.fi' : 'kp-auth-local',
    scope: scope,
    levels: auth_db.PERMISSIONS,
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    iat: Math.floor(Date.now() / 1000)
  };

  // Verbose JWT payload logging (enable with DEBUG=korp-auth:jwt)
  debugJwt('JWT payload:', jwtPayload);

  const token = jwt.sign(jwtPayload, JWT_SECRET, { algorithm: 'RS256' });

  res.send(token);
});

/**
 * POST /resource/:resourcename
 * Create a new resource and grant the creator ADMIN permission
 * Requires JWT authentication
 */
app.post('/resource/:resourcename', (req, res) => {
  const authCode = req.body.jwt;
  if (!authCode) {
    return res.status(401).json({ error: 'unauthorized', message: 'JWT required in request body' });
  }

  try {
    const decoded = jwt.verify(authCode, JWT_SECRET);
    const username = decoded.sub || decoded.email;
    const resourcename = req.params.resourcename;

    auth_db.create_resource(resourcename, "corpus");
    auth_db.set_grant({ userIdentifier: username, resourceName: resourcename, level: auth_db.PERMISSIONS.ADMIN });

    logger.info(`Created resource '${resourcename}' for user '${username}'`, 'Resource');
    res.status(201).send(resourcename);
  } catch (error) {
    if (error instanceof auth_db.ResourceExistsError) {
      return res.status(400).json({ error: 'resource already exists'});
    } else {
      logger.warn(`Invalid auth token for resource creation: ${error.message}`, 'Resource');
      return res.status(401).json({ error: 'invalid auth token' });
    }
  }
});

/**
 * DELETE /resource/:resourcename
 * Delete a resource and all its grants
 * Requires Mink API key (service-to-service authentication)
 */
app.delete('/resource/:resourcename', (req, res) => {
  const authHeader = req.headers.authorization;
  const resourcename = req.params.resourcename;

  if (authHeader !== "apikey " + API_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid API key required' });
  }

  auth_db.delete_resource(resourcename);
  logger.info(`Deleted resource '${resourcename}'`, 'Resource');

  // 204 No Content (even if it didn't exist)
  return res.status(204).send();
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

// Clean up existing socket file if it exists
if (fs.existsSync(SOCKET_PATH)) {
  fs.unlinkSync(SOCKET_PATH);
}

app.listen(SOCKET_PATH, () => {
  console.log('='.repeat(70));
  console.log('Kielipankki Auth Service');
  console.log('='.repeat(70));
  console.log(`Environment:     ${config.nodeEnv.toUpperCase()}`);
  console.log(`Socket:          ${SOCKET_PATH}`);
  console.log(`Database:        ${config.dbPath}`);
  console.log(`JWT Key:         ${config.jwtPrivateKeyPath}`);
  console.log('='.repeat(70));

  if (config.isDevelopment) {
    console.log('\n⚠️  DEVELOPMENT MODE');
    console.log('   Authentication endpoints available at /login, /auth, /logout');
    if (auth_db.demo_users) {
      console.log('\n   Demo users:');
      Object.keys(auth_db.demo_users).forEach(email => {
        console.log(`     • ${email} / ${auth_db.demo_users[email].password}`);
      });
    } else {
      console.log('\n   No demo users configured (set DEMO_USERS environment variable)');
    }
    console.log('\n   In production, set NODE_ENV=production');
  } else if (config.isProduction) {
    console.log('\n✓ PRODUCTION MODE');
    console.log('   Authentication handled by Apache (mod_auth_openidc)');
    console.log('   Reading user identity from request headers');
  }

  console.log('\n' + '='.repeat(70));
  console.log('Configure your reverse proxy (Apache) to proxy requests to this socket.');
  console.log('='.repeat(70) + '\n');

  // Set socket permissions
  try {
    fs.chmodSync(SOCKET_PATH, '666'); // rw-rw-rw-
  } catch (err) {
    logger.warn(`Could not set socket permissions: ${err.message}`, 'Startup');
  }
});

// Graceful shutdown - clean up socket file
process.on('SIGINT', () => {
  logger.info('Shutting down gracefully...', 'Shutdown');
  if (fs.existsSync(SOCKET_PATH)) {
    fs.unlinkSync(SOCKET_PATH);
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...', 'Shutdown');
  if (fs.existsSync(SOCKET_PATH)) {
    fs.unlinkSync(SOCKET_PATH);
  }
  process.exit(0);
});



module.exports = app;
