const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const sqlite = require('node:sqlite');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const config = require('./config');

const app = express();
const SOCKET_PATH = config.socketPath;

// Secret for signing JWTs
const JWT_SECRET = fs.readFileSync(config.jwtPrivateKeyPath, 'utf8');
const API_KEY = config.minkApiKey;

const auth_cookie_name = config.authCookieName;

const auth_db = require('./db.js');
auth_db.create_db_if_missing();

// In-memory token blacklist for logout functionality
const blacklistedTokens = new Set();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

// Session middleware setup
let sessionMiddleware;
if (config.authMode === 'oidc') {
  // Redis-backed sessions for OIDC mode
  const redisClient = new Redis({
    host: config.session.redis.host,
    port: config.session.redis.port,
    password: config.session.redis.password,
    db: config.session.redis.db,
  });

  redisClient.on('error', (err) => {
    console.error('[Redis] Connection error:', err);
  });

  redisClient.on('connect', () => {
    console.log('[Redis] Connected successfully');
  });

  sessionMiddleware = session({
    store: new RedisStore({ client: redisClient, prefix: config.session.redis.keyPrefix }),
    secret: config.session.secret,
    name: config.session.name,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: config.nodeEnv === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: config.session.maxAge,
    },
  });
} else {
  // Memory-backed sessions for local dev mode
  sessionMiddleware = session({
    secret: config.session.secret,
    name: config.session.name,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: config.nodeEnv === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: config.session.maxAge,
    },
  });
}

app.use(sessionMiddleware);

const fallback_redirect_uri = config.fallbackRedirectUri;

// Serve login page
app.get('/login', (req, res) => {
  const { redirect, client_id, state, destination } = req.query;
  
  // Use destination if provided, otherwise fall back to redirect_uri
    const finalRedirectUri = redirect || fallback_redirect_uri;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>KP-future login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
            .login-form { border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
            input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
            button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
            button:hover { background: #0056b3; }
            .demo-users { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>KP-future login</h2>
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

// Handle login form submission
app.post('/auth', (req, res) => {
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
                           secure: true,     // HTTPS must be enabled
                           sameSite: 'lax',  // CSRF protection
                           maxAge: 3600000,  // 1 hour in milliseconds
                           path: '/'         // Available on all paths
                         });
    
    if (redirect_uri) {
        res.redirect(redirect_uri);
    }  else {
        // Or show some error instead?
        res.json({ code: authCode });
    }
});

app.get('/jwt', (req, res) => {
    // OIDC mode: Check for OIDC session
    if (config.authMode === 'oidc') {
        // Check if user has an OIDC session
        if (!req.session.oidc || !req.session.oidc.user) {
            // No OIDC session - redirect to login
            console.log('[OIDC] No session found, redirecting to login');
            return res.redirect('/auth/login?returnTo=/jwt');
        }

        const userInfo = req.session.oidc.user;

        console.log('[OIDC] Issuing JWT for user:', userInfo.email || userInfo.sub);

        // Create and return JWT with user info from OIDC
        // For now, we don't look up grants - just issue a minimal JWT
        const token = jwt.sign(
            {
                sub: userInfo.sub,
                email: userInfo.email || null,
                name: userInfo.name || userInfo.email || userInfo.sub,
                idp: config.oidc.issuerUrl,
                scope: {}, // Empty scope for now - no grants lookup
                levels: auth_db.PERMISSIONS,
                iss: 'korp-auth',
                exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
                iat: Math.floor(Date.now() / 1000),
            },
            JWT_SECRET,
            { algorithm: 'RS256' }
        );

        return res.send(token);
    }

    // Local mode: Use cookie-based auth (existing behavior)
    const sessionToken = req.cookies[auth_cookie_name];

    if (!sessionToken) {
        return res.status(401).json({ error: 'unauthorized' });
    }

    if (blacklistedTokens.has(sessionToken)) {
        return res.status(401).json({ error: 'token_revoked' });
    }

    try {
        const decoded = jwt.verify(sessionToken, JWT_SECRET);
        const username = decoded.username;
        // If the auth cookie was good, renew it
        const authCode = jwt.sign({ username, timestamp: Date.now() }, JWT_SECRET, { expiresIn: '10m', algorithm: 'RS256' });
        res.cookie(auth_cookie_name,
                   authCode, { httpOnly: false,
                               secure: true,
                               sameSite: 'lax',
                               maxAge: 3600000,
                               path: '/'
                             });
        // Create and return JWT
        const token = jwt.sign(
            {
                email: username,
                name: username, // We could get these from the db, but let's wait for kp-aai
                exp: Math.floor(Date.now() / 1000) + 3600,
                scope: auth_db.get_user_scope(username),
                levels: auth_db.PERMISSIONS,
                sub: username,
                idp: "kp-future-auth"
            },
            JWT_SECRET,
            {algorithm: 'RS256'});
        res.send(token);

    } catch (error) {
        // Token invalid/expired, clear the cookie
        res.clearCookie(auth_cookie_name);
        res.status(401).json({ error: 'unauthorized' });
    }
});

// The /resource endpoint used by Mink for creating
app.post('/resource/:resourcename', (req, res) => {
    const authCode = req.body.jwt;
    if (!authCode) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    
    try {
        const decoded = jwt.verify(authCode, JWT_SECRET);
        const username = decoded.email;
        const resourcename = req.params.resourcename;
        auth_db.create_resource(resourcename, "corpus");
        auth_db.set_grant(username, resourcename, auth_db.PERMISSIONS.ADMIN);
        res.status(201).send(resourcename);
    } catch (error) {
        if (error instanceof auth_db.ResourceExistsError) {
            return res.status(400).json({ error: 'resource already exists'});
        } else {
            // TODO we could handle more possibilities
            console.log("Returning 401 due to invalid auth token")
            return res.status(401).json({ error: 'invalid auth token' });
        }
    }
});

// Deleting a resource
app.delete('/resource/:resourcename', (req, res) => {
    const authHeader = req.headers.authorization;
    const resourcename = req.params.resourcename;

    if (authHeader !== "apikey " + API_KEY) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    auth_db.delete_resource(resourcename);
    // Even if it didn't exist we're happy
    return res.status(204).send(resourcename);
});

app.get('/logout', (req, res) => {
    const redirect_uri = req.query.redirect_uri
    const sessionToken = req.cookies[auth_cookie_name];
    if (sessionToken) {
        // Clean up old tokens (TODO: use eg. Redis with TTL)
        if (blacklistedTokens.size > 1000) {
            // TODO: only clean up expired tokens
            blacklistedTokens.clear();
        }
        // Add token to blacklist
        blacklistedTokens.add(sessionToken);
    }
    
    if (redirect_uri) {
        res.redirect(redirect_uri);
  } else {
      res.json({ message: 'Logged out successfully' });
  }
});

// Health check / discovery endpoint - for later
// app.get('/.well-known/openid_configuration', (req, res) => {
//   // For Unix socket, you'll need to configure your reverse proxy/web server
//   // to provide the external base URL. For now, using a placeholder.
//   const baseUrl = process.env.BASE_URL || 'http://localhost';
//   res.json({
//     issuer: baseUrl,
//     authorization_endpoint: `${baseUrl}/login`,
//     token_endpoint: `${baseUrl}/token`,
//     userinfo_endpoint: `${baseUrl}/userinfo`,
//     end_session_endpoint: `${baseUrl}/logout`,
//     jwks_uri: `${baseUrl}/jwks`,
//     response_types_supported: ['code'],
//     grant_types_supported: ['authorization_code'],
//     subject_types_supported: ['public']
//   });
// });

// JWKS endpoint (simplified - for token verification)
// app.get('/jwks', (req, res) => {
//   res.json({
//     keys: [
//       {
//         kty: 'oct',
//         use: 'sig',
//         alg: 'HS256',
//         k: Buffer.from(JWT_SECRET).toString('base64url')
//       }
//     ]
//   });
// });

// Clean up existing socket file if it exists
if (fs.existsSync(SOCKET_PATH)) {
  fs.unlinkSync(SOCKET_PATH);
}

app.listen(SOCKET_PATH, () => {
  console.log(`Mink OAuth2 Server listening on Unix socket: ${SOCKET_PATH}`);
  console.log(`You need configure a reverse proxy (nginx, Apache, etc.) to serve this.`);
  console.log('\nDemo users:');
    Object.keys(auth_db.demo_users).forEach(email => {
        console.log(`  ${email} / ${auth_db.demo_users[email].password}`);
    });
  
  // Set socket permissions (optional - adjust as needed)
  try {
    fs.chmodSync(SOCKET_PATH, '666'); // rw-rw-rw-
  } catch (err) {
    console.warn('Could not set socket permissions:', err.message);
  }
});

// Graceful shutdown - clean up socket file
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  if (fs.existsSync(SOCKET_PATH)) {
    fs.unlinkSync(SOCKET_PATH);
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nReceived SIGTERM, shutting down gracefully...');
  if (fs.existsSync(SOCKET_PATH)) {
    fs.unlinkSync(SOCKET_PATH);
  }
  process.exit(0);
});



module.exports = app;
