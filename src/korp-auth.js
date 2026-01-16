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
const debugAdmin = debug('korp-auth:admin');

const app = express();
const SOCKET_PATH = config.socketPath;

// Secret for signing JWTs
const JWT_SECRET = fs.readFileSync(config.jwtPrivateKeyPath, 'utf8');
const MINK_API_KEY = config.minkApiKey;
const ADMIN_API_KEY = config.adminApiKey;

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
 * They may arrive as a string (hopefully semicolon-separated) or array
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

/**
 * Parse affiliation header into array of values
 */
function parseAffiliations(headerValue) {
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
      .map(aff => aff.trim())
      .filter(aff => aff.length > 0);
  }

  return [];
}

/**
 * Check if user has academic (ACA) status
 * Based on eduPersonAffiliation, eduPersonScopedAffiliation, and eduPersonEntitlement claims
 *
 * Academic status is granted if ANY of these conditions are met:
 * 1. Unscoped affiliation contains: member, student, faculty, or employee
 * 2. CLARIN special case: member@clarin.eu affiliation + http://www.clarin.eu/entitlement/academic entitlement
 * 3. Other scoped affiliation: (member|student|faculty|employee)@domain (but NOT member@clarin.eu)
 * 4. LBR ACA entitlement: urn:nbn:fi:lb-2016110710@LBR
 */
function checkAcademicStatus(affiliations, scopedAffiliations, entitlements) {
  const debugAca = debug('korp-auth:aca');

  // Parse all inputs
  const unscopedAffs = parseAffiliations(affiliations);
  const scopedAffs = parseAffiliations(scopedAffiliations);
  const ents = parseEntitlements(entitlements);

  debugAca('Checking ACA status:', {
    unscopedAffiliations: unscopedAffs,
    scopedAffiliations: scopedAffs,
    entitlements: ents
  });

  // Academic affiliation values
  const academicAffiliations = ['member', 'student', 'faculty', 'employee'];

  // 1. Check unscoped affiliations
  for (const aff of unscopedAffs) {
    if (academicAffiliations.includes(aff.toLowerCase())) {
      debugAca('ACA granted via unscoped affiliation:', aff);
      return true;
    }
  }

  // 2. Check CLARIN special case
  const hasClarinMember = scopedAffs.some(aff =>
    aff.toLowerCase() === 'member@clarin.eu'
  );
  const hasClarinAcademicEntitlement = ents.some(ent =>
    ent === 'http://www.clarin.eu/entitlement/academic'
  );
  if (hasClarinMember && hasClarinAcademicEntitlement) {
    debugAca('ACA granted via CLARIN special case');
    return true;
  }

  // 3. Check other scoped affiliations (excluding CLARIN member@clarin.eu)
  for (const aff of scopedAffs) {
    const lowerAff = aff.toLowerCase();

    // Skip CLARIN member (already handled in special case)
    if (lowerAff === 'member@clarin.eu') {
      continue;
    }

    // Check if affiliation matches academic patterns with @ (scoped)
    for (const academicRole of academicAffiliations) {
      // Pattern: role@domain (e.g., member@helsinki.fi, student@jyu.fi)
      if (lowerAff.startsWith(academicRole + '@')) {
        debugAca('ACA granted via scoped affiliation:', aff);
        return true;
      }
    }
  }

  // 4. Check LBR ACA entitlement
  const hasLbrAca = ents.some(ent =>
    ent === 'urn:nbn:fi:lb-2016110710@LBR'
  );
  if (hasLbrAca) {
    debugAca('ACA granted via LBR entitlement');
    return true;
  }

  debugAca('ACA not granted');
  return false;
}

/**
 * Admin API authentication middleware
 * Requires X-API-Key header with valid ADMIN_API_KEY
 */
function requireAdminAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'X-API-Key header required for admin endpoints'
    });
  }

  if (apiKey !== ADMIN_API_KEY) {
    logger.warn('Invalid admin API key attempt', 'Admin');
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Invalid API key'
    });
  }

  // API key is valid, proceed to endpoint
  next();
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
  let userSub, userEmail, userName, entitlements, isAcademic;

  // PRODUCTION MODE: Read user from Apache OIDC headers
  if (config.isProduction) {
    const oidcSub = req.headers['oidc_claim_sub'];
    const oidcEmail = req.headers['oidc_claim_email'];
    const oidcName = req.headers['oidc_claim_name'];
    const oidcEntitlements = req.headers['oidc_claim_edupersonentitlement'];
    const oidcAffiliation = req.headers['oidc_claim_edupersonaffiliation'];
    const oidcScopedAffiliation = req.headers['oidc_claim_edupersonscopedaffiliation'];

    // Verbose header logging (enable with DEBUG=korp-auth:headers)
    debugHeaders('OIDC headers received:', {
      sub: oidcSub,
      email: oidcEmail,
      name: oidcName,
      entitlements: oidcEntitlements,
      affiliation: oidcAffiliation,
      scopedAffiliation: oidcScopedAffiliation
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

    // Check academic status
    isAcademic = checkAcademicStatus(oidcAffiliation, oidcScopedAffiliation, oidcEntitlements);

    debugAuth('Parsed entitlements:', entitlements);
    debugAuth('Academic status (ACA):', isAcademic);

    // JIT user provisioning - ensure user exists in database
    auth_db.ensure_user(userSub);

    logger.info(`Issuing JWT for user: ${userEmail || userSub} (${entitlements.length} entitlements, ACA: ${isAcademic})`, 'JWT');
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
      isAcademic = false; // No ACA status in development mode

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
    ACA: isAcademic,
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
 * Create a new user-uploaded resource and grant the creator ADMIN permission
 * Requires Mink API key (Authorization header) and JWT authentication
 * Only allows resources starting with "mink-" prefix
 */
app.post('/resource/:resourcename', (req, res) => {
  const resourcename = req.params.resourcename;
  const authHeader = req.headers.authorization;

  // Check 1: Verify Mink API key
  if (authHeader !== "apikey " + MINK_API_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid Mink API key required' });
  }

  // Check 2: Verify resource name starts with "mink-"
  if (!resourcename.startsWith('mink-')) {
    return res.status(400).json({
      error: 'invalid_resource_name',
      message: 'User-uploaded resources must start with "mink-" prefix'
    });
  }

  // Check 3: Verify JWT
  const authCode = req.body.jwt;
  if (!authCode) {
    return res.status(401).json({ error: 'unauthorized', message: 'JWT required in request body' });
  }

  try {
    const decoded = jwt.verify(authCode, JWT_SECRET);
    const username = decoded.sub || decoded.email;

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
 * Delete a user-uploaded resource and all its grants
 * Requires Mink API key (Authorization header) and JWT authentication
 * User must have ADMIN permission on the resource
 * Only allows resources starting with "mink-" prefix
 */
app.delete('/resource/:resourcename', (req, res) => {
  const authHeader = req.headers.authorization;
  const resourcename = req.params.resourcename;

  // Check 1: Verify Mink API key
  if (authHeader !== "apikey " + MINK_API_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid Mink API key required' });
  }

  // Check 2: Verify resource name starts with "mink-"
  if (!resourcename.startsWith('mink-')) {
    return res.status(400).json({
      error: 'invalid_resource_name',
      message: 'User-uploaded resources must start with "mink-" prefix'
    });
  }

  // Check 3: Verify JWT
  const authCode = req.body.jwt;
  if (!authCode) {
    return res.status(401).json({ error: 'unauthorized', message: 'JWT required in request body' });
  }

  try {
    const decoded = jwt.verify(authCode, JWT_SECRET);
    const username = decoded.sub || decoded.email;

    // Check 4: Verify user has ADMIN permission on the resource
    const userScope = decoded.scope;
    const resourcePermission = userScope?.corpora?.[resourcename];

    if (resourcePermission !== auth_db.PERMISSIONS.ADMIN) {
      logger.warn(`User '${username}' attempted to delete resource '${resourcename}' without ADMIN permission`, 'Resource');
      return res.status(403).json({
        error: 'forbidden',
        message: 'ADMIN permission required to delete this resource'
      });
    }

    auth_db.delete_resource(resourcename);
    logger.info(`Deleted resource '${resourcename}' by user '${username}'`, 'Resource');

    // 204 No Content
    return res.status(204).send();
  } catch (error) {
    logger.warn(`Invalid auth token for resource deletion: ${error.message}`, 'Resource');
    return res.status(401).json({ error: 'invalid auth token' });
  }
});

// ============================================================================
// ADMIN API ENDPOINTS (Production only, requires ADMIN_API_KEY)
// ============================================================================

/**
 * GET /admin/entitlements
 * List all entitlements with basic info and grant counts
 * Requires X-API-Key header
 */
app.get('/admin/entitlements', requireAdminAuth, (req, res) => {
  try {
    const entitlements = auth_db.list_entitlements();

    debugAdmin('Listed entitlements:', entitlements.length);
    logger.info(`Listed ${entitlements.length} entitlements`, 'Admin');

    res.status(200).json({ entitlements });
  } catch (error) {
    logger.error(`Error listing entitlements: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to list entitlements'
    });
  }
});

/**
 * GET /admin/entitlement/:urn
 * Get a single entitlement with full grant details
 * Requires X-API-Key header
 */
app.get('/admin/entitlement/:urn', requireAdminAuth, (req, res) => {
  try {
    const urn = decodeURIComponent(req.params.urn);

    debugAdmin('Fetching entitlement:', urn);

    // Get entitlement metadata
    const allEntitlements = auth_db.list_entitlements();
    const entitlement = allEntitlements.find(e => e.urn === urn);

    if (!entitlement) {
      return res.status(404).json({
        error: 'not_found',
        message: `Entitlement '${urn}' not found`
      });
    }

    // Get grants for this entitlement
    const grants = auth_db.get_grants_for_entitlement(urn);

    const result = {
      urn: entitlement.urn,
      description: entitlement.description,
      created_at: entitlement.created_at,
      updated_at: entitlement.updated_at,
      grants: grants
    };

    debugAdmin('Fetched entitlement:', result);
    logger.info(`Fetched entitlement: ${urn}`, 'Admin');

    res.status(200).json(result);
  } catch (error) {
    logger.error(`Error fetching entitlement: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to fetch entitlement'
    });
  }
});

/**
 * POST /admin/entitlement
 * Create or update an entitlement (with optional grants)
 * Requires X-API-Key header
 *
 * Request body:
 * {
 *   "urn": "urn:nbn:fi:lb-123",
 *   "description": "Description text",
 *   "grants": [  // optional
 *     {"resourceName": "corpus-1", "level": 1},
 *     {"resourceName": "corpus-2", "level": 2}
 *   ]
 * }
 */
app.post('/admin/entitlement', requireAdminAuth, (req, res) => {
  try {
    const { urn, description, grants } = req.body;

    debugAdmin('POST /admin/entitlement request:', { urn, description, grants });

    // Validate required fields
    if (!urn || !description) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Both "urn" and "description" fields are required'
      });
    }

    // Validate grants if provided
    if (grants) {
      if (!Array.isArray(grants)) {
        return res.status(400).json({
          error: 'validation_error',
          message: '"grants" must be an array'
        });
      }

      for (const grant of grants) {
        if (!grant.resourceName || !grant.level) {
          return res.status(400).json({
            error: 'validation_error',
            message: 'Each grant must have "resourceName" and "level" fields'
          });
        }

        if (![1, 2, 3].includes(grant.level)) {
          return res.status(400).json({
            error: 'validation_error',
            message: 'Grant level must be 1 (READ), 2 (WRITE), or 3 (ADMIN)'
          });
        }
      }
    }

    // Check if entitlement exists
    const exists = auth_db.entitlement_exists(urn);

    // Create or update entitlement
    if (exists) {
      auth_db.update_entitlement_description(urn, description);
    } else {
      auth_db.create_entitlement(urn, description);
    }

    // Add grants if provided
    let grantsAdded = 0;
    if (grants && grants.length > 0) {
      for (const grant of grants) {
        auth_db.set_grant({
          entitlementUrn: urn,
          resourceName: grant.resourceName,
          level: grant.level
        });
        grantsAdded++;
      }
    }

    const result = {
      urn,
      description,
      created: !exists,
      grantsAdded
    };

    debugAdmin('Created/updated entitlement:', result);
    logger.info(`${exists ? 'Updated' : 'Created'} entitlement: ${urn} (${grantsAdded} grants)`, 'Admin');

    res.status(exists ? 200 : 201).json(result);
  } catch (error) {
    logger.error(`Error creating/updating entitlement: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to create/update entitlement'
    });
  }
});

/**
 * DELETE /admin/entitlement/:urn
 * Delete an entitlement and all associated grants
 * Requires X-API-Key header
 */
app.delete('/admin/entitlement/:urn', requireAdminAuth, (req, res) => {
  try {
    const urn = decodeURIComponent(req.params.urn);

    debugAdmin('Deleting entitlement:', urn);

    auth_db.delete_entitlement(urn);

    logger.info(`Deleted entitlement: ${urn}`, 'Admin');

    // 204 No Content (idempotent - even if didn't exist)
    res.status(204).send();
  } catch (error) {
    logger.error(`Error deleting entitlement: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to delete entitlement'
    });
  }
});

/**
 * POST /admin/grant
 * Add or update a single grant for an entitlement
 * Requires X-API-Key header
 *
 * Request body:
 * {
 *   "entitlementUrn": "urn:nbn:fi:lb-123",
 *   "resourceName": "corpus-1",
 *   "level": 1
 * }
 */
app.post('/admin/grant', requireAdminAuth, (req, res) => {
  try {
    const { entitlementUrn, resourceName, level } = req.body;

    debugAdmin('POST /admin/grant request:', { entitlementUrn, resourceName, level });

    // Validate required fields
    if (!entitlementUrn || !resourceName || !level) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'All fields required: "entitlementUrn", "resourceName", "level"'
      });
    }

    // Validate level
    if (![1, 2, 3].includes(level)) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Level must be 1 (READ), 2 (WRITE), or 3 (ADMIN)'
      });
    }

    // Set the grant (uses upsert)
    auth_db.set_grant({ entitlementUrn, resourceName, level });

    const result = { entitlementUrn, resourceName, level };

    debugAdmin('Set grant:', result);
    logger.info(`Set grant: ${entitlementUrn} -> ${resourceName} (level ${level})`, 'Admin');

    res.status(200).json(result);
  } catch (error) {
    // Check for foreign key constraint failures
    if (error.message && error.message.includes('FOREIGN KEY constraint failed')) {
      return res.status(404).json({
        error: 'not_found',
        message: 'Entitlement or resource not found'
      });
    }

    logger.error(`Error setting grant: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to set grant'
    });
  }
});

/**
 * DELETE /admin/grant
 * Remove a grant for an entitlement
 * Requires X-API-Key header
 * Query params: ?entitlementUrn=...&resourceName=...
 */
app.delete('/admin/grant', requireAdminAuth, (req, res) => {
  try {
    const { entitlementUrn, resourceName } = req.query;

    debugAdmin('DELETE /admin/grant request:', { entitlementUrn, resourceName });

    // Validate query params
    if (!entitlementUrn || !resourceName) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Query params required: "entitlementUrn" and "resourceName"'
      });
    }

    // Remove the grant
    auth_db.remove_grant({ entitlementUrn, resourceName });

    logger.info(`Removed grant: ${entitlementUrn} -> ${resourceName}`, 'Admin');

    // 204 No Content
    res.status(204).send();
  } catch (error) {
    logger.error(`Error removing grant: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to remove grant'
    });
  }
});

/**
 * GET /admin/resources
 * List all resources with grant counts
 * Requires X-API-Key header
 */
app.get('/admin/resources', requireAdminAuth, (req, res) => {
  try {
    const resources = auth_db.list_resources();

    debugAdmin('Listed resources:', resources.length);
    logger.info(`Listed ${resources.length} resources`, 'Admin');

    res.status(200).json({ resources });
  } catch (error) {
    logger.error(`Error listing resources: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to list resources'
    });
  }
});

/**
 * POST /admin/resource
 * Create a new resource
 * Requires X-API-Key header
 *
 * Request body:
 * {
 *   "name": "corpus-name",
 *   "type": "corpus"  // corpus, metadata, or other
 * }
 */
app.post('/admin/resource', requireAdminAuth, (req, res) => {
  try {
    const { name, type } = req.body;

    debugAdmin('POST /admin/resource request:', { name, type });

    // Validate required fields
    if (!name || !type) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Both "name" and "type" fields are required'
      });
    }

    // Validate type
    if (!['corpus', 'metadata', 'other'].includes(type)) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Type must be "corpus", "metadata", or "other"'
      });
    }

    // Create the resource
    auth_db.create_resource(name, type);

    const result = { name, type, created: true };

    debugAdmin('Created resource:', result);
    logger.info(`Created resource: ${name} (type: ${type})`, 'Admin');

    res.status(201).json(result);
  } catch (error) {
    // Check for duplicate resource
    if (error instanceof auth_db.ResourceExistsError) {
      return res.status(409).json({
        error: 'conflict',
        message: `Resource '${req.body.name}' already exists`
      });
    }

    logger.error(`Error creating resource: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to create resource'
    });
  }
});

/**
 * DELETE /admin/resource/:name
 * Delete a resource and all associated grants
 * Requires X-API-Key header
 */
app.delete('/admin/resource/:name', requireAdminAuth, (req, res) => {
  try {
    const name = decodeURIComponent(req.params.name);

    debugAdmin('Deleting resource:', name);

    auth_db.delete_resource(name);

    logger.info(`Deleted resource: ${name}`, 'Admin');

    // 204 No Content (idempotent - even if didn't exist)
    res.status(204).send();
  } catch (error) {
    logger.error(`Error deleting resource: ${error.message}`, 'Admin');
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to delete resource'
    });
  }
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
