/**
 * Configuration module for Korp Auth Service
 * Loads configuration from environment variables with sensible defaults
 */

require('dotenv').config();
const path = require('path');

const config = {
  // Server configuration
  socketPath: process.env.SOCKET_PATH || '/tmp/korp-auth.sock',

  // Directory paths
  authDir: process.env.AUTH_DIR || path.join(__dirname, '..', 'data'),

  // JWT configuration
  jwtPrivateKeyPath: process.env.JWT_PRIVATE_KEY_PATH ||
                     path.join(process.env.AUTH_DIR || path.join(__dirname, '..', 'data'), 'private_key.pem'),

  // API keys
  minkApiKey: process.env.MINK_API_KEY || '',

  // Database configuration
  dbPath: process.env.DB_PATH ||
          path.join(process.env.AUTH_DIR || path.join(__dirname, '..', 'data'), 'resources.sqlite3'),

  // Environment
  nodeEnv: process.env.NODE_ENV || 'development',

  // Cookie configuration
  authCookieName: process.env.AUTH_COOKIE_NAME || 'kp-future-auth-token',

  // Redirect configuration
  fallbackRedirectUri: process.env.FALLBACK_REDIRECT_URI || 'https://www.kielipankki.fi',

  // Authentication mode
  authMode: process.env.AUTH_MODE || 'local', // 'local' | 'oidc'

  // Session configuration
  session: {
    secret: process.env.SESSION_SECRET || 'change-this-in-production-' + Math.random().toString(36),
    name: process.env.SESSION_COOKIE_NAME || 'korp-auth-session',
    maxAge: parseInt(process.env.SESSION_MAX_AGE || '86400000', 10), // 24 hours default
    // Redis configuration
    redis: {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: parseInt(process.env.REDIS_PORT || '6379', 10),
      password: process.env.REDIS_PASSWORD || undefined,
      db: parseInt(process.env.REDIS_DB || '0', 10),
      keyPrefix: process.env.REDIS_KEY_PREFIX || 'korp-auth:sess:'
    }
  },

  // OIDC configuration (Kielipankki AAI - Shibboleth OIDC OP)
  oidc: {
    issuerUrl: process.env.OIDC_ISSUER_URL || 'https://aai.kielipankki.fi',
    clientId: process.env.OIDC_CLIENT_ID || '',
    clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    redirectUri: process.env.OIDC_REDIRECT_URI || '',
    scope: process.env.OIDC_SCOPE || 'openid profile email',
    postLogoutRedirectUri: process.env.OIDC_POST_LOGOUT_REDIRECT_URI || '',

    // Back-channel logout support
    backChannelLogoutUri: process.env.OIDC_BACKCHANNEL_LOGOUT_URI || '',

    // Optional: for dynamic client registration
    dynamicRegistration: process.env.OIDC_DYNAMIC_REGISTRATION === 'true'
  }
};

module.exports = config;
