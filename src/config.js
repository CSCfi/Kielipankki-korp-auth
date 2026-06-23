/**
 * Configuration module for Korp Auth Service
 * Loads configuration from environment variables with sensible defaults
 */

require('dotenv').config();
const path = require('path');

const config = {
  socketPath: process.env.SOCKET_PATH || '/tmp/korp-auth.sock',
  authDir: process.env.AUTH_DIR || path.join(__dirname, '..', 'data'),
  jwtPrivateKeyPath: process.env.JWT_PRIVATE_KEY_PATH ||
                     path.join(process.env.AUTH_DIR || path.join(__dirname, '..', 'data'), 'private_key.pem'),
  minkApiKey: process.env.MINK_API_KEY || '',
  adminApiKey: process.env.ADMIN_API_KEY || '',
  dbPath: process.env.DB_PATH ||
          path.join(process.env.AUTH_DIR || path.join(__dirname, '..', 'data'), 'resources.sqlite3'),

  // Environment
  // 'development' = development mode with login page and demo users
  // 'production' = production mode, reads user identity from Apache headers
  nodeEnv: (() => {
    const env = process.env.NODE_ENV || 'development';
    if (env !== 'development' && env !== 'production') {
      throw new Error(
        `Invalid NODE_ENV="${env}". Must be exactly "development" or "production".\n` +
        'For development: NODE_ENV=development\n' +
        'For production: NODE_ENV=production'
      );
    }
    return env;
  })(),

  get isDevelopment() {
    return this.nodeEnv === 'development';
  },

  get isProduction() {
    return this.nodeEnv === 'production';
  },

  // Development mode only configs
  authCookieName: process.env.AUTH_COOKIE_NAME || 'kp-future-auth-token',
  fallbackRedirectUri: process.env.FALLBACK_REDIRECT_URI || 'https://www.kielipankki.fi',
  demoUsers: process.env.DEMO_USERS ? JSON.parse(process.env.DEMO_USERS) : {}
};

// The API keys are the only thing guarding the resource-management endpoints.
// An empty key fails open: the comparison `authHeader !== "apikey " + KEY`
// (see korp-auth.js) is satisfied by the literal header `Authorization: apikey `
// when the key is "". Refuse to start in production unless both keys are present
// and long enough to not be trivially guessable. Enforced only in production so
// local/dev and the dev-mode test suite need not set them.
if (config.isProduction) {
  const MIN_API_KEY_LENGTH = 12;
  for (const [name, value] of [['MINK_API_KEY', config.minkApiKey],
                               ['ADMIN_API_KEY', config.adminApiKey]]) {
    if (!value || value.length < MIN_API_KEY_LENGTH) {
      throw new Error(
        `${name} must be set and at least ${MIN_API_KEY_LENGTH} characters in production ` +
        `(got ${value ? value.length : 0}). Generate one with: openssl rand -hex 32`
      );
    }
  }
}

module.exports = config;
