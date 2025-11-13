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

  // Authentication mode
  // 'local' = development mode with login page and demo users
  // 'proxy' = production mode, reads user identity from Apache headers
  authMode: process.env.AUTH_MODE || 'local',

  // Development mode only - cookie configuration
  authCookieName: process.env.AUTH_COOKIE_NAME || 'kp-future-auth-token',
  fallbackRedirectUri: process.env.FALLBACK_REDIRECT_URI || 'https://www.kielipankki.fi'
};

module.exports = config;
