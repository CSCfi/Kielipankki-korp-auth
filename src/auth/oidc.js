/**
 * OIDC Client Module
 * Handles OIDC provider discovery and client initialization
 */

const { Issuer, generators } = require('openid-client');
const config = require('../config');

let client = null;
let issuer = null;

/**
 * Initialize OIDC client by discovering the provider
 * Uses OIDC Discovery to automatically configure endpoints
 */
async function initializeOIDCClient() {
  if (client) {
    return client;
  }

  try {
    console.log(`[OIDC] Discovering provider at ${config.oidc.issuerUrl}...`);

    // Discover OIDC provider configuration
    issuer = await Issuer.discover(config.oidc.issuerUrl);

    console.log(`[OIDC] Discovered issuer: ${issuer.metadata.issuer}`);
    console.log(`[OIDC] Authorization endpoint: ${issuer.metadata.authorization_endpoint}`);
    console.log(`[OIDC] Token endpoint: ${issuer.metadata.token_endpoint}`);
    console.log(`[OIDC] UserInfo endpoint: ${issuer.metadata.userinfo_endpoint}`);
    console.log(`[OIDC] JWKS URI: ${issuer.metadata.jwks_uri}`);

    // Create OIDC client
    client = new issuer.Client({
      client_id: config.oidc.clientId,
      client_secret: config.oidc.clientSecret,
      redirect_uris: [config.oidc.redirectUri],
      response_types: ['code'],
    });

    console.log('[OIDC] Client initialized successfully');

    return client;
  } catch (error) {
    console.error('[OIDC] Failed to initialize client:', error.message);
    throw error;
  }
}

/**
 * Get the OIDC client (must be initialized first)
 */
function getClient() {
  if (!client) {
    throw new Error('OIDC client not initialized. Call initializeOIDCClient() first.');
  }
  return client;
}

/**
 * Get the OIDC issuer
 */
function getIssuer() {
  if (!issuer) {
    throw new Error('OIDC issuer not discovered. Call initializeOIDCClient() first.');
  }
  return issuer;
}

/**
 * Generate authorization URL for login
 * @param {string} state - Random state for CSRF protection
 * @param {string} nonce - Random nonce for replay protection
 * @returns {string} Authorization URL
 */
function getAuthorizationUrl(state, nonce) {
  const client = getClient();

  return client.authorizationUrl({
    scope: config.oidc.scope,
    state: state,
    nonce: nonce,
  });
}

/**
 * Exchange authorization code for tokens
 * @param {string} code - Authorization code from callback
 * @param {string} state - State value to verify
 * @param {string} nonce - Nonce value to verify in ID token
 * @returns {Promise<TokenSet>} Token set with id_token, access_token, etc.
 */
async function exchangeCodeForTokens(code, state, nonce) {
  const client = getClient();

  const params = {
    code: code,
    state: state,
  };

  const tokenSet = await client.callback(
    config.oidc.redirectUri,
    params,
    { nonce: nonce, state: state }
  );

  return tokenSet;
}

/**
 * Get user info from ID token claims
 * @param {TokenSet} tokenSet - Token set from code exchange
 * @returns {Object} User info with sub, email, name, etc.
 */
function getUserInfo(tokenSet) {
  const claims = tokenSet.claims();

  return {
    sub: claims.sub,
    email: claims.email || null,
    name: claims.name || claims.email || claims.sub,
    // Store session ID for logout correlation
    sid: claims.sid || null,
  };
}

/**
 * Generate a random state for CSRF protection
 */
function generateState() {
  return generators.state();
}

/**
 * Generate a random nonce for replay protection
 */
function generateNonce() {
  return generators.nonce();
}

module.exports = {
  initializeOIDCClient,
  getClient,
  getIssuer,
  getAuthorizationUrl,
  exchangeCodeForTokens,
  getUserInfo,
  generateState,
  generateNonce,
};
