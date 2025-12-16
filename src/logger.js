/**
 * Custom logging module for korp-auth
 *
 * Provides structured logging with timestamps and optional tags.
 * Can be extended in the future for log levels, file output, etc.
 */

const config = require('./config');

/**
 * Format a log message with timestamp and optional tag
 * @param {string} message - The log message
 * @param {string} tag - Optional tag (e.g., 'Production', 'Resource', 'Auth')
 * @returns {string} Formatted log message
 */
function formatMessage(message, tag = null) {
  const timestamp = new Date().toISOString();
  const env = config.isProduction ? 'PROD' : 'DEV';

  let formatted = `[${timestamp}] [${env}]`;

  if (tag) {
    formatted += ` [${tag}]`;
  }

  formatted += ` ${message}`;

  return formatted;
}

/**
 * Log an informational message to stdout
 * @param {string} message - The message to log
 * @param {string} tag - Optional tag
 */
function info(message, tag = null) {
  console.log(formatMessage(message, tag));
}

/**
 * Log a warning message to stdout
 * @param {string} message - The message to log
 * @param {string} tag - Optional tag
 */
function warn(message, tag = null) {
  console.warn(formatMessage(message, tag));
}

/**
 * Log an error message to stderr
 * @param {string} message - The message to log
 * @param {string} tag - Optional tag
 */
function error(message, tag = null) {
  console.error(formatMessage(message, tag));
}

module.exports = {
  info,
  warn,
  error
};
