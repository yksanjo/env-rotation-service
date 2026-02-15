import CryptoJS from 'crypto-js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { getConfig } from '../commands/init.js';

let masterKey = null;

/**
 * Set the master key for encryption/decryption
 * @param {string} password - Master password
 */
export function setMasterKey(password) {
  const config = getConfig();
  if (!config) throw new Error('Not initialized');
  
  // Derive key using PBKDF2
  const salt = config.salt || 'envguard-salt';
  masterKey = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
  
  return masterKey;
}

/**
 * Clear the master key from memory
 */
export function clearMasterKey() {
  masterKey = null;
}

/**
 * Check if master key is set
 */
export function hasMasterKey() {
  return masterKey !== null;
}

/**
 * Encrypt a value using AES-256
 * @param {string} value - Value to encrypt
 * @returns {string} Encrypted value
 */
export function encrypt(value) {
  if (!masterKey) {
    throw new Error('Master key not set. Run var get or set first.');
  }
  
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(value, masterKey, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  
  // Combine IV and ciphertext
  return iv.toString() + ':' + encrypted.toString();
}

/**
 * Decrypt a value
 * @param {string} encryptedValue - Encrypted value
 * @returns {string} Decrypted value
 */
export function decrypt(encryptedValue) {
  if (!masterKey) {
    throw new Error('Master key not set. Run var get or set first.');
  }
  
  const parts = encryptedValue.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted value format');
  }
  
  const iv = CryptoJS.enc.Hex.parse(parts[0]);
  const ciphertext = parts[1];
  
  const decrypted = CryptoJS.AES.decrypt(ciphertext, masterKey, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  
  return decrypted.toString(CryptoJS.enc.Utf8);
}

/**
 * Encrypt a value with password (for initial setup)
 * @param {string} value - Value to encrypt
 * @param {string} password - Password to use
 * @returns {string} Encrypted value
 */
export function encryptWithPassword(value, password) {
  const config = getConfig();
  const salt = config.salt || 'envguard-salt';
  
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
  
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(value, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  
  return iv.toString() + ':' + encrypted.toString();
}

/**
 * Decrypt a value with password
 * @param {string} encryptedValue - Encrypted value
 * @param {string} password - Password to use
 * @returns {string} Decrypted value
 */
export function decryptWithPassword(encryptedValue, password) {
  const config = getConfig();
  const salt = config.salt || 'envguard-salt';
  
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
  
  const parts = encryptedValue.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted value format');
  }
  
  const iv = CryptoJS.enc.Hex.parse(parts[0]);
  const ciphertext = parts[1];
  
  const decrypted = CryptoJS.AES.decrypt(ciphertext, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  
  return decrypted.toString(CryptoJS.enc.Utf8);
}

/**
 * Generate a random secret
 * @param {number} length - Length of secret
 * @returns {string} Random string
 */
export function generateSecret(length = 32) {
  return CryptoJS.lib.WordArray.random(length).toString();
}

/**
 * Hash a value (for audit logs)
 * @param {string} value - Value to hash
 * @returns {string} Hashed value
 */
export function hash(value) {
  return CryptoJS.SHA256(value).toString();
}

/**
 * Mask a secret for display
 * @param {string} value - Value to mask
 * @param {number} visibleChars - Number of visible characters
 * @returns {string} Masked value
 */
export function maskSecret(value, visibleChars = 4) {
  if (!value || value.length <= visibleChars) {
    return '*'.repeat(8);
  }
  return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars);
}

/**
 * Verify password against stored hash
 * @param {string} password - Password to verify
 * @param {string} storedHash - Stored password hash
 * @returns {boolean} True if valid
 */
export function verifyPassword(password, storedHash) {
  const config = getConfig();
  const salt = config.salt || 'envguard-salt';
  
  const hash = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
  
  return hash === storedHash;
}
