import initSqlJs from 'sql.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { getConfig } from '../commands/init.js';

let db = null;
let SQL = null;

/**
 * Initialize SQL.js
 */
async function initSql() {
  if (SQL) return SQL;
  SQL = await initSqlJs();
  return SQL;
}

/**
 * Initialize and get the database (returns promise)
 */
export async function initDb() {
  if (db) return db;
  
  const config = getConfig();
  if (!config) throw new Error('Not initialized');
  
  const dbPath = join(config.dataDir, 'envguard.db');
  
  // Ensure directory exists
  const dir = dirname(dbPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  
  await initSql();
  
  // Load existing database or create new one
  if (existsSync(dbPath)) {
    const fileBuffer = readFileSync(dbPath);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS environments (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS variables (
      id TEXT PRIMARY KEY,
      environment_id TEXT NOT NULL,
      key TEXT NOT NULL,
      value TEXT,
      encrypted INTEGER DEFAULT 0,
      is_secret INTEGER DEFAULT 0,
      tags TEXT,
      description TEXT,
      rotation_enabled INTEGER DEFAULT 0,
      rotation_period_days INTEGER,
      last_rotated TEXT,
      next_rotation TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
      UNIQUE(environment_id, key)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT DEFAULT (datetime('now')),
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      old_value TEXT,
      new_value TEXT,
      user_id TEXT,
      user_name TEXT,
      ip_address TEXT,
      details TEXT,
      hash TEXT
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS rotation_history (
      id TEXT PRIMARY KEY,
      variable_id TEXT NOT NULL,
      rotated_at TEXT DEFAULT (datetime('now')),
      old_value_hash TEXT,
      new_value_hash TEXT,
      rotated_by TEXT,
      reason TEXT,
      FOREIGN KEY (variable_id) REFERENCES variables(id) ON DELETE CASCADE
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'read',
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS schedules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      cron_expression TEXT,
      enabled INTEGER DEFAULT 1,
      last_run TEXT,
      next_run TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  
  // Create indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_variables_env ON variables(environment_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_rotation_variable ON rotation_history(variable_id)`);
  
  // Save to file
  const data = db.export();
  const buffer = Buffer.from(data);
  writeFileSync(dbPath, buffer);
  
  return db;
}

/**
 * Save database to file
 */
function saveDb() {
  if (!db) return;
  
  const config = getConfig();
  if (!config) return;
  
  const dbPath = join(config.dataDir, 'envguard.db');
  const data = db.export();
  const buffer = Buffer.from(data);
  writeFileSync(dbPath, buffer);
}

/**
 * Close database connection
 */
export function closeDb() {
  if (db) {
    saveDb();
    db.close();
    db = null;
  }
}

/**
 * Execute a raw SQL query
 * @param {string} sql - SQL query
 * @param {Array} params - Query parameters
 */
export function exec(sql, params = []) {
  if (!db) {
    throw new Error('Database not initialized. Call await initDb() first.');
  }
  try {
    db.run(sql, params);
    saveDb();
    return { changes: db.getRowsModified() };
  } catch (error) {
    throw error;
  }
}

/**
 * Execute a query and return all results
 * @param {string} sql - SQL query
 * @param {Array} params - Query parameters
 */
export function all(sql, params = []) {
  if (!db) {
    throw new Error('Database not initialized. Call await initDb() first.');
  }
  try {
    const stmt = db.prepare(sql);
    if (params.length > 0) {
      stmt.bind(params);
    }
    
    const results = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push(row);
    }
    stmt.free();
    
    return results;
  } catch (error) {
    throw error;
  }
}

/**
 * Execute a query and return first result
 * @param {string} sql - SQL query
 * @param {Array} params - Query parameters
 */
export function get(sql, params = []) {
  const results = all(sql, params);
  return results.length > 0 ? results[0] : null;
}

/**
 * Backup database
 * @param {string} backupPath - Path to backup file
 */
export function backup(backupPath) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  const data = db.export();
  const buffer = Buffer.from(data);
  writeFileSync(backupPath, buffer);
}
