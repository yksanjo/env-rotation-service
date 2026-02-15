import { v4 as uuidv4 } from 'uuid';
import { all, get, exec } from './database.js';
import { hash } from './crypto.js';
import { writeFileSync } from 'fs';

/**
 * Log an audit entry
 * @param {Object} options - Audit log options
 */
export function logAudit(options) {
  const {
    action,
    entityType,
    entityId,
    oldValue,
    newValue,
    userId = 'system',
    userName = 'system',
    ipAddress = 'localhost',
    details = {}
  } = options;
  
  const id = uuidv4();
  const timestamp = new Date().toISOString();
  
  // Create hash for tamper detection
  const dataToHash = `${timestamp}:${action}:${entityType}:${entityId}:${oldValue}:${newValue}:${userId}`;
  const logHash = hash(dataToHash);
  
  const detailsJson = JSON.stringify(details);
  
  exec(
    `INSERT INTO audit_logs (id, timestamp, action, entity_type, entity_id, old_value, new_value, user_id, user_name, ip_address, details, hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, timestamp, action, entityType, entityId, oldValue || null, newValue || null, userId, userName, ipAddress, detailsJson, logHash]
  );
  
  return { id, timestamp, hash: logHash };
}

/**
 * Get audit logs with filters
 * @param {Object} filters - Filter options
 */
export function getAuditLogs(filters = {}) {
  const { action, entityType, entityId, startDate, endDate, limit = 100, offset = 0 } = filters;
  
  let sql = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];
  
  if (action) {
    sql += ' AND action = ?';
    params.push(action);
  }
  
  if (entityType) {
    sql += ' AND entity_type = ?';
    params.push(entityType);
  }
  
  if (entityId) {
    sql += ' AND entity_id = ?';
    params.push(entityId);
  }
  
  if (startDate) {
    sql += ' AND timestamp >= ?';
    params.push(startDate);
  }
  
  if (endDate) {
    sql += ' AND timestamp <= ?';
    params.push(endDate);
  }
  
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  
  return all(sql, params);
}

/**
 * Get audit log by ID
 * @param {string} id - Audit log ID
 */
export function getAuditLog(id) {
  return get('SELECT * FROM audit_logs WHERE id = ?', [id]);
}

/**
 * Verify audit log integrity
 * @param {string} id - Audit log ID
 */
export function verifyAuditLog(id) {
  const log = getAuditLog(id);
  if (!log) return null;
  
  const dataToHash = `${log.timestamp}:${log.action}:${log.entity_type}:${log.entity_id}:${log.old_value}:${log.new_value}:${log.user_id}`;
  const calculatedHash = hash(dataToHash);
  
  return {
    valid: calculatedHash === log.hash,
    log,
    calculatedHash,
    storedHash: log.hash
  };
}

/**
 * Export audit logs to file
 * @param {string} filePath - Path to export file
 * @param {Object} filters - Filter options
 */
export function exportAuditLogs(filePath, filters = {}) {
  const logs = getAuditLogs({ ...filters, limit: 100000 });
  
  const exportData = {
    exportedAt: new Date().toISOString(),
    filters,
    logs
  };
  
  writeFileSync(filePath, JSON.stringify(exportData, null, 2));
  
  return logs.length;
}

/**
 * Clean up old audit logs
 * @param {number} daysToKeep - Days to keep logs
 */
export function cleanupAuditLogs(daysToKeep = 90) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
  
  const result = exec(
    'DELETE FROM audit_logs WHERE timestamp < ?',
    [cutoffDate.toISOString()]
  );
  
  return result.changes;
}

/**
 * Get audit statistics
 */
export function getAuditStats() {
  const totalLogs = get('SELECT COUNT(*) as count FROM audit_logs');
  const actionsByType = all(`
    SELECT action, COUNT(*) as count 
    FROM audit_logs 
    GROUP BY action 
    ORDER BY count DESC
  `);
  
  const recentActivity = all(`
    SELECT DATE(timestamp) as date, COUNT(*) as count 
    FROM audit_logs 
    WHERE timestamp >= datetime('now', '-7 days')
    GROUP BY DATE(timestamp)
    ORDER BY date DESC
  `);
  
  return {
    totalLogs: totalLogs.count,
    actionsByType,
    recentActivity
  };
}

/**
 * Get recent activity for a specific entity
 * @param {string} entityType - Entity type
 * @param {string} entityId - Entity ID
 */
export function getEntityHistory(entityType, entityId) {
  return all(
    'SELECT * FROM audit_logs WHERE entity_type = ? AND entity_id = ? ORDER BY timestamp DESC',
    [entityType, entityId]
  );
}
