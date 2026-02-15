#!/usr/bin/env node

import chalk from 'chalk';
import cron from 'node-cron';
import { getConfig } from './commands/init.js';
import { initDb, all, exec } from './utils/database.js';
import { logAudit } from './utils/audit.js';
import { encrypt, decrypt, setMasterKey, generateSecret, hash } from './utils/crypto.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Scheduler for automated secret rotation
 */
class RotationScheduler {
  constructor() {
    this.tasks = new Map();
    this.isRunning = false;
  }

  /**
   * Start the scheduler
   */
  start() {
    console.log(chalk.cyan('🔄 Starting rotation scheduler...'));
    
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }

    this.isRunning = true;
    
    // Check for secrets needing rotation every hour
    cron.schedule('0 * * * *', () => {
      this.checkAndRotate();
    });

    console.log(chalk.green('✓ Scheduler started'));
    console.log(chalk.gray('  Checking for secrets to rotate every hour'));
  }

  /**
   * Check and rotate secrets that are due
   */
  async checkAndRotate() {
    if (!this.isRunning) return;
    
    try {
      await initDb();
      
      const secrets = all(`
        SELECT * FROM variables 
        WHERE is_secret = 1 
        AND rotation_enabled = 1 
        AND next_rotation IS NOT NULL
        AND next_rotation <= datetime('now')
      `);
      
      if (secrets.length > 0) {
        console.log(chalk.yellow(`⚠ Found ${secrets.length} secrets due for rotation`));
        
        for (const secret of secrets) {
          await this.rotateSecret(secret);
        }
      }
    } catch (error) {
      console.error(chalk.red('Error during scheduled rotation:'), error.message);
    }
  }

  /**
   * Rotate a single secret
   */
  async rotateSecret(variable) {
    try {
      // Generate new secret
      const newValue = generateSecret(32);
      const encryptedValue = encrypt(newValue);
      
      // Calculate next rotation
      const nextRotation = variable.rotation_period_days
        ? new Date(Date.now() + variable.rotation_period_days * 24 * 60 * 60 * 1000).toISOString()
        : null;
      
      // Store old hash
      const oldValueHash = hash(variable.value);
      const newValueHash = hash(encryptedValue);
      
      // Update variable
      exec(
        `UPDATE variables SET 
          value = ?, 
          last_rotated = datetime('now'),
          next_rotation = ?,
          updated_at = datetime('now')
         WHERE id = ?`,
        [encryptedValue, nextRotation, variable.id]
      );
      
      // Log rotation history
      const historyId = uuidv4();
      exec(
        `INSERT INTO rotation_history (id, variable_id, old_value_hash, new_value_hash, rotated_by, reason)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [historyId, variable.id, oldValueHash, newValueHash, 'scheduler', 'Automatic rotation']
      );
      
      // Log audit
      logAudit({
        action: 'rotate',
        entityType: 'variable',
        entityId: variable.id,
        oldValue: oldValueHash,
        newValue: newValueHash,
        details: { key: variable.key, automatic: true }
      });
      
      console.log(chalk.green(`✓ Rotated ${variable.key}`));
      
      // Send webhook notification
      await this.sendWebhookNotification(variable, newValue);
      
    } catch (error) {
      console.error(chalk.red(`✗ Failed to rotate ${variable.key}:`), error.message);
    }
  }

  /**
   * Send webhook notification
   */
  async sendWebhookNotification(variable, newValue) {
    const config = getConfig();
    const webhookUrl = config.rotationDefaults?.webhookUrl;
    
    if (!webhookUrl) return;
    
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event: 'secret_rotated',
          variable: variable.key,
          rotatedAt: new Date().toISOString(),
          nextRotation: variable.next_rotation
        })
      });
      
      if (response.ok) {
        console.log(chalk.gray(`  Webhook notification sent`));
      }
    } catch (error) {
      console.error(chalk.red('Webhook failed:'), error.message);
    }
  }

  /**
   * Stop the scheduler
   */
  stop() {
    this.isRunning = false;
    console.log(chalk.yellow('Scheduler stopped'));
  }
}

// Run scheduler if called directly
const scheduler = new RotationScheduler();
scheduler.start();

// Handle graceful shutdown
process.on('SIGINT', () => {
  scheduler.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  scheduler.stop();
  process.exit(0);
});
