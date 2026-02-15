import chalk from 'chalk';
import { Command } from 'commander';
import { v4 as uuidv4 } from 'uuid';
import inquirer from 'inquirer';
import ora from 'ora';
import { getConfig } from './init.js';
import { initDb, exec, all, get } from '../utils/database.js';
import { logAudit } from '../utils/audit.js';
import { encrypt, decrypt, setMasterKey, hasMasterKey, generateSecret, hash } from '../utils/crypto.js';

// Run rotation for secrets
const run = new Command('run')
  .description('Rotate secrets in an environment')
  .option('-e, --env <name>', 'Environment name')
  .option('-k, --key <key>', 'Specific variable key to rotate')
  .option('--all', 'Rotate all secrets (including non-expired)')
  .option('-f, --force', 'Skip confirmation')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = get('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      // Build query based on options
      let sql = 'SELECT * FROM variables WHERE environment_id = ? AND is_secret = 1';
      const params = [env.id];
      
      if (options.key) {
        sql += ' AND key = ?';
        params.push(options.key);
      } else if (!options.all) {
        // Only rotate expired secrets
        sql += ' AND (next_rotation IS NULL OR next_rotation <= datetime("now"))';
      }
      
      const variables = all(sql, params);
      
      if (variables.length === 0) {
        console.log(chalk.yellow('No secrets to rotate.'));
        return;
      }
      
      console.log(chalk.cyan(`\nFound ${variables.length} secret(s) to rotate:\n`));
      
      const table = variables.map(v => ({
        Key: chalk.white(v.key),
        'Last Rotated': v.last_rotated ? chalk.gray(new Date(v.last_rotated).toLocaleDateString()) : chalk.gray('Never'),
        'Next Rotation': v.next_rotation ? chalk.gray(new Date(v.next_rotation).toLocaleDateString()) : chalk.gray('-')
      }));
      
      console.table(table);
      
      // Confirmation
      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Rotate ${variables.length} secret(s)?`,
            default: true
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Rotation cancelled.'));
          return;
        }
      }
      
      // Set master key for encryption
      if (!hasMasterKey()) {
        const prompt = require('prompt-sync')({ echo: '*' });
        console.log(chalk.gray('Master password required for encryption.'));
        const password = prompt('Enter master password: ');
        
        const CryptoJS = require('crypto-js');
        const salt = config.salt || 'envguard-salt';
        const key = CryptoJS.PBKDF2(password, salt, {
          keySize: 256 / 32,
          iterations: 10000
        }).toString();
        
        if (key !== config.passwordHash) {
          throw new Error('Invalid master password');
        }
        
        setMasterKey(password);
      }
      
      const spinner = ora('Rotating secrets...').start();
      
      let rotated = 0;
      const now = new Date();
      
      for (const v of variables) {
        // Generate new secret
        const newValue = generateSecret(32);
        const encryptedValue = encrypt(newValue);
        
        // Calculate next rotation date
        const nextRotation = v.rotation_period_days
          ? new Date(Date.now() + v.rotation_period_days * 24 * 60 * 60 * 1000).toISOString()
          : null;
        
        // Store old value hash for audit
        const oldValueHash = hash(v.value);
        const newValueHash = hash(encryptedValue);
        
        // Update variable
        exec(
          `UPDATE variables SET 
            value = ?, 
            last_rotated = datetime("now"),
            next_rotation = ?,
            updated_at = datetime("now")
           WHERE id = ?`,
          [encryptedValue, nextRotation, v.id]
        );
        
        // Log rotation history
        const historyId = uuidv4();
        exec(
          `INSERT INTO rotation_history (id, variable_id, old_value_hash, new_value_hash, rotated_by, reason)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [historyId, v.id, oldValueHash, newValueHash, 'system', 'Manual rotation']
        );
        
        // Log audit
        logAudit({
          action: 'rotate',
          entityType: 'variable',
          entityId: v.id,
          oldValue: oldValueHash,
          newValue: newValueHash,
          details: { key: v.key, envName }
        });
        
        rotated++;
      }
      
      spinner.succeed(chalk.green(`✓ Rotated ${rotated} secret(s) successfully!`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Schedule rotation
const schedule = new Command('schedule')
  .description('Manage rotation schedules')
  .option('-e, --env <name>', 'Environment name')
  .option('-d, --days <number>', 'Default rotation period in days')
  .option('--enable', 'Enable auto-rotation for secrets')
  .option('--disable', 'Disable auto-rotation for secrets')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      if (options.days) {
        // Update default rotation period
        config.rotationDefaults = config.rotationDefaults || {};
        config.rotationDefaults.periodDays = parseInt(options.days);
        
        console.log(chalk.green(`✓ Default rotation period set to ${options.days} days`));
      }
      
      if (options.enable || options.disable) {
        const envName = options.env || config.defaultEnv;
        const env = get('SELECT * FROM environments WHERE name = ?', [envName]);
        
        if (!env) {
          console.log(chalk.red(`✗ Environment "${envName}" not found`));
          return;
        }
        
        const enabled = options.enable ? 1 : 0;
        
        // Update all secrets in environment
        exec(
          'UPDATE variables SET rotation_enabled = ? WHERE environment_id = ? AND is_secret = 1',
          [enabled, env.id]
        );
        
        console.log(chalk.green(`✓ Auto-rotation ${options.enable ? 'enabled' : 'disabled'} for "${envName}"`));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// View rotation history
const history = new Command('history')
  .description('View rotation history')
  .option('-e, --env <name>', 'Environment name')
  .option('-k, --key <key>', 'Variable key')
  .option('-l, --limit <number>', 'Number of records', '20')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      let sql = `
        SELECT rh.*, v.key as variable_key, e.name as env_name 
        FROM rotation_history rh
        JOIN variables v ON rh.variable_id = v.id
        JOIN environments e ON v.environment_id = e.id
        WHERE 1=1
      `;
      const params = [];
      
      if (options.env) {
        sql += ' AND e.name = ?';
        params.push(options.env);
      }
      
      if (options.key) {
        sql += ' AND v.key = ?';
        params.push(options.key);
      }
      
      sql += ' ORDER BY rh.rotated_at DESC LIMIT ?';
      params.push(parseInt(options.limit));
      
      const history = all(sql, params);
      
      if (history.length === 0) {
        console.log(chalk.yellow('No rotation history found.'));
        return;
      }
      
      console.log(chalk.cyan.bold('\n🔄 Rotation History\n'));
      
      const table = history.map(h => ({
        Key: chalk.white(h.variable_key),
        Environment: chalk.gray(h.env_name),
        'Rotated At': chalk.gray(new Date(h.rotated_at).toLocaleString()),
        'By': chalk.gray(h.rotated_by),
        Reason: chalk.gray(h.reason || '-')
      }));
      
      console.table(table);
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Check rotation status
const status = new Command('status')
  .description('Check rotation status for secrets')
  .option('-e, --env <name>', 'Environment name')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = get('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      const sql = `
        SELECT * FROM variables 
        WHERE environment_id = ? AND is_secret = 1 AND rotation_enabled = 1
      `;
      
      const variables = all(sql, [env.id]);
      
      if (variables.length === 0) {
        console.log(chalk.yellow('No secrets with rotation enabled.'));
        return;
      }
      
      console.log(chalk.cyan.bold(`\n🔄 Rotation Status for "${envName}"\n`));
      
      const now = new Date();
      
      const table = variables.map(v => {
        const needsRotation = v.next_rotation && new Date(v.next_rotation) <= now;
        
        return {
          Key: chalk.white(v.key),
          'Last Rotated': v.last_rotated ? chalk.gray(new Date(v.last_rotated).toLocaleDateString()) : chalk.red('Never'),
          'Next Rotation': v.next_rotation 
            ? (needsRotation ? chalk.red(new Date(v.next_rotation).toLocaleDateString()) : chalk.gray(new Date(v.next_rotation).toLocaleDateString()))
            : chalk.gray('-'),
          Status: needsRotation ? chalk.red('⚠ Due') : (v.last_rotated ? chalk.green('✓ OK') : chalk.yellow('⚠ Pending'))
        };
      });
      
      console.table(table);
      
      const dueCount = variables.filter(v => v.next_rotation && new Date(v.next_rotation) <= now).length;
      
      if (dueCount > 0) {
        console.log(chalk.yellow(`\n⚠ ${dueCount} secret(s) are due for rotation.`));
        console.log(chalk.gray(`  Run: envguard rotate run --env ${envName}`));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

export const rotateCommands = {
  run,
  schedule,
  history,
  status
};
