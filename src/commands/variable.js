import chalk from 'chalk';
import { Command } from 'commander';
import { v4 as uuidv4 } from 'uuid';
import inquirer from 'inquirer';
import ora from 'ora';
import { getConfig } from './init.js';
import { initDb, exec, all, get as dbGet } from '../utils/database.js';
import { logAudit } from '../utils/audit.js';
import { encrypt, decrypt, setMasterKey, hasMasterKey, clearMasterKey, maskSecret, generateSecret, encryptWithPassword, decryptWithPassword } from '../utils/crypto.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import promptSync from 'prompt-sync';
import CryptoJS from 'crypto-js';

// Get master password securely
function getMasterPassword() {
  const config = getConfig();
  
  // Check if there's a stored password hash
  if (!config || !config.passwordHash) {
    throw new Error('Not initialized');
  }
  
  const prompt = promptSync({ echo: '*' });
  console.log(chalk.gray('Master password required to access secrets.'));
  const password = prompt('Enter master password: ');
  
  // Verify password
  const salt = config.salt || 'envguard-salt';
  const hash = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
  
  if (hash !== config.passwordHash) {
    throw new Error('Invalid master password');
  }
  
  return password;
}

// List variables
const list = new Command('list')
  .description('List environment variables')
  .option('-e, --env <name>', 'Environment name')
  .option('-s, --secrets', 'Show secrets (requires master password)')
  .option('-t, --tags <tags>', 'Filter by tags (comma-separated)')
  .option('--search <term>', 'Search in key names')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      let sql = 'SELECT * FROM variables WHERE environment_id = ?';
      const params = [env.id];
      
      if (options.tags) {
        const tags = options.tags.split(',').map(t => t.trim());
        sql += ' AND (' + tags.map(() => 'tags LIKE ?').join(' OR ') + ')';
        tags.forEach(t => params.push(`%${t}%`));
      }
      
      if (options.search) {
        sql += ' AND key LIKE ?';
        params.push(`%${options.search}%`);
      }
      
      sql += ' ORDER BY key';
      
      const variables = all(sql, params);
      
      if (variables.length === 0) {
        console.log(chalk.yellow(`No variables in "${envName}". Add one with:`));
        console.log(chalk.cyan(`  envguard var set KEY "value" --env ${envName}`));
        return;
      }
      
      console.log(chalk.cyan.bold(`\n🔐 Variables in "${envName}"\n`));
      
      const table = variables.map(v => {
        let displayValue = v.value;
        
        if (v.is_secret) {
          if (options.secrets) {
            // Decrypt if master key is set
            try {
              if (hasMasterKey()) {
                displayValue = decrypt(v.value);
              } else {
                displayValue = chalk.yellow('(run with --secrets to show)');
              }
            } catch (e) {
              displayValue = chalk.red('(decryption failed)');
            }
          } else {
            displayValue = maskSecret(v.value || '********');
          }
        }
        
        return {
          Key: chalk.white(v.key),
          Value: v.is_secret ? chalk.yellow(displayValue) : chalk.gray(displayValue),
          Secret: v.is_secret ? chalk.red('🔒') : '',
          Tags: v.tags ? chalk.gray(v.tags) : '',
          Updated: chalk.gray(new Date(v.updated_at).toLocaleDateString())
        };
      });
      
      console.table(table);
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Set variable
const set = new Command('set')
  .description('Set an environment variable')
  .argument('<key>', 'Variable key')
  .argument('[value]', 'Variable value (will prompt if not provided)')
  .option('-e, --env <name>', 'Environment name')
  .option('-s, --secret', 'Mark as secret (will be encrypted)')
  .option('-t, --tags <tags>', 'Tags (comma-separated)')
  .option('-d, --description <description>', 'Description')
  .option('--rotation-days <days>', 'Auto-rotation period in days')
  .action(async (key, providedValue, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      // Get value if not provided
      let value = providedValue;
      if (!value) {
        if (options.secret) {
          const prompt = promptSync({ echo: '*' });
          value = prompt('Enter secret value: ');
        } else {
          const answers = await inquirer.prompt([
            {
              type: 'input',
              name: 'value',
              message: `Enter value for ${key}:`
            }
          ]);
          value = answers.value;
        }
      }
      
      // Check if variable exists
      const existing = dbGet('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [env.id, key]);
      
      const spinner = ora('Saving variable...').start();
      
      let storedValue = value;
      let isEncrypted = 0;
      
      // Encrypt if secret
      if (options.secret) {
        try {
          if (!hasMasterKey()) {
            setMasterKey(getMasterPassword());
          }
          storedValue = encrypt(value);
          isEncrypted = 1;
        } catch (e) {
          spinner.fail(chalk.red('✗ Failed to encrypt: ') + e.message);
          return;
        }
      }
      
      const id = existing?.id || uuidv4();
      const rotationEnabled = options.rotationDays ? 1 : 0;
      const nextRotation = options.rotationDays 
        ? new Date(Date.now() + options.rotationDays * 24 * 60 * 60 * 1000).toISOString()
        : null;
      
      if (existing) {
        exec(
          `UPDATE variables SET 
            value = ?, encrypted = ?, is_secret = ?, tags = ?, description = ?,
            rotation_enabled = ?, rotation_period_days = ?, next_rotation = ?,
            updated_at = datetime('now')
           WHERE id = ?`,
          [storedValue, isEncrypted, options.secret ? 1 : 0, options.tags || '', options.description || '',
           rotationEnabled, options.rotationDays || null, nextRotation, id]
        );
        
        logAudit({
          action: 'update',
          entityType: 'variable',
          entityId: id,
          oldValue: existing.value,
          newValue: storedValue,
          details: { key, envName, isSecret: options.secret }
        });
      } else {
        exec(
          `INSERT INTO variables 
            (id, environment_id, key, value, encrypted, is_secret, tags, description, rotation_enabled, rotation_period_days, next_rotation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [id, env.id, key, storedValue, isEncrypted, options.secret ? 1 : 0, 
           options.tags || '', options.description || '', rotationEnabled, options.rotationDays || null, nextRotation]
        );
        
        logAudit({
          action: 'create',
          entityType: 'variable',
          entityId: id,
          newValue: storedValue,
          details: { key, envName, isSecret: options.secret }
        });
      }
      
      spinner.succeed(chalk.green(`✓ Variable ${key} saved successfully!`));
      
      if (options.secret) {
        console.log(chalk.gray('  Value encrypted and stored securely.'));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Get variable
const getVar = new Command('get')
  .description('Get an environment variable value')
  .argument('<key>', 'Variable key')
  .option('-e, --env <name>', 'Environment name')
  .action(async (key, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      const variable = dbGet('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [env.id, key]);
      
      if (!variable) {
        console.log(chalk.red(`✗ Variable "${key}" not found in "${envName}"`));
        return;
      }
      
      let value = variable.value;
      
      if (variable.is_secret) {
        try {
          if (!hasMasterKey()) {
            setMasterKey(getMasterPassword());
          }
          value = decrypt(variable.value);
        } catch (e) {
          console.log(chalk.red(`✗ Failed to decrypt: ${e.message}`));
          console.log(chalk.gray('  Make sure you have the correct master password.'));
          return;
        }
      }
      
      console.log(chalk.white(value));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Delete variable
const deleteCmd = new Command('delete')
  .description('Delete an environment variable')
  .argument('<key>', 'Variable key')
  .option('-e, --env <name>', 'Environment name')
  .option('-f, --force', 'Skip confirmation')
  .action(async (key, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      const variable = dbGet('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [env.id, key]);
      
      if (!variable) {
        console.log(chalk.red(`✗ Variable "${key}" not found in "${envName}"`));
        return;
      }
      
      // Confirmation
      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Delete variable "${key}"?`,
            default: false
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Deletion cancelled.'));
          return;
        }
      }
      
      const spinner = ora('Deleting variable...').start();
      
      exec('DELETE FROM variables WHERE id = ?', [variable.id]);
      
      logAudit({
        action: 'delete',
        entityType: 'variable',
        entityId: variable.id,
        oldValue: variable.value,
        details: { key, envName }
      });
      
      spinner.succeed(chalk.green(`✓ Variable "${key}" deleted successfully!`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Edit variable (interactive)
const edit = new Command('edit')
  .description('Edit an environment variable interactively')
  .argument('<key>', 'Variable key')
  .option('-e, --env <name>', 'Environment name')
  .action(async (key, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      const variable = dbGet('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [env.id, key]);
      
      if (!variable) {
        console.log(chalk.red(`✗ Variable "${key}" not found in "${envName}"`));
        return;
      }
      
      // Get current value (decrypt if secret)
      let currentValue = variable.value;
      if (variable.is_secret) {
        try {
          if (!hasMasterKey()) {
            setMasterKey(getMasterPassword());
          }
          currentValue = decrypt(variable.value);
        } catch (e) {
          console.log(chalk.red(`✗ Failed to decrypt current value: ${e.message}`));
          return;
        }
      }
      
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'value',
          message: `Enter new value for ${key}:`,
          default: currentValue
        },
        {
          type: 'input',
          name: 'tags',
          message: 'Enter tags (comma-separated):',
          default: variable.tags || ''
        },
        {
          type: 'input',
          name: 'description',
          message: 'Enter description:',
          default: variable.description || ''
        }
      ]);
      
      const spinner = ora('Updating variable...').start();
      
      let storedValue = answers.value;
      
      if (variable.is_secret) {
        try {
          if (!hasMasterKey()) {
            setMasterKey(getMasterPassword());
          }
          storedValue = encrypt(answers.value);
        } catch (e) {
          spinner.fail(chalk.red('✗ Failed to encrypt: ') + e.message);
          return;
        }
      }
      
      exec(
        `UPDATE variables SET value = ?, tags = ?, description = ?, updated_at = datetime('now') WHERE id = ?`,
        [storedValue, answers.tags, answers.description, variable.id]
      );
      
      logAudit({
        action: 'update',
        entityType: 'variable',
        entityId: variable.id,
        oldValue: variable.value,
        newValue: storedValue,
        details: { key, envName }
      });
      
      spinner.succeed(chalk.green(`✓ Variable "${key}" updated successfully!`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Bulk operations
const bulk = new Command('bulk')
  .description('Perform bulk operations on variables')
  .option('-e, --env <name>', 'Environment name')
  .option('-a, --action <action>', 'Action: import, export, delete')
  .option('-f, --file <path>', 'File path for import/export')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const envName = options.env || config.defaultEnv;
      const env = dbGet('SELECT * FROM environments WHERE name = ?', [envName]);
      
      if (!env) {
        console.log(chalk.red(`✗ Environment "${envName}" not found`));
        return;
      }
      
      if (options.action === 'export') {
        const variables = all('SELECT * FROM variables WHERE environment_id = ?', [env.id]);
        
        const exportData = {};
        variables.forEach(v => {
          exportData[v.key] = v.is_secret ? (v.encrypted ? v.value : v.value) : v.value;
        });
        
        const filePath = options.file || `${envName}-env.json`;
        writeFileSync(filePath, JSON.stringify(exportData, null, 2));
        
        console.log(chalk.green(`✓ Exported ${variables.length} variables to ${filePath}`));
        
      } else if (options.action === 'import') {
        if (!options.file) {
          console.log(chalk.red('✗ Please specify file path with -f option'));
          return;
        }
        
        if (!existsSync(options.file)) {
          console.log(chalk.red(`✗ File "${options.file}" not found`));
          return;
        }
        
        const data = JSON.parse(readFileSync(options.file, 'utf8'));
        let imported = 0;
        
        for (const [key, value] of Object.entries(data)) {
          const id = uuidv4();
          const existing = dbGet('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [env.id, key]);
          
          if (existing) {
            exec('UPDATE variables SET value = ?, updated_at = datetime("now") WHERE id = ?', [value, existing.id]);
          } else {
            exec('INSERT INTO variables (id, environment_id, key, value) VALUES (?, ?, ?, ?)', [id, env.id, key, value]);
          }
          imported++;
        }
        
        console.log(chalk.green(`✓ Imported ${imported} variables`));
        
      } else if (options.action === 'delete') {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Delete all variables in "${envName}"?`,
            default: false
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Operation cancelled.'));
          return;
        }
        
        exec('DELETE FROM variables WHERE environment_id = ?', [env.id]);
        console.log(chalk.green(`✓ All variables deleted from "${envName}"`));
        
      } else {
        console.log(chalk.red('✗ Invalid action. Use: import, export, or delete'));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

export const varCommands = {
  list,
  set,
  get: getVar,
  delete: deleteCmd,
  edit,
  bulk
};
