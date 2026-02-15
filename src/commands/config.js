import chalk from 'chalk';
import { Command } from 'commander';
import CryptoJS from 'crypto-js';
import { v4 as uuidv4 } from 'uuid';
import inquirer from 'inquirer';
import ora from 'ora';
import { getConfig, updateConfig } from './init.js';
import { initDb, exec, all, get } from '../utils/database.js';

// View configuration
const view = new Command('view')
  .description('View current configuration')
  .action(async () => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      console.log(chalk.cyan.bold('\n⚙️  Configuration\n'));
      
      const displayConfig = {
        'Project Name': chalk.white(config.projectName),
        'Version': chalk.gray(config.version),
        'Default Environment': chalk.white(config.defaultEnv),
        'Data Directory': chalk.gray(config.dataDir),
        'Created At': chalk.gray(new Date(config.createdAt).toLocaleString()),
        'Audit Retention': chalk.gray(`${config.auditRetentionDays} days`),
        'Default Rotation Period': chalk.gray(`${config.rotationDefaults?.periodDays || 90} days`),
        'Auto-rotation': config.rotationDefaults?.enabled ? chalk.green('Enabled') : chalk.gray('Disabled')
      };
      
      console.table(displayConfig);
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Set configuration
const set = new Command('set')
  .description('Set configuration values')
  .option('--default-env <name>', 'Set default environment')
  .option('--audit-days <days>', 'Set audit log retention days')
  .option('--rotation-days <days>', 'Set default rotation period in days')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      if (options.defaultEnv) {
        const env = get('SELECT * FROM environments WHERE name = ?', [options.defaultEnv]);
        if (!env) {
          console.log(chalk.red(`✗ Environment "${options.defaultEnv}" not found`));
          return;
        }
        updateConfig('defaultEnv', options.defaultEnv);
        console.log(chalk.green(`✓ Default environment set to "${options.defaultEnv}"`));
      }
      
      if (options.auditDays) {
        updateConfig('auditRetentionDays', parseInt(options.auditDays));
        console.log(chalk.green(`✓ Audit retention set to ${options.auditDays} days`));
      }
      
      if (options.rotationDays) {
        config.rotationDefaults = config.rotationDefaults || {};
        config.rotationDefaults.periodDays = parseInt(options.rotationDays);
        updateConfig('rotationDefaults', config.rotationDefaults);
        console.log(chalk.green(`✓ Default rotation period set to ${options.rotationDays} days`));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// User management
const users = new Command('users')
  .description('Manage users')
  .action(async () => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const userList = all('SELECT id, username, role, created_at, last_login FROM users ORDER BY username');
      
      if (userList.length === 0) {
        console.log(chalk.yellow('No users found.'));
        console.log(chalk.gray('  Use "envguard config users add" to add a user.'));
        return;
      }
      
      console.log(chalk.cyan.bold('\n👥 Users\n'));
      
      const table = userList.map(u => ({
        Username: chalk.white(u.username),
        Role: u.role === 'admin' ? chalk.red(u.role) : (u.role === 'write' ? chalk.yellow(u.role) : chalk.gray(u.role)),
        'Last Login': u.last_login ? chalk.gray(new Date(u.last_login).toLocaleString()) : chalk.gray('Never'),
        Created: chalk.gray(new Date(u.created_at).toLocaleDateString())
      }));
      
      console.table(table);
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Add user
const addUser = new Command('add')
  .description('Add a new user')
  .argument('<username>', 'Username')
  .option('-r, --role <role>', 'User role (read, write, admin)', 'read')
  .action(async (username, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      // Check if user exists
      const existing = get('SELECT * FROM users WHERE username = ?', [username]);
      if (existing) {
        console.log(chalk.red(`✗ User "${username}" already exists`));
        return;
      }
      
      // Get password
      const answers = await inquirer.prompt([
        {
          type: 'password',
          name: 'password',
          message: 'Enter password:',
          validate: (input) => input.length >= 6 || 'Password must be at least 6 characters'
        },
        {
          type: 'password',
          name: 'confirm',
          message: 'Confirm password:',
          validate: (input, answers) => input === answers.password || 'Passwords do not match'
        }
      ]);
      
      const id = uuidv4();
      const salt = uuidv4();
      const passwordHash = CryptoJS.PBKDF2(answers.password, salt, {
        keySize: 256 / 32,
        iterations: 10000
      }).toString();
      
      exec(
        'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
        [id, username, passwordHash, options.role]
      );
      
      console.log(chalk.green(`✓ User "${username}" added with role "${options.role}"`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Delete user
const deleteUser = new Command('delete')
  .description('Delete a user')
  .argument('<username>', 'Username')
  .option('-f, --force', 'Skip confirmation')
  .action(async (username, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const user = get('SELECT * FROM users WHERE username = ?', [username]);
      if (!user) {
        console.log(chalk.red(`✗ User "${username}" not found`));
        return;
      }
      
      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Delete user "${username}"?`,
            default: false
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Deletion cancelled.'));
          return;
        }
      }
      
      exec('DELETE FROM users WHERE id = ?', [user.id]);
      console.log(chalk.green(`✓ User "${username}" deleted`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

users.addCommand(addUser);
users.addCommand(deleteUser);

export const configCommands = {
  view,
  set,
  users
};
