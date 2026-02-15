import chalk from 'chalk';
import CryptoJS from 'crypto-js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import inquirer from 'inquirer';
import ora from 'ora';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let config = null;

/**
 * Get the config directory path
 */
function getConfigDir() {
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  return join(homeDir, '.envguard');
}

/**
 * Get the config file path
 */
function getConfigPath() {
  return join(getConfigDir(), 'config.json');
}

/**
 * Load configuration
 */
export function getConfig() {
  if (config) return config;
  
  const configPath = getConfigPath();
  if (!existsSync(configPath)) {
    return null;
  }
  
  try {
    config = JSON.parse(readFileSync(configPath, 'utf8'));
    return config;
  } catch (error) {
    console.error(chalk.red('Error loading config:'), error.message);
    return null;
  }
}

/**
 * Save configuration
 */
function saveConfig(newConfig) {
  const configDir = getConfigDir();
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }
  
  const configPath = getConfigPath();
  writeFileSync(configPath, JSON.stringify(newConfig, null, 2));
  config = newConfig;
}

/**
 * Initialize a new envguard project
 */
export async function initProject(options) {
  const spinner = ora('Initializing envguard...').start();
  
  try {
    // Check if already initialized
    const existingConfig = getConfig();
    if (existingConfig) {
      spinner.stop();
      const { overwrite } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'overwrite',
          message: 'envguard is already initialized. Do you want to reinitialize? This will delete all existing data.',
          default: false
        }
      ]);
      
      if (!overwrite) {
        console.log(chalk.yellow('Initialization cancelled.'));
        return;
      }
      
      spinner.start();
    }
    
    // Get project name
    let projectName = options.name;
    if (!projectName) {
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'projectName',
          message: 'Enter project name:',
          default: 'my-project'
        }
      ]);
      projectName = answers.projectName;
    }
    
    // Get master password
    let masterPassword = options.masterPassword;
    if (!masterPassword) {
      const answers = await inquirer.prompt([
        {
          type: 'password',
          name: 'masterPassword',
          message: 'Enter master password for encryption:',
          validate: (input) => {
            if (input.length < 8) {
              return 'Password must be at least 8 characters';
            }
            return true;
          }
        },
        {
          type: 'password',
          name: 'confirmPassword',
          message: 'Confirm master password:',
          validate: (input, answers) => {
            if (input !== answers.masterPassword) {
              return 'Passwords do not match';
            }
            return true;
          }
        }
      ]);
      masterPassword = answers.masterPassword;
    }
    
    // Generate salt and hash password
    const salt = uuidv4();
    const passwordHash = CryptoJS.PBKDF2(masterPassword, salt, {
      keySize: 256 / 32,
      iterations: 10000
    }).toString();
    
    // Create config
    const newConfig = {
      version: '1.0.0',
      projectName,
      salt,
      passwordHash,
      dataDir: join(getConfigDir(), 'data'),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      defaultEnv: 'development',
      rotationDefaults: {
        enabled: false,
        periodDays: 90
      },
      auditRetentionDays: 90
    };
    
    // Save config
    saveConfig(newConfig);
    
    // Create data directory
    mkdirSync(newConfig.dataDir, { recursive: true });
    
    spinner.succeed(chalk.green('✓ envguard initialized successfully!'));
    
    console.log(chalk.cyan('\nNext steps:'));
    console.log(chalk.gray('  1. Create an environment: ') + chalk.white('envguard env create production'));
    console.log(chalk.gray('  2. Add variables: ') + chalk.white('envguard var set API_KEY "your-key" --env production --secret'));
    console.log(chalk.gray('  3. View audit logs: ') + chalk.white('envguard audit'));
    console.log(chalk.gray('  4. Start rotation: ') + chalk.white('envguard rotate run --env production'));
    
  } catch (error) {
    spinner.fail(chalk.red('✗ Initialization failed: ') + error.message);
    throw error;
  }
}

/**
 * Reset/clear all data
 */
export async function resetProject() {
  const spinner = ora('Resetting envguard...').start();
  
  try {
    const configPath = getConfigPath();
    if (existsSync(configPath)) {
      const fs = await import('fs');
      fs.unlinkSync(configPath);
    }
    
    config = null;
    spinner.succeed(chalk.green('✓ envguard reset successfully!'));
  } catch (error) {
    spinner.fail(chalk.red('✗ Reset failed: ') + error.message);
    throw error;
  }
}

/**
 * Update configuration
 */
export function updateConfig(key, value) {
  const currentConfig = getConfig();
  if (!currentConfig) {
    throw new Error('Not initialized');
  }
  
  currentConfig[key] = value;
  currentConfig.updatedAt = new Date().toISOString();
  saveConfig(currentConfig);
  
  return currentConfig;
}

/**
 * Check if initialized
 */
export function isInitialized() {
  return getConfig() !== null;
}
