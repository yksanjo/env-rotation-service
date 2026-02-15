import chalk from 'chalk';
import { Command } from 'commander';
import { v4 as uuidv4 } from 'uuid';
import inquirer from 'inquirer';
import ora from 'ora';
import { getConfig, updateConfig } from './init.js';
import { initDb, exec, all, get } from '../utils/database.js';
import { logAudit } from '../utils/audit.js';
import { setMasterKey, clearMasterKey, hasMasterKey } from '../utils/crypto.js';

// List environments
const list = new Command('list')
  .description('List all environments')
  .option('-v, --verbose', 'Show detailed information')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      const environments = all('SELECT * FROM environments ORDER BY name');
      
      if (environments.length === 0) {
        console.log(chalk.yellow('No environments found. Create one with:'));
        console.log(chalk.cyan('  envguard env create <name>'));
        return;
      }
      
      console.log(chalk.cyan.bold('\n📦 Environments\n'));
      
      const table = environments.map(env => ({
        Name: chalk.white(env.name),
        ID: chalk.gray(env.id.substring(0, 8)),
        Description: env.description || chalk.gray('-'),
        Created: chalk.gray(new Date(env.created_at).toLocaleDateString())
      }));
      
      console.table(table);
      
      if (options.verbose) {
        console.log(chalk.gray(`\nDefault: ${chalk.white(config.defaultEnv)}`));
      }
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Create environment
const create = new Command('create')
  .description('Create a new environment')
  .argument('<name>', 'Environment name')
  .option('-d, --description <description>', 'Environment description')
  .option('--default', 'Set as default environment')
  .action(async (name, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    const spinner = ora('Creating environment...').start();
    
    try {
      await initDb();
      
      // Check if environment already exists
      const existing = get('SELECT * FROM environments WHERE name = ?', [name]);
      if (existing) {
        spinner.fail(chalk.red(`✗ Environment "${name}" already exists`));
        return;
      }
      
      const id = uuidv4();
      const description = options.description || '';
      
      exec(
        'INSERT INTO environments (id, name, description) VALUES (?, ?, ?)',
        [id, name, description]
      );
      
      logAudit({
        action: 'create',
        entityType: 'environment',
        entityId: id,
        newValue: JSON.stringify({ name, description }),
        details: { name, description }
      });
      
      // Set as default if requested
      if (options.default) {
        updateConfig('defaultEnv', name);
      }
      
      spinner.succeed(chalk.green(`✓ Environment "${name}" created successfully!`));
      
    } catch (error) {
      spinner.fail(chalk.red('✗ Error: ') + error.message);
    }
  });

// Delete environment
const deleteCmd = new Command('delete')
  .description('Delete an environment')
  .argument('<name>', 'Environment name')
  .option('-f, --force', 'Skip confirmation')
  .action(async (name, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      initDb();
      
      const env = get('SELECT * FROM environments WHERE name = ?', [name]);
      if (!env) {
        console.log(chalk.red(`✗ Environment "${name}" not found`));
        return;
      }
      
      // Confirmation
      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Delete environment "${name}" and all its variables?`,
            default: false
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Deletion cancelled.'));
          return;
        }
      }
      
      const spinner = ora('Deleting environment...').start();
      
      // Delete variables first
      exec('DELETE FROM variables WHERE environment_id = ?', [env.id]);
      
      // Delete environment
      exec('DELETE FROM environments WHERE id = ?', [env.id]);
      
      logAudit({
        action: 'delete',
        entityType: 'environment',
        entityId: env.id,
        oldValue: JSON.stringify({ name: env.name }),
        details: { name: env.name, deletedVariables: true }
      });
      
      spinner.succeed(chalk.green(`✓ Environment "${name}" deleted successfully!`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Clone environment
const clone = new Command('clone')
  .description('Clone an environment')
  .argument('<source>', 'Source environment name')
  .argument('<target>', 'Target environment name')
  .option('-v, --variables', 'Clone variables as well')
  .action(async (source, target, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    const spinner = ora('Cloning environment...').start();
    
    try {
      initDb();
      
      const sourceEnv = get('SELECT * FROM environments WHERE name = ?', [source]);
      if (!sourceEnv) {
        spinner.fail(chalk.red(`✗ Source environment "${source}" not found`));
        return;
      }
      
      const existing = get('SELECT * FROM environments WHERE name = ?', [target]);
      if (existing) {
        spinner.fail(chalk.red(`✗ Target environment "${target}" already exists`));
        return;
      }
      
      const id = uuidv4();
      exec(
        'INSERT INTO environments (id, name, description) VALUES (?, ?, ?)',
        [id, target, `Cloned from ${source}`]
      );
      
      // Clone variables if requested
      let clonedVars = 0;
      if (options.variables) {
        const variables = all('SELECT * FROM variables WHERE environment_id = ?', [sourceEnv.id]);
        
        for (const v of variables) {
          const varId = uuidv4();
          exec(
            `INSERT INTO variables (id, environment_id, key, value, encrypted, is_secret, tags, description, rotation_enabled, rotation_period_days)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [varId, id, v.key, v.value, v.encrypted, v.is_secret, v.tags, v.description, v.rotation_enabled, v.rotation_period_days]
          );
          clonedVars++;
        }
      }
      
      logAudit({
        action: 'clone',
        entityType: 'environment',
        entityId: id,
        newValue: JSON.stringify({ source, target, clonedVars }),
        details: { source, target, clonedVars }
      });
      
      spinner.succeed(chalk.green(`✓ Environment "${source}" cloned to "${target}"!`));
      
      if (options.variables) {
        console.log(chalk.gray(`  Cloned ${clonedVars} variables`));
      }
      
    } catch (error) {
      spinner.fail(chalk.red('✗ Error: ') + error.message);
    }
  });

// Export environment
const exportCmd = new Command('export')
  .description('Export environment to file')
  .argument('<name>', 'Environment name')
  .argument('[file]', 'Output file path')
  .option('--include-secrets', 'Include encrypted secrets')
  .action(async (name, filePath, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    const spinner = ora('Exporting environment...').start();
    
    try {
      initDb();
      
      const env = get('SELECT * FROM environments WHERE name = ?', [name]);
      if (!env) {
        spinner.fail(chalk.red(`✗ Environment "${name}" not found`));
        return;
      }
      
      const variables = all('SELECT * FROM variables WHERE environment_id = ?', [env.id]);
      
      const exportData = {
        exportedAt: new Date().toISOString(),
        environment: {
          name: env.name,
          description: env.description
        },
        variables: variables.map(v => ({
          key: v.key,
          value: options.includeSecrets ? v.value : (v.is_secret ? '[SECRET]' : v.value),
          isSecret: !!v.is_secret,
          tags: v.tags,
          description: v.description
        }))
      };
      
      const outputPath = filePath || `${name}-env.json`;
      const fs = await import('fs');
      fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2));
      
      logAudit({
        action: 'export',
        entityType: 'environment',
        entityId: env.id,
        details: { name, filePath: outputPath, variablesCount: variables.length }
      });
      
      spinner.succeed(chalk.green(`✓ Environment exported to "${outputPath}"`));
      console.log(chalk.gray(`  Exported ${variables.length} variables`));
      
    } catch (error) {
      spinner.fail(chalk.red('✗ Error: ') + error.message);
    }
  });

// Import environment
const importCmd = new Command('import')
  .description('Import environment from file')
  .argument('<file>', 'Input file path')
  .argument('[name]', 'Environment name (optional, uses file name)')
  .option('--overwrite', 'Overwrite existing variables')
  .action(async (filePath, envName, options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    const spinner = ora('Importing environment...').start();
    
    try {
      const fs = await import('fs');
      
      if (!fs.existsSync(filePath)) {
        spinner.fail(chalk.red(`✗ File "${filePath}" not found`));
        return;
      }
      
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      
      initDb();
      
      const name = envName || data.environment?.name || 'imported';
      
      // Create or get environment
      let env = get('SELECT * FROM environments WHERE name = ?', [name]);
      let envId;
      
      if (env) {
        envId = env.id;
        spinner.info(chalk.yellow(`Using existing environment "${name}"`));
      } else {
        envId = uuidv4();
        exec('INSERT INTO environments (id, name, description) VALUES (?, ?, ?)', [
          envId, name, data.environment?.description || 'Imported environment'
        ]);
      }
      
      let imported = 0;
      let skipped = 0;
      
      if (data.variables) {
        for (const v of data.variables) {
          const existing = get('SELECT * FROM variables WHERE environment_id = ? AND key = ?', [envId, v.key]);
          
          if (existing && !options.overwrite) {
            skipped++;
            continue;
          }
          
          const varId = existing?.id || uuidv4();
          
          if (existing) {
            exec(
              `UPDATE variables SET value = ?, is_secret = ?, tags = ?, description = ?, updated_at = datetime('now') WHERE id = ?`,
              [v.value, v.isSecret ? 1 : 0, v.tags || '', v.description || '', varId]
            );
          } else {
            exec(
              `INSERT INTO variables (id, environment_id, key, value, is_secret, tags, description) VALUES (?, ?, ?, ?, ?, ?, ?)`,
              [varId, envId, v.key, v.value, v.isSecret ? 1 : 0, v.tags || '', v.description || '']
            );
          }
          imported++;
        }
      }
      
      logAudit({
        action: 'import',
        entityType: 'environment',
        entityId: envId,
        newValue: JSON.stringify({ name, imported, skipped }),
        details: { name, imported, skipped, filePath }
      });
      
      spinner.succeed(chalk.green(`✓ Environment imported successfully!`));
      console.log(chalk.gray(`  Imported ${imported} variables, skipped ${skipped}`));
      
    } catch (error) {
      spinner.fail(chalk.red('✗ Error: ') + error.message);
    }
  });

export const envCommands = {
  list,
  create,
  delete: deleteCmd,
  clone,
  export: exportCmd,
  import: importCmd
};
