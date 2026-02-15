#!/usr/bin/env node

import chalk from 'chalk';
import { Command } from 'commander';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { initProject, getConfig } from './commands/init.js';
import { envCommands } from './commands/env.js';
import { varCommands } from './commands/variable.js';
import { auditCommands } from './commands/audit.js';
import { rotateCommands } from './commands/rotate.js';
import { configCommands } from './commands/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const program = new Command();

program
  .name('envguard')
  .description('Secure, team-based env variable management with audit trails and rotation')
  .version('1.0.0');

// Check if initialized
function checkInitialized() {
  const config = getConfig();
  if (!config) {
    console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
    process.exit(1);
  }
  return config;
}

// Add pre-hook to check initialization for certain commands
program.on('command:*', () => {
  const config = getConfig();
  if (!config && process.argv.length > 2 && !['init', '--help', '--version'].includes(process.argv[2])) {
    console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
    process.exit(1);
  }
});

// Initialize command
program
  .command('init')
  .description('Initialize a new envguard project')
  .option('-n, --name <name>', 'Project name')
  .option('-m, --master-password <password>', 'Master password for encryption')
  .action(async (options) => {
    await initProject(options);
  });

// Environment commands
program
  .command('env')
  .description('Manage environments')
  .addCommand(envCommands.list)
  .addCommand(envCommands.create)
  .addCommand(envCommands.delete)
  .addCommand(envCommands.clone)
  .addCommand(envCommands.export)
  .addCommand(envCommands.import);

// Variable commands
program
  .command('var')
  .description('Manage environment variables')
  .addCommand(varCommands.list)
  .addCommand(varCommands.set)
  .addCommand(varCommands.get)
  .addCommand(varCommands.delete)
  .addCommand(varCommands.edit)
  .addCommand(varCommands.bulk);

// Audit commands
program
  .command('audit')
  .description('View audit logs')
  .addCommand(auditCommands.view)
  .addCommand(auditCommands.export)
  .addCommand(auditCommands.cleanup);

// Rotation commands
program
  .command('rotate')
  .description('Manage secret rotation')
  .addCommand(rotateCommands.run)
  .addCommand(rotateCommands.schedule)
  .addCommand(rotateCommands.history)
  .addCommand(rotateCommands.status);

// Config commands
program
  .command('config')
  .description('Manage configuration')
  .addCommand(configCommands.view)
  .addCommand(configCommands.set)
  .addCommand(configCommands.users);

// Dashboard command
program
  .command('dashboard')
  .description('Show dashboard overview')
  .action(async () => {
    checkInitialized();
    const { showDashboard } = await import('./commands/dashboard.js');
    await showDashboard();
  });

// Parse arguments
program.parse(process.argv);

// Show help if no arguments
if (process.argv.length === 2) {
  program.help();
}
