import chalk from 'chalk';
import { Command } from 'commander';
import inquirer from 'inquirer';
import ora from 'ora';
import { getConfig } from './init.js';
import { initDb, all, get } from '../utils/database.js';
import { getAuditLogs, getAuditStats, cleanupAuditLogs, exportAuditLogs as exportLogs } from '../utils/audit.js';

// View audit logs
const view = new Command('view')
  .description('View audit logs')
  .option('-a, --action <type>', 'Filter by action type')
  .option('-e, --entity <id>', 'Filter by entity ID')
  .option('-t, --entity-type <type>', 'Filter by entity type')
  .option('-l, --limit <number>', 'Number of logs to show', '50')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      const filters = {
        action: options.action,
        entityId: options.entity,
        entityType: options.entityType,
        limit: parseInt(options.limit)
      };
      
      const logs = getAuditLogs(filters);
      
      if (logs.length === 0) {
        console.log(chalk.yellow('No audit logs found.'));
        return;
      }
      
      if (options.json) {
        console.log(JSON.stringify(logs, null, 2));
        return;
      }
      
      console.log(chalk.cyan.bold('\n📋 Audit Logs\n'));
      
      const table = logs.map(log => ({
        Timestamp: chalk.gray(new Date(log.timestamp).toLocaleString()),
        Action: getActionColor(log.action)(log.action),
        Entity: log.entity_type,
        User: chalk.gray(log.user_name || 'system'),
        Details: log.details ? chalk.gray(JSON.parse(log.details).action || '-') : '-'
      }));
      
      console.table(table);
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Export audit logs
const exportCmd = new Command('export')
  .description('Export audit logs to file')
  .option('-o, --output <path>', 'Output file path')
  .option('-a, --action <type>', 'Filter by action type')
  .option('--from <date>', 'Start date (ISO format)')
  .option('--to <date>', 'End date (ISO format)')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    const spinner = ora('Exporting audit logs...').start();
    
    try {
      await initDb();
      
      const filters = {
        action: options.action,
        startDate: options.from,
        endDate: options.to,
        limit: 100000
      };
      
      const filePath = options.output || `audit-logs-${Date.now()}.json`;
      
      const count = await exportLogs(filePath, filters);
      
      spinner.succeed(chalk.green(`✓ Exported ${count} audit logs to "${filePath}"`));
      
    } catch (error) {
      spinner.fail(chalk.red('✗ Error: ') + error.message);
    }
  });

// Cleanup audit logs
const cleanup = new Command('cleanup')
  .description('Clean up old audit logs')
  .option('-d, --days <number>', 'Days to keep logs', '90')
  .option('-f, --force', 'Skip confirmation')
  .action(async (options) => {
    const config = getConfig();
    if (!config) {
      console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
      process.exit(1);
    }
    
    try {
      await initDb();
      
      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Delete all audit logs older than ${options.days} days?`,
            default: false
          }
        ]);
        
        if (!confirm) {
          console.log(chalk.yellow('Cleanup cancelled.'));
          return;
        }
      }
      
      const spinner = ora('Cleaning up audit logs...').start();
      
      const deleted = cleanupAuditLogs(parseInt(options.days));
      
      spinner.succeed(chalk.green(`✓ Deleted ${deleted} old audit logs`));
      
    } catch (error) {
      console.error(chalk.red('✗ Error:'), error.message);
    }
  });

// Helper function to color action types
function getActionColor(action) {
  switch (action) {
    case 'create':
      return chalk.green;
    case 'update':
      return chalk.yellow;
    case 'delete':
      return chalk.red;
    case 'rotate':
      return chalk.blue;
    case 'export':
    case 'import':
      return chalk.cyan;
    default:
      return chalk.gray;
  }
}

export const auditCommands = {
  view,
  export: exportCmd,
  cleanup
};
