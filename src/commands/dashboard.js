import chalk from 'chalk';
import { getConfig } from './init.js';
import { initDb, all, get } from '../utils/database.js';
import { getAuditStats } from '../utils/audit.js';

/**
 * Show dashboard overview
 */
export async function showDashboard() {
  const config = getConfig();
  if (!config) {
    console.log(chalk.red('✗ Not initialized. Run: ') + chalk.cyan('envguard init'));
    process.exit(1);
  }
  
  try {
    await initDb();
    
    // Get statistics
    const environments = all('SELECT COUNT(*) as count FROM environments');
    const variables = all('SELECT COUNT(*) as count FROM variables');
    const secrets = all('SELECT COUNT(*) as count FROM variables WHERE is_secret = 1');
    const secretsNeedingRotation = all(`
      SELECT COUNT(*) as count FROM variables 
      WHERE is_secret = 1 AND rotation_enabled = 1 
      AND (next_rotation IS NULL OR next_rotation <= datetime('now'))
    `);
    
    // Get recent activity
    const recentActivity = all(`
      SELECT action, COUNT(*) as count, MAX(timestamp) as last_occurred
      FROM audit_logs 
      WHERE timestamp >= datetime('now', '-7 days')
      GROUP BY action
      ORDER BY count DESC
    `);
    
    // Get environment details
    const envList = all(`
      SELECT e.name, COUNT(v.id) as var_count, 
             SUM(CASE WHEN v.is_secret = 1 THEN 1 ELSE 0 END) as secret_count
      FROM environments e
      LEFT JOIN variables v ON e.id = v.environment_id
      GROUP BY e.id
      ORDER BY e.name
    `);
    
    console.log(chalk.cyan.bold('\n📊 EnvGuard Dashboard\n'));
    
    // Overview stats
    console.log(chalk.white.bold('  Overview'));
    console.log(chalk.gray('  ──────────────'));
    console.log(chalk.gray('  Project: ') + chalk.white(config.projectName));
    console.log(chalk.gray('  Environments: ') + chalk.cyan(environments[0]?.count || 0));
    console.log(chalk.gray('  Variables: ') + chalk.cyan(variables[0]?.count || 0));
    console.log(chalk.gray('  Secrets: ') + chalk.yellow(secrets[0]?.count || 0));
    
    if (secretsNeedingRotation[0]?.count > 0) {
      console.log(chalk.gray('  ⚠ Rotation Due: ') + chalk.red(secretsNeedingRotation[0]?.count || 0));
    }
    console.log();
    
    // Environments breakdown
    console.log(chalk.white.bold('  Environments'));
    console.log(chalk.gray('  ──────────────'));
    
    if (envList.length === 0) {
      console.log(chalk.gray('  No environments created yet.'));
    } else {
      envList.forEach(env => {
        console.log(chalk.white(`  ${env.name}`) + chalk.gray(` - ${env.var_count} vars, ${env.secret_count} secrets`));
      });
    }
    console.log();
    
    // Recent activity
    if (recentActivity.length > 0) {
      console.log(chalk.white.bold('  Recent Activity (7 days)'));
      console.log(chalk.gray('  ───────────────────────'));
      recentActivity.forEach(activity => {
        const actionColor = getActionColor(activity.action);
        console.log(`  ${actionColor(activity.action)}: ${chalk.gray(activity.count)}`);
      });
      console.log();
    }
    
    // Quick actions
    console.log(chalk.white.bold('  Quick Actions'));
    console.log(chalk.gray('  ─────────────'));
    console.log(chalk.gray('  → ') + chalk.cyan('envguard env create <name>') + chalk.gray('  Create environment'));
    console.log(chalk.gray('  → ') + chalk.cyan('envguard var set <key> <value>') + chalk.gray('  Add variable'));
    console.log(chalk.gray('  → ') + chalk.cyan('envguard audit view') + chalk.gray('  View audit logs'));
    console.log(chalk.gray('  → ') + chalk.cyan('envguard rotate status') + chalk.gray('  Check rotation'));
    console.log();
    
  } catch (error) {
    console.error(chalk.red('✗ Error:'), error.message);
  }
}

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
