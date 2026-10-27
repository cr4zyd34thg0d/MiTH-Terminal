#!/usr/bin/env node
/**
 * MiTH Terminal Runner
 * Spawns the lightweight zero-config companion daemon.
 */

const { spawn } = require('child_process');
const path = require('path');

const serverScript = path.join(__dirname, '..', 'daemon', 'server.py');
const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

const forwardedArgs = process.argv.slice(2);
if (!forwardedArgs.includes('--port') && !process.env.PORT) {
  forwardedArgs.push('--port', '8790');
} else if (!forwardedArgs.includes('--port') && process.env.PORT) {
  forwardedArgs.push('--port', process.env.PORT);
}

const child = spawn(pythonCmd, [serverScript, ...forwardedArgs], {
  stdio: 'inherit'
});

child.on('error', (err) => {
  console.error('Failed to start python companion daemon:', err.message);
  console.error('Ensure Python 3.10+ is installed on your system.');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});
