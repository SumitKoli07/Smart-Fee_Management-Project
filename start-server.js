/**
 * Script to start the server with better error handling
 */
const { spawn } = require('child_process');
const path = require('path');

console.log('Starting server...');

// Path to server.js
const serverPath = path.join(__dirname, 'server.js');
console.log(`Server path: ${serverPath}`);

// Start the server process
const serverProcess = spawn('node', [serverPath], {
  stdio: 'inherit', // Inherit stdio so we see output in console
  shell: true
});

// Handle events
serverProcess.on('error', (error) => {
  console.error('Failed to start server process:', error);
});

serverProcess.on('exit', (code, signal) => {
  if (code) {
    console.log(`Server process exited with code ${code}`);
  } else if (signal) {
    console.log(`Server process was killed with signal ${signal}`);
  } else {
    console.log('Server process exited');
  }
});

// Handle process exit
process.on('SIGINT', () => {
  console.log('Stopping server...');
  serverProcess.kill();
  process.exit();
});

console.log('Server startup script running. Press Ctrl+C to stop.'); 