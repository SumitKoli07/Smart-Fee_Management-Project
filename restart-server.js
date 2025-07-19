/**
 * Script to restart the server
 */
const { spawn, exec } = require('child_process');
const path = require('path');

console.log('Stopping existing Node.js processes...');

// Function to execute a command and return its output
function executeCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error executing command: ${error.message}`);
        return reject(error);
      }
      if (stderr) {
        console.error(`Command stderr: ${stderr}`);
      }
      resolve(stdout);
    });
  });
}

// Main function to restart the server
async function restartServer() {
  try {
    // Kill existing Node.js processes
    if (process.platform === 'win32') {
      // Windows
      await executeCommand('taskkill /F /IM node.exe');
    } else {
      // Linux/Mac
      await executeCommand('pkill -f node');
    }
    
    console.log('All Node.js processes stopped');
  } catch (error) {
    console.log('No existing Node.js processes to stop or unable to stop them');
  }
  
  console.log('Starting server...');
  
  // Path to server.js
  const serverPath = path.join(__dirname, 'server.js');
  console.log(`Server path: ${serverPath}`);
  
  // Start the server process
  const serverProcess = spawn('node', [serverPath], {
    stdio: 'inherit', // Inherit stdio so we see output in console
    shell: true,
    detached: true // Detach the process so it can run independently
  });
  
  // Handle events
  serverProcess.on('error', (error) => {
    console.error('Failed to start server process:', error);
  });
  
  // Unref the process to allow this script to exit independently of the server
  serverProcess.unref();
  
  console.log('Server started. You can close this window.');
}

// Run the restart function
restartServer()
  .then(() => {
    console.log('Server restart script completed.');
    // Exit this process after a short delay to give the server time to start
    setTimeout(() => process.exit(0), 2000);
  })
  .catch(error => {
    console.error('Error in restart script:', error);
    process.exit(1);
  }); 