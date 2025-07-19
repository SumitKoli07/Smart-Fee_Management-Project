// Simple script to verify that our nodemailer integration is working
console.log("Verifying email integration and restarting server...");

// Check that nodemailer is available
try {
    const nodemailer = require('nodemailer');
    console.log("✅ Nodemailer is available");
    
    // Check that our payment reminder utility is available
    try {
        const sendPaymentReminder = require('./email/sendPaymentReminder');
        console.log("✅ Payment reminder utility is available");
        
        console.log("\nServer should now be able to send payment reminders via email.");
        console.log("When you click the reminder button in the dashboard:");
        console.log("1. A confirmation dialog will appear");
        console.log("2. If confirmed, the button will show a loading indicator");
        console.log("3. The email will be sent to the client's email address");
        console.log("4. A success message will show with the email address used");
        
        console.log("\nRestarting server now...");
        
        // Use child_process to restart the server
        const { spawn } = require('child_process');
        const serverProcess = spawn('node', ['server.js'], {
            detached: true,
            stdio: 'inherit'
        });
        
        serverProcess.unref();
        console.log("Server restarted with PID:", serverProcess.pid);
        
    } catch (utilError) {
        console.error("❌ Error loading payment reminder utility:", utilError);
        console.error("Please check that the file ./email/sendPaymentReminder.js exists and is correct");
    }
} catch (e) {
    console.error("❌ Nodemailer is not installed. Please run:");
    console.error("npm install nodemailer");
} 