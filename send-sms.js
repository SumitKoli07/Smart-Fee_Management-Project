require('dotenv').config();
const readline = require('readline');
const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioNumber = process.env.TWILIO_PHONE_NUMBER;

const client = twilio(accountSid, authToken);

// Setup input interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Ask user for the mobile number (without +91)
rl.question('Enter 10-digit mobile number (without +91): ', (inputNumber) => {
  const phoneNumber = `+91${inputNumber}`;

  // Send SMS
  client.messages
    .create({
      body: 'Hello from Twilio using .env!',
      from: twilioNumber,
      to: phoneNumber
    })
    .then(message => {
      console.log('✅ Message sent! SID:', message.sid);
      rl.close();
    })
    .catch(error => {
      console.error('❌ Failed to send message:', error);
      rl.close();
    });
});
