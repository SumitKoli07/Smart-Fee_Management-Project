# Smart Fee Management System

A web application for client registration with MongoDB integration.

## Setup Instructions

1. **Make sure you have MongoDB installed and running on your system**
   - MongoDB should be running on the default port: `mongodb://127.0.0.1:27017`
   - The system will automatically create a database named `mp` with a collection called `clientRegister`

2. **Install dependencies**
   ```
   npm install
   ```

3. **Start the server**
   ```
   npm start
   ```
   
   Or for development with auto-restart:
   ```
   npm run dev
   ```

4. **Access the application**
   - Open your browser and go to: `http://localhost:3000/register`
   - This will display the client registration form

## Features

- Client registration with MongoDB storage
- Form validation on both client and server side
- Responsive design with dark mode support
- Real-time feedback with toast notifications
- State and city selection with dynamic dropdowns

## Technical Details

- Frontend: HTML, CSS, JavaScript with Tailwind CSS
- Backend: Node.js with Express.js
- Database: MongoDB with Mongoose ORM
- The application uses the following MongoDB connection string:
  ```
  mongodb://127.0.0.1:27017/mp
  ```

## Database Schema

The client data is stored in the `clientRegister` collection with the following fields:

- `fullname`: String (required)
- `email`: String (required, unique)
- `dob`: Date (required)
- `gender`: String (required)
- `mobile`: String (required)
- `altMobile`: String (optional)
- `address`: String (required)
- `state`: String (required)
- `city`: String (required)
- `pincode`: String (required)
- `password`: String (required)
- `registrationDate`: Date (default: current date/time)

## Security Notes

For a production environment, you should:
1. Hash passwords before storing them (using bcrypt)
2. Use environment variables for sensitive information
3. Implement HTTPS
4. Add CSRF protection 