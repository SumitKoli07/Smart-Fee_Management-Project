const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const clientRequests = require('./routes/clientRequests');
const requests = require('./routes/requests');

// Import models
const Client = require('./models/clientRegister');
const Owner = require('./models/ownerRegister');
const Request = require('./models/Request');
const Admin = require('./models/Admin');

// Setup storage for file uploads
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        // Create uploads directory if it doesn't exist
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: function(req, file, cb) {
        // Generate unique filename with original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({ storage: storage });

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
    origin: '*', // Allow all origins
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allow all methods
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Owner-ID'], // Allow these headers
    credentials: true // Allow cookies to be sent with requests
}));

// Log all API requests for debugging

// Enhanced request logging middleware for better debugging
app.use((req, res, next) => {
    // Generate a unique ID for this request
    const requestId = Date.now().toString(36) + Math.random().toString(36).substring(2);
    
    // Log basic request info
    console.log(`[REQUEST ${requestId}] ${req.method} ${req.originalUrl}`);
    
    // Log request headers
    console.log(`[REQUEST ${requestId}] Headers: ${JSON.stringify(req.headers)}`);
    
    // Log request body if present
    if (req.body && Object.keys(req.body).length > 0) {
        console.log(`[REQUEST ${requestId}] Body: ${JSON.stringify(req.body)}`);
    }
    
    // Create a copy of the original res.json method
    const originalJson = res.json;
    
    // Override res.json method to log response
    res.json = function(data) {
        console.log(`[RESPONSE ${requestId}] ${JSON.stringify(data)}`);
        
        // Call the original method
        return originalJson.call(this, data);
    };
    
    // Log any errors that occur
    const originalNext = next;
    const errorHandlingNext = (err) => {
        if (err) {
            console.error(`[ERROR ${requestId}] ${err.message}`);
            console.error(err.stack);
        }
        return originalNext(err);
    };
    
    // Continue with the request
    errorHandlingNext();
});

// Log all API requests for debugging

// Enhanced request logging middleware for better debugging
app.use((req, res, next) => {
    // Generate a unique ID for this request
    const requestId = Date.now().toString(36) + Math.random().toString(36).substring(2);
    
    // Log basic request info
    console.log(`[REQUEST ${requestId}] ${req.method} ${req.originalUrl}`);
    
    // Log request headers
    console.log(`[REQUEST ${requestId}] Headers: ${JSON.stringify(req.headers)}`);
    
    // Log request body if present
    if (req.body && Object.keys(req.body).length > 0) {
        console.log(`[REQUEST ${requestId}] Body: ${JSON.stringify(req.body)}`);
    }
    
    // Create a copy of the original res.json method
    const originalJson = res.json;
    
    // Override res.json method to log response
    res.json = function(data) {
        console.log(`[RESPONSE ${requestId}] ${JSON.stringify(data)}`);
        
        // Call the original method
        return originalJson.call(this, data);
    };
    
    // Log any errors that occur
    const originalNext = next;
    const errorHandlingNext = (err) => {
        if (err) {
            console.error(`[ERROR ${requestId}] ${err.message}`);
            console.error(err.stack);
        }
        return originalNext(err);
    };
    
    // Continue with the request
    errorHandlingNext();
});

// Log all API requests for debugging
app.use('/api', (req, res, next) => {
    console.log(`API Request: ${req.method} ${req.originalUrl}`);
    console.log('Headers:', req.headers);
    next();
});

// Simple ping endpoint to test API connectivity
app.get('/api/ping', (req, res) => {
    console.log('Ping endpoint hit');
    res.status(200).json({ success: true, message: 'API is working' });
});

// Direct test endpoint to check for approved requests
app.get('/api/test-approved-requests', async (req, res) => {
    try {
        console.log('Test approved requests endpoint hit');
        const allRequests = await Request.find({ status: 'approved' });
        console.log(`Found ${allRequests.length} total approved requests`);
        
        let details = [];
        if (allRequests.length > 0) {
            details = allRequests.map(req => ({
                id: req._id,
                ownerId: req.ownerId,
                clientId: req.clientId,
                status: req.status
            }));
        }
        
        res.status(200).json({ 
            success: true, 
            message: `Found ${allRequests.length} approved requests`,
            count: allRequests.length,
            details
        });
    } catch (error) {
        console.error('Error in test endpoint:', error);
        res.status(500).json({ success: false, message: 'Error testing requests' });
    }
});

// Static file serving - ensure all directories are properly accessible
app.use(express.static(path.join(__dirname)));
app.use('/clientUI', express.static(path.join(__dirname, 'clientUI')));
app.use('/ownerUI', express.static(path.join(__dirname, 'ownerUI')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/mp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB successfully'))
.catch(err => {
    console.error('Failed to connect to MongoDB:', err);
    
    // Log more detailed error information
    if (err.name === 'MongoNetworkError') {
        console.error('MongoDB server may not be running. Please start MongoDB service.');
    } else if (err.name === 'MongoServerSelectionError') {
        console.error('Unable to select MongoDB server. Check if the connection string is correct.');
    }
});

// Client Registration Route
app.post('/api/register-client', async (req, res) => {
    try {
        const { 
            fullname, email, dob, gender, mobile, altMobile, 
            address, state, city, pincode, password, ownerId
        } = req.body;

        // Check if client already exists
        const existingClient = await Client.findOne({ email });
        if (existingClient) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new client with hashed password
        const newClient = new Client({
            fullname, 
            email, 
            dob, 
            gender, 
            mobile, 
            altMobile,
            address, 
            state, 
            city, 
            pincode, 
            password: hashedPassword,
            owner: ownerId,  // Link client to owner
            status: 'pending'  // Default status is pending until approved
        });

        // Save client to database
        await newClient.save();
        
        res.status(201).json({ success: true, message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Registration failed', error: error.message });
    }
});

// Owner Registration Route - Updated to handle multiple payment settings
app.post('/api/register-owner', upload.fields([
    { name: 'businessDoc', maxCount: 1 }, 
    { name: 'taxDoc', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log('Owner registration request received:', req.body);
        
        const { 
            businessName, ownerName, businessEmail, businessPhone, businessAddress, 
            registrationNo, taxID, serviceName, serviceDescription, capacity, 
            businessType, otherBusinessType, password, serviceFee
        } = req.body;

        // Parse serviceFee as a number
        const parsedServiceFee = Number(serviceFee) || 0;
        console.log('Parsed service fee:', parsedServiceFee);
        
        if (parsedServiceFee <= 0) {
            return res.status(400).json({ success: false, message: 'Valid service fee is required' });
        }

        // Handle payment settings - properly parse JSON string from form data
        let paymentSettings = [];
        
        try {
            // Check if paymentSettings is provided as JSON string
            if (req.body.paymentSettings) {
                console.log('Raw payment settings:', req.body.paymentSettings);
                const parsedSettings = JSON.parse(req.body.paymentSettings);
                console.log('Parsed payment settings:', parsedSettings);
                
                if (Array.isArray(parsedSettings)) {
                    // Format the settings to ensure they're in the correct format (objects with name and amount)
                    paymentSettings = parsedSettings.map(setting => {
                        if (typeof setting === 'object' && setting.name) {
                            return {
                                name: setting.name,
                                amount: Number(setting.amount) || 0
                            };
                        } else if (typeof setting === 'string') {
                            return {
                                name: setting,
                                amount: 0
                            };
                        }
                        return null;
                    }).filter(setting => setting !== null);
                }
            } 
            // Fallback to paymentSetting (singular) if paymentSettings is not available
            else if (req.body.paymentSetting) {
                const settingValue = Array.isArray(req.body.paymentSetting)
                    ? req.body.paymentSetting
                    : [req.body.paymentSetting];
                
                // Convert to new format
                paymentSettings = settingValue.map(s => ({
                    name: s,
                    amount: 0
                }));
            }
            
            if (!Array.isArray(paymentSettings) || paymentSettings.length === 0) {
                return res.status(400).json({ success: false, message: 'At least one payment setting is required' });
            }
            
            console.log('Payment settings processed:', paymentSettings);
        } catch (e) {
            console.error('Error parsing payment settings:', e);
            return res.status(400).json({ success: false, message: 'Invalid payment settings format' });
        }

        // Check if owner/business already exists
        const existingOwner = await Owner.findOne({ businessEmail });
        if (existingOwner) {
            return res.status(400).json({ success: false, message: 'Business email already registered' });
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Get file paths
        const businessDocPath = req.files.businessDoc ? req.files.businessDoc[0].path : null;
        const taxDocPath = req.files.taxDoc ? req.files.taxDoc[0].path : null;

        // Create new owner with payment settings as array
        const newOwner = new Owner({
            businessName,
            ownerName,
            businessEmail,
            businessPhone,
            businessAddress,
            registrationNo,
            taxID,
            serviceName,
            serviceDescription,
            capacity,
            businessType,
            otherBusinessType: businessType === 'other' ? otherBusinessType : null,
            paymentSettings, // Store as array
            paymentSetting: paymentSettings.length > 0 ? paymentSettings.map(setting => setting.name).join(',') : null, // Store all names as comma-separated string
            password: hashedPassword,
            businessDoc: businessDocPath,
            taxDoc: taxDocPath,
            serviceFee: parsedServiceFee // Use the parsed value
        });

        // Save owner to database
        const savedOwner = await newOwner.save();
        console.log('Owner saved successfully with ID:', savedOwner._id);
        console.log('Owner service fee:', savedOwner.serviceFee);
        
        res.status(201).json({ success: true, message: 'Business registration successful' });
    } catch (error) {
        console.error('Owner registration error:', error);
        // Log more details about the error for debugging
        if (error.name === 'ValidationError') {
            console.log('Validation error details:', error.errors);
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed', 
                errors: Object.keys(error.errors).map(field => ({
                    field,
                    message: error.errors[field].message
                }))
            });
        }
        res.status(500).json({ success: false, message: 'Registration failed', error: error.message });
    }
});

// Owner Login
app.post('/api/owner/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find owner by email
        const owner = await Owner.findOne({ businessEmail: email });
        if (!owner) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check if password matches
        const isMatch = await bcrypt.compare(password, owner.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign(
            { id: owner._id, email: owner.businessEmail },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        // Format payment settings to ensure correct format
        let formattedSettings = [];
        if (owner.paymentSettings && owner.paymentSettings.length > 0) {
            formattedSettings = owner.paymentSettings.map(setting => {
                if (typeof setting === 'object' && setting.name) {
                    return setting;
                }
                return {
                    name: setting,
                    amount: 0
                };
            });
        }

        // Return owner data (excluding password) and token
        const ownerData = {
            _id: owner._id,
            businessName: owner.businessName,
            ownerName: owner.ownerName,
            businessEmail: owner.businessEmail,
            businessPhone: owner.businessPhone,
            serviceName: owner.serviceName,
            businessType: owner.businessType,
            paymentSettings: formattedSettings // Use formatted payment settings
        };

        res.status(200).json({
            message: 'Login successful',
            owner: ownerData,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Client Login
app.post('/api/login-client', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find client by email
        const client = await Client.findOne({ email });
        if (!client) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check if password matches
        const isMatch = await bcrypt.compare(password, client.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign(
            { id: client._id, email: client.email },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        // Return client data (excluding password) and token
        const clientData = {
            _id: client._id,
            fullName: client.fullname,  
            email: client.email,
            mobile: client.mobile,
            city: client.city,
            state: client.state
        };

        res.status(200).json({
            message: 'Login successful',
            client: clientData,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Serve pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'clientRegister.html'));
});

app.get('/owner-register', (req, res) => {
    res.sendFile(path.join(__dirname, 'ownerRegister.html'));
});

// Use routes
app.use('/api/client-requests', clientRequests);
app.use('/api/requests', requests);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    try {
        const bearerHeader = req.headers['authorization'];
        
        if (!bearerHeader) {
            return res.status(401).json({ message: 'No authentication token provided' });
        }
        
        const token = bearerHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// Owner token verification endpoint
app.get('/api/owner/verify', verifyToken, async (req, res) => {
    try {
        // Check if this owner exists in database
        const owner = await Owner.findOne({ _id: req.user.id });
        
        if (!owner) {
            return res.status(404).json({ message: 'Owner not found' });
        }
        
        // Format payment settings to ensure correct structure
        let formattedSettings = [];
        if (owner.paymentSettings && owner.paymentSettings.length > 0) {
            formattedSettings = owner.paymentSettings.map(setting => {
                if (typeof setting === 'object' && setting.name) {
                    return setting;
                }
                return {
                    name: setting,
                    amount: 0
                };
            });
        }
        
        // Return minimal owner data on successful verification
        res.status(200).json({ 
            verified: true,
            owner: {
                id: owner._id,
                businessName: owner.businessName,
                businessEmail: owner.businessEmail,
                paymentSettings: formattedSettings // Use formatted payment settings
            }
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ message: 'Server error during verification' });
    }
});

// API endpoint to get all approved client requests
app.get('/api/clients', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        
        console.log('Fetching approved requests for owner:', ownerId);
        
        // Fetch approved requests from the Request collection
        const approvedRequests = await Request.find({ 
            ownerId: ownerId,
            status: 'approved' 
        }).populate('clientId', 'fullname email mobile');
        
        console.log(`Found ${approvedRequests.length} approved requests for owner ${ownerId}`);
        
        // Transform data to include only necessary fields
        const clientData = approvedRequests.map(request => {
            // Get client info from populated clientId or fallback to clientDetails
            const clientInfo = request.clientId || request.clientDetails || {};
            
            // Get client email - prioritize the dedicated clientEmail field
            const email = request.clientEmail || clientInfo.email || '';
            
            // Determine the next due date - use existing field if available, otherwise calculate
            let nextDue = null;
            if (request.nextDueDate) {
                // Use the stored nextDueDate field if it exists
                nextDue = request.nextDueDate;
                console.log(`Using stored next due date for request ${request._id}: ${nextDue}`);
            } else if (request.approvedDate) {
                // If no explicit nextDueDate but we have approvedDate, they should be the same
                nextDue = request.approvedDate;
                console.log(`Using approval date as next due date for request ${request._id}: ${nextDue}`);
            } else if (request.lastPaymentDate) {
                // Calculate from last payment date
                nextDue = calculateNextDueDate(request.lastPaymentDate, request.planType);
                console.log(`Calculated next due date from last payment: ${nextDue}`);
            } else {
                // There is no payment or approval info, so no due date
                console.log(`No payment history for request ${request._id}, no due date available`);
            }
            
            return {
                id: request._id,
                clientId: request.clientId?._id || request.clientId,
                fullname: clientInfo.fullname || 'Unknown',
                email: email,
                mobile: clientInfo.mobile || 'N/A',
                planType: request.planType || 'N/A',
                planAmount: request.planAmount || 0,
                approvedDate: request.approvedDate,
                nextDueDate: nextDue,
                lastPaymentDate: request.lastPaymentDate,
                paymentStatus: request.paymentStatus || 'unpaid',
                // Include additional details for debugging
                status: request.status,
                address: clientInfo.address || '',
                city: clientInfo.city || '',
                state: clientInfo.state || ''
            };
        });
        
        res.status(200).json(clientData);
    } catch (error) {
        console.error('Error fetching approved requests:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching approved requests',
            error: error.message 
        });
    }
});

// Helper function to calculate next due date based on plan type
function calculateNextDueDate(approvedDate, planType) {
    if (!approvedDate) {
        console.log('Error: Missing date parameter in calculateNextDueDate');
        return null;
    }
    
    if (!planType) {
        console.log('Error: Missing planType parameter in calculateNextDueDate');
        return null;
    }
    
    try {
        const date = new Date(approvedDate);
        if (isNaN(date.getTime())) {
            console.log(`Error: Invalid date ${approvedDate} in calculateNextDueDate`);
            return null;
        }
        
        console.log(`Calculating next due date - Starting from: ${date.toISOString()}, Plan type: ${planType}`);
        
        const normalizedPlanType = planType.toLowerCase().trim();
        const originalDay = date.getDate(); // Store the original day
        
        switch (normalizedPlanType) {
            case 'monthly':
                date.setMonth(date.getMonth() + 1);
                break;
            case 'quarterly':
                date.setMonth(date.getMonth() + 3);
                break;
            case 'half-yearly':
                date.setMonth(date.getMonth() + 6);
                break;
            case 'yearly':
                date.setFullYear(date.getFullYear() + 1);
                break;
            default:
                console.log(`Unknown plan type: ${planType}`);
                return null;
        }
        
        // Check if the day of month changed due to month having fewer days
        if (date.getDate() !== originalDay) {
            // Set to the last day of the previous month to maintain the same day
            date.setDate(0); // This sets to the last day of the previous month
            // Then set to the original day or last day of the month if original day exceeds month length
            const lastDayOfMonth = new Date(date.getFullYear(), date.getMonth() + 1, 0).getDate();
            date.setDate(Math.min(originalDay, lastDayOfMonth));
        }
        
        console.log(`Calculated next due date: ${date.toISOString()}`);
        return date;
    } catch (error) {
        console.error(`Error calculating next due date: ${error.message}`);
        return null;
    }
}

// API endpoint to send reminder to client
app.post('/api/clients/remind/:clientId', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const client = await Client.findById(clientId);
        
        if (!client) {
            return res.status(404).json({ success: false, message: 'Client not found' });
        }
        
        // In a real implementation, this would send an email or SMS
        console.log(`Reminder sent to client: ${client.fullname} (${client.email})`);
        
        res.status(200).json({ 
            success: true, 
            message: 'Reminder sent successfully' 
        });
    } catch (error) {
        console.error('Error sending reminder:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to send reminder',
            error: error.message
        });
    }
});

// API endpoint to mark client payment
app.post('/api/clients/payment/:clientId', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const { status, date, planType } = req.body;
        
        const client = await Client.findById(clientId);
        
        if (!client) {
            return res.status(404).json({ success: false, message: 'Client not found' });
        }
        
        // Update client payment status
        client.paymentStatus = status || 'paid';
        
        // Set the lastPaymentDate to the current nextDueDate if it exists
        if (client.nextDueDate) {
            client.lastPaymentDate = new Date(client.nextDueDate);
            console.log(`Set client lastPaymentDate to current nextDueDate: ${client.lastPaymentDate}`);
        } else {
            client.lastPaymentDate = date ? new Date(date) : new Date();
            console.log(`No existing nextDueDate for client. Set lastPaymentDate to: ${client.lastPaymentDate}`);
        }
        
        // Get plan type from request body or use default
        const clientPlanType = planType || client.planType || 'monthly';
        
        // Calculate next due date based on payment plan and lastPaymentDate
        const nextDueDate = calculateNextDueDate(client.lastPaymentDate, clientPlanType);
        if (nextDueDate) {
            client.nextDueDate = nextDueDate;
            console.log(`Client next due date set to: ${nextDueDate} based on plan type: ${clientPlanType}`);
        } else {
            // Fallback to simple monthly calculation if the helper function fails
            const fallbackNextDueDate = new Date(client.lastPaymentDate);
            fallbackNextDueDate.setMonth(fallbackNextDueDate.getMonth() + 1);
            client.nextDueDate = fallbackNextDueDate;
            console.log(`Used fallback calculation for client next due date: ${client.nextDueDate}`);
        }
        
        await client.save();
        
        res.status(200).json({ 
            success: true, 
            message: 'Payment recorded successfully',
            client: {
                id: client._id,
                name: client.fullname,
                paymentStatus: client.paymentStatus,
                lastPaymentDate: client.lastPaymentDate,
                nextDueDate: client.nextDueDate,
                planType: clientPlanType
            }
        });
    } catch (error) {
        console.error('Error recording payment:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to record payment',
            error: error.message
        });
    }
});

// API endpoint to mark payment for a request
app.post('/api/requests/:requestId/payment', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        const ownerId = req.user.id;
        const { status, date, lastPaymentDate, planType } = req.body;
        
        console.log(`Processing payment for request: ${requestId}`);
        console.log(`Request parameters: status=${status}, date=${date}, lastPaymentDate=${lastPaymentDate}, planType=${planType}`);
        
        // Find the request
        const request = await Request.findById(requestId);
        
        if (!request) {
            console.log(`Request not found: ${requestId}`);
            return res.status(404).json({ 
                success: false, 
                message: 'Request not found' 
            });
        }
        
        // Verify ownership
        if (request.ownerId.toString() !== ownerId) {
            console.log(`Ownership verification failed. Request owner: ${request.ownerId}, Current user: ${ownerId}`);
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to update payment for this request' 
            });
        }
        
        // Update payment status
        request.paymentStatus = status || 'paid';
        
        // Save current payment date
        const currentPaymentDate = new Date();
        
        // Set the lastPaymentDate based on the current payment
        if (lastPaymentDate) {
            // If client explicitly provides lastPaymentDate, use it
            request.lastPaymentDate = new Date(lastPaymentDate);
            console.log(`Using client-provided lastPaymentDate: ${request.lastPaymentDate}`);
        } else {
            // Use current payment date as last payment date
            request.lastPaymentDate = currentPaymentDate;
            console.log(`Set lastPaymentDate to current date: ${request.lastPaymentDate}`);
        }
        
        // Use plan type from request body if provided, otherwise use the stored plan type
        const usePlanType = planType || request.planType;
        console.log(`Using plan type: ${usePlanType} (from request body: ${planType}, from stored request: ${request.planType})`);
        
        // Calculate next due date based on the lastPaymentDate and planType
        const nextDueDate = calculateNextDueDate(request.lastPaymentDate, usePlanType);
        if (nextDueDate) {
            request.nextDueDate = nextDueDate;
            console.log(`Next due date set to: ${nextDueDate} based on plan type: ${usePlanType}`);
        } else {
            console.log(`Failed to calculate next due date. Using planType: ${usePlanType}`);
        }
        
        await request.save();
        console.log(`Request updated successfully. Payment status: ${request.paymentStatus}, Last payment date: ${request.lastPaymentDate}, Next due date: ${request.nextDueDate}`);
        
        res.status(200).json({ 
            success: true, 
            message: 'Payment recorded successfully',
            request: {
                id: request._id,
                clientId: request.clientId,
                paymentStatus: request.paymentStatus,
                lastPaymentDate: request.lastPaymentDate,
                nextDueDate: request.nextDueDate,
                planType: request.planType
            }
        });
    } catch (error) {
        console.error('Error recording payment:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to record payment',
            error: error.message
        });
    }
});

// API endpoint to remove client
app.delete('/api/clients/:clientId', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        
        const client = await Client.findById(clientId);
        
        if (!client) {
            return res.status(404).json({ success: false, message: 'Client not found' });
        }
        
        await Client.findByIdAndDelete(clientId);
        
        res.status(200).json({ 
            success: true, 
            message: 'Client removed successfully' 
        });
    } catch (error) {
        console.error('Error removing client:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to remove client',
            error: error.message
        });
    }
});

// Get all owner services from the database
app.get('/api/owner-services', async (req, res) => {
    try {
        console.log('Fetching owner services...');
        
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            console.error('MongoDB is not connected. Current state:', mongoose.connection.readyState);
            throw new Error('Database connection is not established');
        }
        
        const owners = await Owner.find({});
        
        console.log('Found owners:', owners.length);
        
        // Return all owner data with success flag
        res.status(200).json({ 
            success: true, 
            services: owners 
        });
    } catch (error) {
        console.error('Error fetching owner services:', error);
        
        // Send a more detailed error message
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch services', 
            error: error.message,
            readyState: mongoose.connection.readyState
        });
    }
});

// Endpoint to fetch owner payment settings
app.get('/api/owner/payment-settings', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        console.log('GET /api/owner/payment-settings - Fetching settings for owner ID:', ownerId);
        
        // Find the owner by id
        const owner = await Owner.findById(ownerId);
        
        if (!owner) {
            console.log('Owner not found with ID:', ownerId);
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        console.log('Owner found, raw data:', JSON.stringify({
            id: owner._id,
            paymentSetting: owner.paymentSetting,
            paymentSettings: owner.paymentSettings,
            serviceFee: owner.serviceFee,
            monthlyAmount: owner.monthlyAmount,
            quarterlyAmount: owner.quarterlyAmount,
            halfYearlyAmount: owner.halfYearlyAmount,
            yearlyAmount: owner.yearlyAmount
        }));
        
        // Extract payment settings from owner
        // Handle both old format (array of strings) and new format (array of objects)
        let formattedSettings = [];
        
        if (owner.paymentSettings && owner.paymentSettings.length > 0) {
            formattedSettings = owner.paymentSettings.map(setting => {
                // Check if already in the new format
                if (typeof setting === 'object' && setting.name) {
                    return setting;
                }
                // Convert string to object format
                return {
                    name: setting,
                    amount: 0 // Default amount
                };
            });
        }
        
        // Create the response with all payment-related fields
        const paymentSettings = {
            paymentSettings: formattedSettings,
            paymentSetting: owner.paymentSetting || '', // Include legacy paymentSetting field (now contains all settings as comma-separated string)
            serviceFee: owner.serviceFee || 0,
            // Include specific payment period amounts
            monthlyAmount: owner.monthlyAmount || 0,
            quarterlyAmount: owner.quarterlyAmount || 0,
            halfYearlyAmount: owner.halfYearlyAmount || 0,
            yearlyAmount: owner.yearlyAmount || 0,
            discountStrategy: owner.discountStrategy || 'default'
        };
        
        console.log('Sending payment settings to client:', JSON.stringify(paymentSettings));
        
        res.status(200).json({
            success: true,
            paymentSettings
        });
    } catch (error) {
        console.error('Error fetching payment settings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment settings',
            error: error.message
        });
    }
});

// Endpoint to update owner service fee and payment settings
app.post('/api/owner/payment-settings', verifyToken, async (req, res) => {
    try {
        console.log('Received payment settings update request');
        const ownerId = req.user.id;
        console.log('Owner ID from token:', ownerId);
        
        // Extract service fee and payment settings from request body
        const { paymentSettings, serviceFee, monthlyAmount, quarterlyAmount, halfYearlyAmount, yearlyAmount, discountStrategy } = req.body;
        console.log('Received data:', JSON.stringify({ 
            paymentSettings, 
            serviceFee,
            monthlyAmount,
            quarterlyAmount,
            halfYearlyAmount,
            yearlyAmount,
            discountStrategy
        }, null, 2));

        // Log each custom payment option if they exist
        if (paymentSettings && Array.isArray(paymentSettings)) {
            console.log(`Received ${paymentSettings.length} custom payment options:`);
            paymentSettings.forEach((option, index) => {
                console.log(`Option ${index + 1}: Name=${option.name}, Days=${option.days || 'N/A'}, Amount=${option.amount}`);
            });
        }
        
        // Parse and validate service fee
        const parsedServiceFee = Number(serviceFee);
        if (isNaN(parsedServiceFee) || parsedServiceFee <= 0) {
            console.log('Validation failed: Invalid service fee');
            return res.status(400).json({
                success: false,
                message: 'A valid service fee amount is required'
            });
        }
        
        console.log('Validated service fee:', parsedServiceFee);
        
        // First check if the owner exists
        const existingOwner = await Owner.findById(ownerId);
        if (!existingOwner) {
            console.log('Owner not found with ID:', ownerId);
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        console.log('Found existing owner. Current service fee:', existingOwner.serviceFee);
        
        // Extract the paymentSetting for backward compatibility
        // Store all payment setting names as a comma-separated string
        let paymentSetting = '';
        if (paymentSettings && paymentSettings.length > 0) {
            paymentSetting = paymentSettings.map(setting => {
                return typeof setting === 'object' ? setting.name : setting;
            }).join(',');
            console.log('Using all payment settings for legacy paymentSetting:', paymentSetting);
        }
        
        // Prepare the update object with all payment-related fields
        const updateData = {
            serviceFee: parsedServiceFee,
            paymentSettings: paymentSettings || [],
            paymentSetting: paymentSetting // Set the legacy field
        };
        
        // Add specific payment period amounts if provided
        if (monthlyAmount !== undefined) updateData.monthlyAmount = Number(monthlyAmount) || 0;
        if (quarterlyAmount !== undefined) updateData.quarterlyAmount = Number(quarterlyAmount) || 0;
        if (halfYearlyAmount !== undefined) updateData.halfYearlyAmount = Number(halfYearlyAmount) || 0;
        if (yearlyAmount !== undefined) updateData.yearlyAmount = Number(yearlyAmount) || 0;
        
        // Add discount strategy if provided
        if (discountStrategy !== undefined) updateData.discountStrategy = discountStrategy;
        
        console.log('Updating owner with data:', JSON.stringify(updateData));
        
        console.log('Updating owner with ID:', ownerId);
        // Find and update both serviceFee, paymentSettings, and paymentSetting fields
        const updatedOwner = await Owner.findByIdAndUpdate(
            ownerId,
            { $set: updateData },
            { new: true, runValidators: true }
        );
        
        if (!updatedOwner) {
            console.log('Owner not found with ID:', ownerId);
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        console.log('Update successful. Updated owner:', updatedOwner._id);
        console.log('Service fee saved:', updatedOwner.serviceFee);
        console.log('Payment settings saved:', updatedOwner.paymentSettings);
        console.log('Legacy payment setting saved:', updatedOwner.paymentSetting);
        console.log('Specific payment amounts saved:', {
            monthlyAmount: updatedOwner.monthlyAmount,
            quarterlyAmount: updatedOwner.quarterlyAmount,
            halfYearlyAmount: updatedOwner.halfYearlyAmount,
            yearlyAmount: updatedOwner.yearlyAmount
        });
        
        // Create response including all payment period fields
        const responseData = {
            success: true,
            message: 'Payment settings updated successfully',
            paymentSettings: {
                paymentSettings: updatedOwner.paymentSettings,
                paymentSetting: updatedOwner.paymentSetting,
                serviceFee: updatedOwner.serviceFee,
                monthlyAmount: updatedOwner.monthlyAmount,
                quarterlyAmount: updatedOwner.quarterlyAmount,
                halfYearlyAmount: updatedOwner.halfYearlyAmount,
                yearlyAmount: updatedOwner.yearlyAmount,
                discountStrategy: updatedOwner.discountStrategy || 'default'
            }
        };
        
        res.status(200).json(responseData);
    } catch (error) {
        console.error('Error updating payment settings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update payment settings',
            error: error.message
        });
    }
});

// Endpoint to calculate smart fees based on base service fee
app.post('/api/calculate-smart-fees', async (req, res) => {
    try {
        console.log('Calculate smart fees request received');
        const { baseFee, discountStrategy } = req.body;
        
        // Validate input
        const parsedBaseFee = Number(baseFee);
        if (isNaN(parsedBaseFee) || parsedBaseFee <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid base fee amount is required'
            });
        }
        
        // Calculate fees for different payment intervals
        // Default strategy provides increasing discounts for longer payment periods
        let monthlyAmount = parsedBaseFee;
        let quarterlyAmount, halfYearlyAmount, yearlyAmount;
        
        // Different discount strategies
        if (discountStrategy === 'aggressive') {
            // Aggressive discounts for longer payment periods
            quarterlyAmount = Math.round(monthlyAmount * 3 * 0.90); // 10% discount
            halfYearlyAmount = Math.round(monthlyAmount * 6 * 0.85); // 15% discount
            yearlyAmount = Math.round(monthlyAmount * 12 * 0.75); // 25% discount
        } else if (discountStrategy === 'conservative') {
            // More conservative discounts
            quarterlyAmount = Math.round(monthlyAmount * 3 * 0.97); // 3% discount
            halfYearlyAmount = Math.round(monthlyAmount * 6 * 0.95); // 5% discount
            yearlyAmount = Math.round(monthlyAmount * 12 * 0.92); // 8% discount
        } else {
            // Default balanced strategy
            quarterlyAmount = Math.round(monthlyAmount * 3 * 0.95); // 5% discount
            halfYearlyAmount = Math.round(monthlyAmount * 6 * 0.90); // 10% discount
            yearlyAmount = Math.round(monthlyAmount * 12 * 0.85); // 15% discount
        }
        
        // Return calculated fee structure
        res.status(200).json({
            success: true,
            fees: {
                monthly: monthlyAmount,
                quarterly: quarterlyAmount,
                halfYearly: halfYearlyAmount,
                yearly: yearlyAmount
            },
            discountStrategy: discountStrategy || 'default'
        });
    } catch (error) {
        console.error('Error calculating smart fees:', error);
        res.status(500).json({
            success: false,
            message: 'Error calculating fee structure',
            error: error.message
        });
    }
});

// Add new endpoint for handling enrollment requests
app.post('/api/requests/enroll', verifyToken, async (req, res) => {
    try {
        console.log('Enrollment request received:', req.body);
        console.log('User from token:', req.user);
        
        const { serviceId, ownerId, planType, planAmount, clientInfo } = req.body;
        const clientId = req.user.id; // Get client ID from token
        
        // Validate inputs
        if (!serviceId || !planType || !planAmount) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        
        // Get client details from client collection to ensure we have the most up-to-date data
        const client = await Client.findById(clientId);
        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Client not found'
            });
        }
        
        console.log('Client found:', {
            id: client._id,
            name: client.fullname,
            email: client.email
        });
        
        // Find the service/owner to get the owner ID
        const service = await Owner.findById(serviceId);
        
        if (!service) {
            return res.status(404).json({
                success: false,
                message: 'Service not found'
            });
        }

        console.log('Service found:', {
            id: service._id,
            businessName: service.businessName,
            owner: service.ownerName
        });

        // Create the request with the owner's ID and client details
        const newRequest = new Request({
            clientId,
            serviceId,
            ownerId: service._id, // Set the ownerId from the service
            planType,
            planAmount,
            status: 'pending',
            clientEmail: client.email, // Add a dedicated field for client email
            clientDetails: {
                fullname: client.fullname,
                email: client.email,
                mobile: client.mobile,
                address: client.address,
                city: client.city,
                state: client.state
            },
            serviceDetails: {
                businessName: service.businessName,
                serviceName: service.serviceName,
                ownerName: service.ownerName
            },
            notes: `Enrollment request for ${planType} plan at ₹${planAmount}`
        });

        const savedRequest = await newRequest.save();
        console.log('Request saved:', savedRequest);

        res.status(201).json({
            success: true,
            message: 'Enrollment request submitted successfully',
            request: savedRequest
        });
    } catch (error) {
        console.error('Error creating enrollment request:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit enrollment request',
            error: error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    const dbConnected = mongoose.connection.readyState === 1;
    
    res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        db: {
            connected: dbConnected,
            state: mongoose.connection.readyState
        }
    });
});

// Test route for owner model
app.get('/api/test-owner-model', async (req, res) => {
    try {
        // Create a simple test owner object
        const testOwner = {
            businessName: 'Test Business',
            ownerName: 'Test Owner',
            businessEmail: `test${Date.now()}@example.com`, // Ensure unique email
            businessPhone: '1234567890',
            businessAddress: 'Test Address',
            registrationNo: 'TEST123',
            taxID: 'TAX123',
            serviceName: 'Test Service',
            capacity: 10,
            businessType: 'gym',
            paymentSettings: ['monthly', 'yearly'],
            password: 'hashedpassword',
            serviceFee: 1000
        };
        
        // Validate the model without saving
        const owner = new Owner(testOwner);
        const validationError = owner.validateSync();
        
        if (validationError) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed', 
                errors: validationError.errors 
            });
        }
        
        // If validation passes, we're good
        res.status(200).json({ 
            success: true, 
            message: 'Owner model validation successful',
            schema: Object.keys(owner.schema.paths)
        });
    } catch (error) {
        console.error('Test owner model error:', error);
        res.status(500).json({ success: false, message: 'Test failed', error: error.message });
    }
});

// Debug endpoint to directly check payment settings
app.get('/api/debug/owner-payment-settings/:ownerId', async (req, res) => {
    try {
        const ownerId = req.params.ownerId;
        console.log('Debug endpoint - Fetching settings for owner ID:', ownerId);
        
        // Find the owner by id
        const owner = await Owner.findById(ownerId);
        
        if (!owner) {
            console.log('Owner not found with ID:', ownerId);
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Extract just the payment-related fields for debugging
        const paymentData = {
            id: owner._id,
            businessName: owner.businessName,
            paymentSetting: owner.paymentSetting,
            paymentSettings: owner.paymentSettings,
            serviceFee: owner.serviceFee
        };
        
        console.log('Debug - Owner payment data:', JSON.stringify(paymentData));
        
        res.status(200).json({
            success: true,
            owner: paymentData
        });
    } catch (error) {
        console.error('Error in debug endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Error in debug endpoint',
            error: error.message
        });
    }
});

// Force update endpoint for setting payment settings for debugging
app.get('/api/debug/force-set-payment/:ownerId', async (req, res) => {
    try {
        const ownerId = req.params.ownerId;
        console.log('Force setting payment settings for owner ID:', ownerId);
        
        // Find the owner by id
        const owner = await Owner.findById(ownerId);
        
        if (!owner) {
            console.log('Owner not found with ID:', ownerId);
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Set default values if missing
        const updates = {
            paymentSetting: owner.paymentSetting || 'Monthly',
            paymentSettings: owner.paymentSettings && owner.paymentSettings.length > 0 ? 
                owner.paymentSettings : 
                [{ name: 'Monthly', amount: 1000 }, { name: 'Quarterly', amount: 2500 }],
            serviceFee: owner.serviceFee || 1000
        };
        
        // Update the owner
        const updatedOwner = await Owner.findByIdAndUpdate(
            ownerId,
            { $set: updates },
            { new: true }
        );
        
        console.log('Force updated owner payment settings:', {
            id: updatedOwner._id,
            paymentSetting: updatedOwner.paymentSetting,
            paymentSettings: updatedOwner.paymentSettings,
            serviceFee: updatedOwner.serviceFee
        });
        
        res.status(200).json({
            success: true,
            message: 'Payment settings force updated',
            owner: {
                id: updatedOwner._id,
                paymentSetting: updatedOwner.paymentSetting,
                paymentSettings: updatedOwner.paymentSettings,
                serviceFee: updatedOwner.serviceFee
            }
        });
    } catch (error) {
        console.error('Error force updating payment settings:', error);
        res.status(500).json({
            success: false,
            message: 'Error force updating payment settings',
            error: error.message
        });
    }
});

// API endpoint to get pending clients for approval
app.get('/api/clients/pending', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        
        // Fetch only pending clients that belong to this owner
        const clients = await Client.find({ 
            owner: ownerId,
            status: 'pending' 
        });
        
        console.log(`Found ${clients.length} pending clients for owner ${ownerId}`);
        
        // Transform data to include only necessary fields
        const clientData = clients.map(client => ({
            id: client._id,
            fullname: client.fullname,
            email: client.email,
            mobile: client.mobile,
            address: client.address,
            city: client.city,
            state: client.state,
            pincode: client.pincode,
            registrationDate: client.registrationDate
        }));
        
        res.status(200).json(clientData);
    } catch (error) {
        console.error('Error fetching pending clients:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error while fetching pending clients',
            error: error.message 
        });
    }
});

// API endpoint to approve a client
app.post('/api/clients/:clientId/approve', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const ownerId = req.user.id;
        
        // Find the client and verify ownership
        const client = await Client.findById(clientId);
        
        if (!client) {
            return res.status(404).json({ 
                success: false, 
                message: 'Client not found' 
            });
        }
        
        // Verify that this client belongs to the owner
        if (client.owner.toString() !== ownerId) {
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to approve this client' 
            });
        }
        
        // Update client status to approved
        client.status = 'approved';
        client.approvedDate = new Date();
        
        await client.save();
        
        res.status(200).json({ 
            success: true, 
            message: 'Client approved successfully',
            client: {
                id: client._id,
                fullname: client.fullname,
                email: client.email,
                status: client.status,
                approvedDate: client.approvedDate
            }
        });
    } catch (error) {
        console.error('Error approving client:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to approve client',
            error: error.message
        });
    }
});

// API endpoint to reject a client
app.post('/api/clients/:clientId/reject', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const ownerId = req.user.id;
        
        // Find the client and verify ownership
        const client = await Client.findById(clientId);
        
        if (!client) {
            return res.status(404).json({ 
                success: false, 
                message: 'Client not found' 
            });
        }
        
        // Verify that this client belongs to the owner
        if (client.owner.toString() !== ownerId) {
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to reject this client' 
            });
        }
        
        // Update client status to rejected
        client.status = 'rejected';
        client.rejectedDate = new Date();
        
        await client.save();
        
        res.status(200).json({ 
            success: true, 
            message: 'Client rejected successfully'
        });
    } catch (error) {
        console.error('Error rejecting client:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to reject client',
            error: error.message
        });
    }
});


// API endpoint to send reminder for a request
app.post('/api/requests/:requestId/remind', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        const ownerId = req.user.id;
        
        console.log(`Processing reminder request for ID: ${requestId}`);
        
        // First, try to find the request directly
        let request = await Request.findById(requestId);
        
        // If not found, check if this is a client ID and find the latest request for this client
        if (!request) {
            console.log(`Request not found with ID ${requestId}, checking if this is a client ID...`);
            
            // Try to find requests for this client
            const requests = await Request.find({ 
                clientId: requestId,
                ownerId: ownerId,
                status: 'approved'
            }).sort({ approvedDate: -1 });
            
            if (requests && requests.length > 0) {
                request = requests[0]; // Use the most recent request
                console.log(`Found request ${request._id} for client ${requestId}`);
            } else {
                return res.status(404).json({ 
                    success: false, 
                    message: 'No request found for this client' 
                });
            }
        }
        
        // Verify ownership
        if (request.ownerId.toString() !== ownerId) {
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to send reminder for this request' 
            });
        }

        // Find the owner to get business details
        const owner = await Owner.findById(ownerId);
        if (!owner) {
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Better client email extraction - check all possible sources
        let clientEmail = '';
        
        // First try direct clientEmail property
        if (request.clientEmail && typeof request.clientEmail === 'string' && request.clientEmail.includes('@')) {
            clientEmail = request.clientEmail;
            console.log(`Using direct clientEmail property: ${clientEmail}`);
        } 
        // Then try email in clientDetails
        else if (request.clientDetails && request.clientDetails.email && 
                 typeof request.clientDetails.email === 'string' && 
                 request.clientDetails.email.includes('@')) {
            clientEmail = request.clientDetails.email;
            console.log(`Using clientDetails.email: ${clientEmail}`);
        }
        // Try to extract from the client object if it's a reference
        else if (request.clientId && typeof request.clientId === 'object' && request.clientId.email) {
            clientEmail = request.clientId.email;
            console.log(`Using clientId.email: ${clientEmail}`);
        }
        
        // Final validation
        if (!clientEmail || !clientEmail.includes('@')) {
            console.error('No valid email found in request:', JSON.stringify(request));
            return res.status(400).json({
                success: false,
                message: 'No valid client email found'
            });
        }
        
        // Get client name
        const clientInfo = request.clientId || request.clientDetails || {};
        const clientName = clientInfo.fullname || 'Client';
        
        try {
            // Import the email utility
            const sendPaymentReminder = require('./email/sendPaymentReminder');
            
            // Send the email reminder
            await sendPaymentReminder({
                clientEmail: clientEmail,
                clientName: clientName,
                serviceName: request.serviceDetails?.serviceName || owner.serviceName || 'our services',
                ownerName: owner.ownerName || 'The Management',
                businessName: owner.businessName || request.serviceDetails?.businessName || 'Our Business',
                amount: request.planAmount || 'the outstanding amount',
                dueDate: request.nextDueDate || new Date(),
                planType: request.planType || 'subscription'
            });
            
            console.log(`Payment reminder email sent to ${clientName} (${clientEmail})`);
            
            res.status(200).json({ 
                success: true, 
                message: 'Payment reminder email sent successfully',
                email: clientEmail 
            });
        } catch (emailError) {
            console.error('Error sending email reminder:', emailError);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to send email reminder',
                error: emailError.message 
            });
        }
    } catch (error) {
        console.error('Error processing reminder request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process reminder request',
            error: error.message
        });
    }
});
// API endpoint to delete a request
app.delete('/api/requests/:requestId', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        const ownerId = req.user.id;
        
        // Find the request
        const request = await Request.findById(requestId);
        
        if (!request) {
            return res.status(404).json({ 
                success: false, 
                message: 'Request not found' 
            });
        }
        
        // Verify ownership
        if (request.ownerId.toString() !== ownerId) {
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to delete this request' 
            });
        }
        
        // Delete the request
        await Request.findByIdAndDelete(requestId);
        
        res.status(200).json({ 
            success: true, 
            message: 'Request deleted successfully' 
        });
    } catch (error) {
        console.error('Error deleting request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete request',
            error: error.message
        });
    }
});

// API endpoint to approve a request
app.post('/api/requests/:requestId/approve', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        const ownerId = req.user.id;
        
        // Find the request and verify ownership
        const request = await Request.findById(requestId);
        
        if (!request) {
            return res.status(404).json({ 
                success: false, 
                message: 'Request not found' 
            });
        }
        
        // Verify that this request belongs to the owner
        if (request.ownerId.toString() !== ownerId) {
            return res.status(403).json({ 
                success: false, 
                message: 'Not authorized to approve this request' 
            });
        }
        
        // Make sure we have client's email
        if (!request.clientEmail && request.clientDetails && request.clientDetails.email) {
            request.clientEmail = request.clientDetails.email;
        }
        
        // If we still don't have client's email, try to get it from the client document
        if (!request.clientEmail) {
            try {
                const client = await Client.findById(request.clientId);
                if (client && client.email) {
                    request.clientEmail = client.email;
                    // Also update the clientDetails if it exists
                    if (request.clientDetails) {
                        request.clientDetails.email = client.email;
                    }
                }
            } catch (err) {
                console.error('Error fetching client email:', err);
            }
        }
        
        // Update request status to approved
        request.status = 'approved';
        request.approvedDate = new Date();
        
        // Set initial payment status
        request.paymentStatus = 'unpaid';
        
        // Set next due date based on approval date
        request.nextDueDate = request.approvedDate;
        
        await request.save();
        
        console.log(`Request ${requestId} approved successfully with clientEmail: ${request.clientEmail}`);
        
        res.status(200).json({ 
            success: true, 
            message: 'Request approved successfully',
            request: {
                id: request._id,
                clientId: request.clientId,
                status: request.status,
                approvedDate: request.approvedDate,
                nextDueDate: request.nextDueDate,
                clientEmail: request.clientEmail
            }
        });
    } catch (error) {
        console.error('Error approving request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to approve request',
            error: error.message
        });
    }
});

// API endpoint to get client's enrolled services
app.get('/api/client/enrolled-services', verifyToken, async (req, res) => {
    try {
        const clientId = req.user.id;
        console.log(`Fetching enrolled services for client ID: ${clientId}`);
        
        // Find all approved requests for this client
        const requests = await Request.find({ 
            clientId: clientId,
            status: 'approved'
        }).sort({ approvedDate: -1 }); // Most recent first
        
        console.log(`Found ${requests.length} approved services for client`);
        
        // Format the response data
        const services = await Promise.all(requests.map(async (request) => {
            // Try to get more details from the owner if needed
            let ownerDetails = {};
            if (request.ownerId) {
                try {
                    const owner = await Owner.findById(request.ownerId);
                    if (owner) {
                        ownerDetails = {
                            businessName: owner.businessName,
                            businessEmail: owner.businessEmail,
                            businessPhone: owner.businessPhone,
                            serviceName: owner.serviceName
                        };
                    }
                } catch (err) {
                    console.error('Error fetching owner details:', err);
                }
            }
            
            return {
                id: request._id,
                planType: request.planType || 'Standard',
                planAmount: request.planAmount || 0,
                status: request.status,
                paymentStatus: request.paymentStatus || 'unpaid',
                approvedDate: request.approvedDate,
                lastPaymentDate: request.lastPaymentDate,
                nextDueDate: request.nextDueDate,
                // Get service details from request or owner
                serviceDetails: request.serviceDetails || {
                    businessName: ownerDetails.businessName || 'Business Name',
                    serviceName: ownerDetails.serviceName || 'Service Name',
                    ownerName: ownerDetails.ownerName || ''
                },
                owner: {
                    id: request.ownerId,
                    businessName: ownerDetails.businessName || request.serviceDetails?.businessName || '',
                    businessEmail: ownerDetails.businessEmail || '',
                    businessPhone: ownerDetails.businessPhone || '',
                    serviceName: ownerDetails.serviceName || request.serviceDetails?.serviceName || ''
                }
            };
        }));
        
        res.status(200).json({
            success: true,
            services
        });
    } catch (error) {
        console.error('Error fetching client enrolled services:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch enrolled services',
            error: error.message
        });
    }
});

// Owner Profile API Endpoint - Get profile data
app.get('/api/owner/profile', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        
        // Find the owner by id
        const owner = await Owner.findById(ownerId);
        
        if (!owner) {
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Create a safe version of owner data without password
        const safeOwnerData = {
            _id: owner._id,
            businessName: owner.businessName,
            ownerName: owner.ownerName,
            businessEmail: owner.businessEmail,
            businessPhone: owner.businessPhone,
            businessAddress: owner.businessAddress,
            registrationNo: owner.registrationNo,
            taxID: owner.taxID,
            serviceName: owner.serviceName,
            serviceDescription: owner.serviceDescription,
            capacity: owner.capacity,
            businessType: owner.businessType,
            otherBusinessType: owner.otherBusinessType
        };
        
        res.status(200).json({
            success: true,
            owner: safeOwnerData
        });
    } catch (error) {
        console.error('Error getting owner profile:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while getting profile',
            error: error.message
        });
    }
});

// Owner Profile API Endpoint - Update profile data
app.put('/api/owner/profile', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        
        // Extract profile data from request body
        const {
            businessName,
            ownerName,
            businessPhone,
            businessAddress,
            registrationNo,
            taxID,
            serviceName,
            serviceDescription,
            capacity,
            businessType,
            otherBusinessType
        } = req.body;
        
        // Validate required fields
        if (!businessName || !ownerName || !businessPhone || !businessAddress || 
            !registrationNo || !taxID || !serviceName || !capacity || !businessType) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        
        // Prepare the update object
        const updateData = {
            businessName,
            ownerName,
            businessPhone,
            businessAddress,
            registrationNo,
            taxID,
            serviceName,
            serviceDescription,
            capacity: Number(capacity),
            businessType
        };
        
        // Add otherBusinessType if business type is 'other'
        if (businessType === 'other' && otherBusinessType) {
            updateData.otherBusinessType = otherBusinessType;
        }
        
        // Find and update the owner
        const updatedOwner = await Owner.findByIdAndUpdate(
            ownerId,
            { $set: updateData },
            { new: true, runValidators: true }
        );
        
        if (!updatedOwner) {
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Create a safe version of owner data without password
        const safeOwnerData = {
            _id: updatedOwner._id,
            businessName: updatedOwner.businessName,
            ownerName: updatedOwner.ownerName,
            businessEmail: updatedOwner.businessEmail,
            businessPhone: updatedOwner.businessPhone,
            businessAddress: updatedOwner.businessAddress,
            registrationNo: updatedOwner.registrationNo,
            taxID: updatedOwner.taxID,
            serviceName: updatedOwner.serviceName,
            serviceDescription: updatedOwner.serviceDescription,
            capacity: updatedOwner.capacity,
            businessType: updatedOwner.businessType,
            otherBusinessType: updatedOwner.otherBusinessType
        };
        
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            owner: safeOwnerData
        });
    } catch (error) {
        console.error('Error updating owner profile:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while updating profile',
            error: error.message
        });
    }
});

// Owner Password Change API Endpoint
app.post('/api/owner/change-password', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        const { currentPassword, newPassword } = req.body;
        
        // Validate input
        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }
        
        // Find the owner
        const owner = await Owner.findById(ownerId);
        if (!owner) {
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, owner.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }
        
        // Validate new password strength
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters and include uppercase, lowercase, number, and special character'
            });
        }
        
        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        
        // Update the password
        const updatedOwner = await Owner.findByIdAndUpdate(
            ownerId,
            { $set: { password: hashedPassword } },
            { new: true }
        );
        
        res.status(200).json({
            success: true,
            message: 'Password updated successfully'
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while changing password',
            error: error.message
        });
    }
});

// Global object to store OTPs (in a production environment, use a database)
const otpStore = {};

// Email OTP routes
app.post('/api/send-email-otp', async (req, res) => {
  try {
    console.log('OTP request received:', req.body);
    const { email } = req.body;
    
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid email is required' });
    }
    
    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`Generated OTP for ${email}: ${otp}`);
    
    // Store OTP with expiry (15 minutes)
    otpStore[email] = {
      code: otp,
      expiry: Date.now() + (15 * 60 * 1000) // 15 minutes in milliseconds
    };
    
    // Create email transporter with reduced debug output
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || '//YOUR EMAIL',
        pass: process.env.EMAIL_PASSWORD || '//YOUR PASSWORD THROUTH THE TWO STEP VERIFICATION'
      },
      debug: false, // Disable debug mode
      logger: false // Disable logger
    });
    
    // Verify transporter configuration
    transporter.verify((error, success) => {
      if (error) {
        console.error("Email transporter verification failed:", error);
        console.error("Please check your email credentials and ensure:");
        console.error("1. You're using the correct email and password");
        console.error("2. If using Gmail, you've enabled 'Less secure app access' or created an 'App Password'");
        console.error("3. Your network allows SMTP connections");
      } else {
        console.log("Email transporter is ready to send emails");
      }
    });
    
    // Define mail options
    const mailOptions = {
      from: process.env.EMAIL_USER || 'ganeshhipparkar30@gmail.com',
      to: email,
      subject: 'Email Verification OTP - Smart Fee Management',
      text: `Your verification code is: ${otp}\n\nThis code will expire in 15 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h1 style="color: #4338ca; text-align: center;">Smart Fee Management</h1>
          <h2 style="text-align: center;">Email Verification</h2>
          <p>Hello,</p>
          <p>Thank you for registering with Smart Fee Management. Please use the following OTP to verify your email address:</p>
          <div style="text-align: center; padding: 15px; background-color: #f3f4f6; border-radius: 5px; margin: 20px 0;">
            <span style="font-size: 24px; font-weight: bold; letter-spacing: 5px;">${otp}</span>
          </div>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
          <div style="text-align: center; margin
            <p>&copy; 2025 Smart Fee Management. All rights reserved.</p>
          </div>
        </div>
      `
    };
    
    // Send the email
    await transporter.sendMail(mailOptions);
    console.log(`OTP email sent to ${email}`);
    
    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP email:', error);
    res.status(500).json({ message: 'Failed to send OTP', error: error.message });
  }
});

app.post('/api/verify-email-otp', (req, res) => {
  try {
    console.log('OTP verification request received:', req.body);
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }
    
    // Check if OTP exists and is valid
    const otpData = otpStore[email];
    
    if (!otpData) {
      return res.status(400).json({ message: 'No OTP found for this email. Please request a new one.' });
    }
    
    // Check if OTP has expired
    if (Date.now() > otpData.expiry) {
      // Remove expired OTP
      delete otpStore[email];
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }
    
    // Check if OTP matches
    if (otpData.code !== otp) {
      return res.status(400).json({ message: 'Invalid OTP. Please try again.' });
    }
    
    // OTP verified successfully, remove it from store
    delete otpStore[email];
    console.log(`OTP verified successfully for ${email}`);
    
    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Failed to verify OTP', error: error.message });
  }
});

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        // Find admin by email
        const admin = await Admin.findOne({ email });
        
        if (!admin) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Check password
        const isMatch = await admin.comparePassword(password);
        
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: 'admin' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Send successful response
        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            admin: {
                email: admin.email,
                id: admin._id
            }
        });
    } catch (error) {
        console.error('Error in admin login:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Admin endpoints
// Logging middleware for admin endpoints
app.use('/api/admin/*', (req, res, next) => {
    console.log(`Admin API Request: ${req.method} ${req.originalUrl}`);
    console.log('Admin Auth Token:', req.headers['authorization'] ? 'Present' : 'Missing');
    next();
});

// Get all clients with improved error handling
app.get('/api/admin/clients', verifyToken, async (req, res) => {
    try {
        // Check if the user is an admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }
        
        console.log('Fetching all clients for admin...');
        
        // Fetch all clients
        const clients = await Client.find({}).sort({ registrationDate: -1 });
        
        console.log(`Found ${clients.length} clients`);
        
        // Return the clients
        res.status(200).json(clients);
    } catch (error) {
        console.error('Error fetching clients:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching clients',
            error: error.message
        });
    }
});

// Delete a client
app.delete('/api/admin/clients/:clientId', verifyToken, async (req, res) => {
    try {
        // Check if the user is an admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }
        
        const { clientId } = req.params;
        
        // Delete the client
        const result = await Client.findByIdAndDelete(clientId);
        
        if (!result) {
            return res.status(404).json({
                success: false,
                message: 'Client not found'
            });
        }
        
        // Also delete any requests associated with this client
        await Request.deleteMany({ clientId });
        
        res.status(200).json({
            success: true,
            message: 'Client deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting client:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while deleting client',
            error: error.message
        });
    }
});

// Get all owners with improved error handling
app.get('/api/admin/owners', verifyToken, async (req, res) => {
    try {
        // Check if the user is an admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }
        
        console.log('Fetching all owners for admin...');
        
        // Fetch all owners
        const owners = await Owner.find({}).sort({ registrationDate: -1 });
        
        console.log(`Found ${owners.length} owners`);
        
        // Return the owners
        res.status(200).json(owners);
    } catch (error) {
        console.error('Error fetching owners:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching owners',
            error: error.message
        });
    }
});

// Delete an owner
app.delete('/api/admin/owners/:ownerId', verifyToken, async (req, res) => {
    try {
        // Check if the user is an admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }
        
        const { ownerId } = req.params;
        
        // Delete the owner
        const result = await Owner.findByIdAndDelete(ownerId);
        
        if (!result) {
            return res.status(404).json({
                success: false,
                message: 'Owner not found'
            });
        }
        
        // Also delete any requests associated with this owner
        await Request.deleteMany({ ownerId });
        
        res.status(200).json({
            success: true,
            message: 'Owner deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting owner:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while deleting owner',
            error: error.message
        });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access the application at http://localhost:${PORT}`);
});

// API endpoint to get owner requests with filtering
app.get('/api/owner/requests', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        const { status } = req.query;
        
        console.log(`Fetching requests for owner: ${ownerId}, status filter: ${status}`);
        
        // Build query object
        const query = { ownerId: ownerId };
        
        // Add status filter if provided
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }
        
        // Fetch requests from database
        const requests = await Request.find(query)
            .populate('clientId', 'fullname email mobile')
            .populate('serviceId', 'serviceName businessName');
        
        console.log(`Found ${requests.length} requests for owner ${ownerId}`);
        
        res.status(200).json({
            success: true,
            requests
        });
    } catch (error) {
        console.error('Error fetching owner requests:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching requests',
            error: error.message
        });
    }
});

// API endpoint to get clients for an owner
app.get('/api/owner/clients', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.id;
        
        console.log('Fetching clients for owner:', ownerId);
        
        // Find all approved requests for this owner to count unique clients
        const approvedRequests = await Request.find({ 
            ownerId: ownerId,
            status: 'approved' 
        }).populate('clientId', 'fullname email mobile');
        
        console.log(`Found ${approvedRequests.length} approved requests for owner ${ownerId}`);
        
        // Create a map of unique clients from the requests
        const uniqueClientsMap = new Map();
        
        approvedRequests.forEach(request => {
            const clientId = request.clientId?._id?.toString() || request.clientId?.toString();
            if (clientId && !uniqueClientsMap.has(clientId)) {
                // Get client info from populated clientId or fallback to clientDetails
                const clientInfo = request.clientId || request.clientDetails || {};
                
                uniqueClientsMap.set(clientId, {
                    id: clientId,
                    fullname: clientInfo.fullname || 'Unknown',
                    email: request.clientEmail || clientInfo.email || '',
                    mobile: clientInfo.mobile || 'N/A'
                });
            }
        });
        
        // Convert the map to an array
        const clients = Array.from(uniqueClientsMap.values());
        
        console.log(`Found ${clients.length} unique clients for owner ${ownerId}`);
        
        res.status(200).json({
            success: true,
            clients
        });
    } catch (error) {
        console.error('Error fetching clients for owner:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching clients',
            error: error.message
        });
    }
});

const checkDuePayments = require('./email/checkDuePayments');

// Call checkDuePayments when server starts
checkDuePayments();

// Set up interval to check due payments every hour
setInterval(checkDuePayments, 60 * 60 * 1000);

// Function to check and send payment due alerts
async function checkAndSendDuePaymentAlerts(ownerId) {
  try {
    console.log(`Checking due payments for owner: ${ownerId}`);
    
    // Find all approved and unpaid requests for this owner
    const dueRequests = await Request.find({
      ownerId: ownerId,
      status: 'approved',
      paymentStatus: 'unpaid'
    });

    for (const request of dueRequests) {
      // Calculate days remaining
      const nextDue = new Date(request.nextDueDate);
      const today = new Date();
      const timeDiff = nextDue - today;
      const daysRemaining = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));

      if (daysRemaining <= 3 && daysRemaining >= 0) {
        console.log(`Sending payment reminder for request ${request._id} with ${daysRemaining} days remaining`);
        
        try {
          // Get client email from request
          const clientEmail = request.clientEmail || (request.clientDetails && request.clientDetails.email);
          const clientName = request.clientDetails?.fullname || 'Client';
          
          if (!clientEmail) {
            console.error(`No email found for client in request ${request._id}`);
            continue;
          }

          // Send payment reminder email
          const mailOptions = {
            from: process.env.EMAIL_USER || 'ganeshhipparkar30@gmail.com',
            to: clientEmail,
            subject: `Payment Reminder: ${daysRemaining} days remaining`,
            html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h1 style="color: #4338ca; text-align: center;">Payment Reminder</h1>
                <p>Hello ${clientName},</p>
                <p>This is a reminder that your payment of ₹${request.planAmount} for ${request.serviceDetails?.serviceName || 'our service'} is due in ${daysRemaining} days.</p>
                <p>Due Date: ${nextDue.toLocaleDateString()}</p>
                <p>Please make the payment at your earliest convenience to avoid any service interruptions.</p>
                <div style="text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px;">
                  <p>&copy; 2025 Smart Fee Management. All rights reserved.</p>
                </div>
              </div>
            `
          };

          await transporter.sendMail(mailOptions);
          console.log(`Payment reminder sent successfully to ${clientEmail}`);
        } catch (error) {
          console.error(`Failed to send payment reminder to ${request.clientEmail}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error checking due payments:', error);
  }
}

// Add endpoint to check due payments
app.get('/api/check-due-payments', verifyToken, async (req, res) => {
  try {
    const ownerId = req.user.id;
    
    // Find all approved and unpaid requests for this owner
    const dueRequests = await Request.find({
      ownerId: ownerId,
      status: 'approved',
      paymentStatus: 'unpaid'
    });

    // Process each request and send emails
    const processedRequests = [];
    for (const request of dueRequests) {
      // Calculate days remaining
      const nextDue = new Date(request.nextDueDate);
      const today = new Date();
      const timeDiff = nextDue - today;
      const daysRemaining = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));

      if (daysRemaining <= 3 && daysRemaining >= 0) {
        // Get client email from request
        const clientEmail = request.clientEmail || (request.clientDetails && request.clientDetails.email);
        const clientName = request.clientDetails?.fullname || 'Client';
        
        if (clientEmail) {
          try {
            // Send payment reminder email
            const mailOptions = {
              from: process.env.EMAIL_USER || 'ganeshhipparkar30@gmail.com',
              to: clientEmail,
              subject: `Payment Reminder: ${daysRemaining} days remaining`,
              html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                  <h1 style="color: #4338ca; text-align: center;">Payment Reminder</h1>
                  <p>Hello ${clientName},</p>
                  <p>This is a reminder that your payment of ₹${request.planAmount} for ${request.serviceDetails?.serviceName || 'our service'} is due in ${daysRemaining} days.</p>
                  <p>Due Date: ${nextDue.toLocaleDateString()}</p>
                  <p>Please make the payment at your earliest convenience to avoid any service interruptions.</p>
                  <div style="text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px;">
                    <p>&copy; 2025 Smart Fee Management. All rights reserved.</p>
                  </div>
                </div>
              `
            };

            await transporter.sendMail(mailOptions);
            console.log(`Payment reminder sent successfully to ${clientEmail}`);
          } catch (error) {
            console.error(`Failed to send payment reminder to ${clientEmail}:`, error);
          }
        }

        // Add to processed requests
        processedRequests.push({
          id: request._id,
          clientName: clientName,
          serviceName: request.serviceDetails?.serviceName || 'Service',
          amount: request.planAmount,
          nextDueDate: request.nextDueDate,
          daysRemaining: daysRemaining
        });
      }
    }

    res.status(200).json({ 
      success: true, 
      message: 'Due payments check completed',
      dueRequests: processedRequests
    });
  } catch (error) {
    console.error('Error in check-due-payments endpoint:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to check due payments',
      error: error.message 
    });
  }
});

// Function to send payment reminder email
async function sendPaymentReminderEmail(request) {
  try {
    const clientEmail = request.clientEmail || (request.clientDetails && request.clientDetails.email);
    const clientName = request.clientDetails?.fullname || 'Client';
    
    if (!clientEmail) {
      console.error(`No email found for client in request ${request._id}`);
      return false;
    }

    // Calculate days remaining
    const nextDue = new Date(request.nextDueDate);
    const today = new Date();
    const timeDiff = nextDue - today;
    const daysRemaining = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));

    // Send payment reminder email
    const mailOptions = {
      from: process.env.EMAIL_USER || 'ganeshhipparkar30@gmail.com',
      to: clientEmail,
      subject: `Payment Reminder: ${daysRemaining} days remaining`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h1 style="color: #4338ca; text-align: center;">Payment Reminder</h1>
          <p>Hello ${clientName},</p>
          <p>This is a reminder that your payment of ₹${request.planAmount} for ${request.serviceDetails?.serviceName || 'our service'} is due in ${daysRemaining} days.</p>
          <p>Due Date: ${nextDue.toLocaleDateString()}</p>
          <p>Please make the payment at your earliest convenience to avoid any service interruptions.</p>
          <div style="text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px;">
            <p>&copy; 2025 Smart Fee Management. All rights reserved.</p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`Payment reminder sent successfully to ${clientEmail}`);
    return true;
  } catch (error) {
    console.error(`Failed to send payment reminder to ${request.clientEmail}:`, error);
    return false;
  }
}

// Add endpoint to get approved clients with automatic reminders
app.get('/api/owner/approved-clients', verifyToken, async (req, res) => {
  try {
    const ownerId = req.user.id;
    console.log(`Fetching approved clients for owner: ${ownerId}`);
    
    // Find all approved requests for this owner
    const requests = await Request.find({
      ownerId: ownerId,
      status: 'approved'
    }).populate('clientId', 'fullname email mobile');

    console.log(`Found ${requests.length} approved requests`);
    const clients = [];
    
    for (const request of requests) {
      // Calculate days remaining
      const nextDue = new Date(request.nextDueDate);
      const today = new Date();
      const timeDiff = nextDue - today;
      const daysRemaining = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));
      
      // Debug logging
      console.log(`Request ${request._id}:`);
      console.log(`- Next due date: ${nextDue}`);
      console.log(`- Today: ${today}`);
      console.log(`- Days remaining: ${daysRemaining}`);

      // Get client info from populated clientId or fallback to clientDetails
      const clientInfo = request.clientId || request.clientDetails || {};
      
      clients.push({
        id: request._id,
        clientId: request.clientId?._id || request.clientId,
        fullname: clientInfo.fullname || 'Unknown',
        email: request.clientEmail || clientInfo.email || '',
        mobile: clientInfo.mobile || 'N/A',
        planType: request.planType || 'N/A',
        planAmount: request.planAmount || 0,
        approvedDate: request.approvedDate,
        nextDueDate: request.nextDueDate,
        lastPaymentDate: request.lastPaymentDate,
        paymentStatus: request.paymentStatus || 'unpaid',
        daysRemaining: daysRemaining, // This will be negative for overdue payments
        isOverdue: daysRemaining < 0, // Add flag for overdue status
        overdueDays: daysRemaining < 0 ? Math.abs(daysRemaining) : 0, // Number of days overdue
        status: request.status
      });
    }

    console.log(`Sending ${clients.length} clients to frontend`);
    res.status(200).json({
      success: true,
      clients
    });
  } catch (error) {
    console.error('Error fetching approved clients:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch approved clients',
      error: error.message
    });
  }
});

