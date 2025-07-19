const mongoose = require('mongoose');
const Admin = require('./models/Admin');

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/mp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB successfully'))
.catch(err => {
    console.error('Failed to connect to MongoDB:', err);
    process.exit(1);
});

async function checkAdmin() {
    try {
        // Check if admin exists
        const admin = await Admin.findOne({ email: 'ganeshhipparkar30@gmail.com' });
        
        if (admin) {
            console.log('Admin user exists:', {
                email: admin.email,
                id: admin._id,
                createdAt: admin.createdAt
            });
        } else {
            console.log('Admin user does not exist');
        }
        
        mongoose.connection.close();
    } catch (error) {
        console.error('Error checking admin user:', error);
        mongoose.connection.close();
    }
}

checkAdmin(); 