const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();


//const SECRET = process.env.JWT_SECRET;

// Function to generate JWT
function generateJWT(username, role) {
    // Create the token with weak secret
    const token=jwt.sign({ email: username,role: role }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    //const token = jwt.sign({ username: username, role: role }, SECRET, { algorithm: 'HS256' });
    console.log('Generated JWT:', token);
    return token;
}

// Example usage
generateJWT('admin@example.com', 'admin');

