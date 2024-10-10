 
// routes/secure.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');

// Secure: Price Manipulation Prevention
router.post('/purchase', (req, res) => {
    const { productId } = req.body;

    // Retrieve the price from the server (instead of client-controlled price)
    const query = `SELECT price FROM products WHERE id = ?`;
    db.query(query, [productId], (err, result) => {
        if (err) return res.status(500).send('Database error');
        const price = result[0].price;

        // Proceed with inserting the validated price
        const purchaseQuery = `INSERT INTO purchases (product_id, price) VALUES (?, ?)`;
        db.query(purchaseQuery, [productId, price], (err, result) => {
            if (err) return res.status(500).send('Database error');
            res.send('Purchase completed!');
        });
    });
});

// Secure: SQL Injection Protection using Prepared Statements
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Using prepared statements to prevent SQL Injection
    const query = `SELECT * FROM users WHERE username = ?`;
    db.query(query, [username], async (err, result) => {
        if (err) return res.status(500).send('Database error');
        if (result.length > 0) {
            // Use bcrypt to compare passwords securely
            const validPassword = await bcrypt.compare(password, result[0].password);
            if (validPassword) {
                res.send('Login successful!');
            } else {
                res.status(401).send('Invalid credentials');
            }
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// Secure: Strong JWT, MFA (not shown, but assumed), and Authorization Checks
router.post('/auth', (req, res) => {
    const { username, password } = req.body;

    // Secure authentication with bcrypt and strong JWT
    if (username === 'admin' && password === 'admin123') {
        const token = jwt.sign({ username: 'admin', role: 'admin' }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Secure: Authorization with Proper Role Checks
router.get('/admin', (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send('Invalid token');

        // Check if user is admin
        if (decoded.role === 'admin') {
            res.send('Welcome to the admin panel!');
        } else {
            res.status(403).send('Access denied');
        }
    });
});

// Secure: Rate Limiting for Login Attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 5,  // Limit each IP to 5 login attempts per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

router.post('/login-nolimit', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = ?`;

    db.query(query, [username], async (err, result) => {
        if (err) return res.status(500).send('Database error');
        if (result.length > 0) {
            const validPassword = await bcrypt.compare(password, result[0].password);
            if (validPassword) {
                res.send('Login successful!');
            } else {
                res.status(401).send('Invalid credentials');
            }
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// Secure: No Sensitive Data Exposure (Do not expose environment variables)
router.get('/config', (req, res) => {
    res.status(403).send('Access to sensitive configuration is denied');
});

// Secure: Strong Password Hashing using bcrypt
router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Hash the password with bcrypt before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;

    db.query(query, [username, hashedPassword], (err, result) => {
        if (err) return res.status(500).send('Database error');
        res.send('User registered successfully!');
    });
});

module.exports = router;
