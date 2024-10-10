 
// app.js
const express = require('express');
const dotenv = require('dotenv');
const secureRoutes = require('./routes/secure');

dotenv.config();

const app = express();

// Middlewares
app.use(express.json());  // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// Use the secure routes
app.use('/secure', secureRoutes);

module.exports = app;
