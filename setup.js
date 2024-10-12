// Import database connection
const connection = require('./db');
const bcrypt = require('bcrypt');

// Function to drop users table if it exists
const dropUsersTable = () => {
    const query = `DROP TABLE IF EXISTS users`;
    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error dropping users table:', err);
        } else {
            console.log('Users table dropped successfully.');
            createUsersTable();  // Recreate the table after it's dropped
        }
    });
};

// Function to create users table
const createUsersTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(255) NOT NULL,  -- Store hashed password
            role ENUM('user', 'admin') NOT NULL DEFAULT 'user'  -- Add the role field
        )`;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error creating users table:', err);
        } else {
            console.log('Users table created successfully.');
            insertSampleUsers();  // Insert sample users after table is created
        }
    });
};

// Function to insert sample users with bcrypt hashed passwords
const insertSampleUsers = async () => {
    try {
        // Hash passwords
        const adminPassword = await bcrypt.hash('admin123', 10);  // Hash the admin password
        const userPassword = await bcrypt.hash('user123', 10);    // Hash the user password

        const query = `
            INSERT INTO users (username, password, role) VALUES
            ('admin', '${adminPassword}', 'admin'),
            ('user', '${userPassword}', 'user')
        `;

        connection.query(query, (err, results) => {
            if (err) {
                console.error('Error inserting sample users:', err);
            } else {
                console.log('Sample users inserted successfully.');
            }
        });
    } catch (err) {
        console.error('Error hashing passwords:', err);
    }
};



// Function to create products table
const createProductsTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            price DECIMAL(10, 2) NOT NULL
        )`;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error creating products table:', err);
        } else {
            console.log('Products table created successfully.');
            createPurchasesTable();
        }
    });
};

// Function to create products table
const createPurchasesTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS purchases (
            id INT AUTO_INCREMENT PRIMARY KEY,
            product_id INT(2) NOT NULL,
            price DECIMAL(10, 2) NOT NULL
        )`;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error creating products table:', err);
        } else {
            console.log('Purchases table created successfully.');
            insertSampleProducts();
        }
    });
};

// Function to insert sample products
const insertSampleProducts = () => {
    const query = `
        INSERT INTO products (name, description, price) VALUES
        ('Laptop', 'A high-end gaming laptop', 1200.50),
        ('Smartphone', 'A latest-gen smartphone', 799.99),
        ('Headphones', 'Noise-cancelling headphones', 199.99),
        ('Tablet', 'A tablet with a 10-inch display', 299.99)
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error inserting sample products:', err);
        } else {
            console.log('Sample products inserted successfully.');
            exitProcess();  // Exit after inserting sample products
        }
    });
};





// Function to exit the process
const exitProcess = () => {
    connection.end(err => {
        if (err) {
            console.error('Error closing the database connection:', err);
        } else {
            console.log('Database connection closed. Exiting setup script.');
        }
        process.exit(0);  // Exit the process
    });
};

// Function to run all setup tasks
const runSetup = () => {
    dropUsersTable();  // First drop the table
    createProductsTable();  // Create products table after dropping users
};

// Execute the setup script
runSetup();
