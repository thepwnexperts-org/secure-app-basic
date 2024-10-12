// Import database connection
const connection = require('./db');
const bcrypt = require('bcrypt');

// Function to drop users table if it exists
const dropUsersTable = () => {
    return new Promise((resolve, reject) => {
        const query = `DROP TABLE IF EXISTS users`;
        connection.query(query, (err, results) => {
            if (err) {
                console.error('Error dropping users table:', err);
                reject(err);
            } else {
                console.log('Users table dropped successfully.');
                resolve();  // Resolve the promise to continue
            }
        });
    });
};

// Function to create users table
const createUsersTable = async () => {
    const query = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(255) NOT NULL,  -- Store hashed password
            role ENUM('user', 'admin') NOT NULL DEFAULT 'user'  -- Add the role field
        )`;

    return new Promise((resolve, reject) => {
        connection.query(query, async (err, results) => {
            if (err) {
                console.error('Error creating users table:', err);
                reject(err);
            } else {
                console.log('Users table created successfully.');
                await insertSampleUsers();  // Wait for the sample users to be inserted
                resolve();  // Resolve after insertion
            }
        });
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

        return new Promise((resolve, reject) => {
            connection.query(query, (err, results) => {
                if (err) {
                    console.error('Error inserting sample users:', err);
                    reject(err);
                } else {
                    console.log('Sample users inserted successfully.');
                    resolve();  // Resolve after insertion
                }
            });
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

    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) {
                console.error('Error creating products table:', err);
                reject(err);
            } else {
                console.log('Products table created successfully.');
                createPurchasesTable().then(resolve).catch(reject);
            }
        });
    });
};

// Function to create purchases table
const createPurchasesTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS purchases (
            id INT AUTO_INCREMENT PRIMARY KEY,
            product_id INT(2) NOT NULL,
            price DECIMAL(10, 2) NOT NULL
        )`;

    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) {
                console.error('Error creating purchases table:', err);
                reject(err);
            } else {
                console.log('Purchases table created successfully.');
                insertSampleProducts().then(resolve).catch(reject);
            }
        });
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

    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) {
                console.error('Error inserting sample products:', err);
                reject(err);
            } else {
                console.log('Sample products inserted successfully.');
                exitProcess();  // Exit after inserting sample products
                resolve();  // Resolve after insertion
            }
        });
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
const runSetup = async () => {
    await dropUsersTable();  // First drop the table
    await createUsersTable();  // Create users table
    await createProductsTable();  // Create products table
};

// Execute the setup script
runSetup().catch(err => {
    console.error('Error in setup:', err);
    exitProcess();  // Exit on error
});
