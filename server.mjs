import express from 'express';
import bodyParser from 'body-parser';
import chalk from 'chalk';  // Import chalk for colored output
import dotenv from 'dotenv';  // Import dotenv to use environment variables

// Load environment variables from a .env file (if present)
dotenv.config();

// Create an instance of the express app
const app = express();

// Use bodyParser middleware to parse URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Define the route to handle POST requests
app.post('/', (req, res) => {
    const { hostname, ip } = req.body;

    // Validate that both fields exist
    if (!hostname || !ip) {
        return res.status(400).send('Hostname and IP address are required');
    }

    // Log the received data
    console.log('Received data:');
    console.log('Hostname:', hostname);
    console.log('IP Address:', ip);

    // Respond back to the client
    res.send('Data received successfully');
});

// Get the server IP address and port from environment variables (with fallback)
const PORT = process.env.PORT || 3000;
const IP_ADDRESS = process.env.IP_ADDRESS || '0.0.0.0';  // Default to 0.0.0.0 if not specified

// Start the server and listen on the specified IP address and port
app.listen(PORT, IP_ADDRESS, () => {
    console.log(chalk.green(`Server is running on http://${IP_ADDRESS}:${PORT}`));  // Use chalk to print in green
});
