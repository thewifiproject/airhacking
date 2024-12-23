// Import necessary modules
import express from 'express';
import bodyParser from 'body-parser';
import chalk from 'chalk';  // Import chalk for colored output

// Create an instance of the express app
const app = express();

// Use bodyParser middleware to parse URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Define the route to handle POST requests
app.post('/', (req, res) => {
    const { hostname, ip } = req.body;
    
    // Log the received data
    console.log('Received data:');
    console.log('Hostname:', hostname);
    console.log('IP Address:', ip);
    
    // Respond back to the client
    res.send('Data received successfully');
});

// Define the server IP address and port
const PORT = 3000;
const IP_ADDRESS = '10.0.1.33';

// Start the server and listen on the specified IP address and port
app.listen(PORT, IP_ADDRESS, () => {
    console.log(chalk.green(`Server is running on http://${IP_ADDRESS}:${PORT}`));  // Use chalk to print in green
});
