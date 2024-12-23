const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Use body-parser middleware to parse JSON requests
app.use(bodyParser.json());

// Store received data in-memory
let receivedData = [];

// Route to receive system information from the client
app.post('/receive-data', (req, res) => {
    const { ip_address, hostname } = req.body;

    if (ip_address && hostname) {
        // Store the received data
        receivedData.push({ ip_address, hostname });

        // Respond with a success message
        return res.status(200).json({
            status: 'success',
            message: 'Data received successfully',
        });
    } else {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required data (ip_address, hostname)',
        });
    }
});

// Route to view the received data
app.get('/view-data', (req, res) => {
    return res.status(200).json(receivedData);
});

// Your desired local IP address (10.0.1.35)
const localIpAddress = '10.0.1.35';  // Replace with your actual local IP address

// Start the server on your local IP address (10.0.1.35)
app.listen(port, localIpAddress, () => {
    console.log(`Server is running on http://${localIpAddress}:${port}`);
});
