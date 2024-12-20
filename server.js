// server.js
const express = require('express');
const bodyParser = require('body-parser');

// Create an Express app
const app = express();

// Middleware to parse POST request data
app.use(bodyParser.urlencoded({ extended: true }));

// Handle the login POST request
app.post('/', (req, res) => {
    const { username, password } = req.body;

    if (username && password) {
        console.log('Received credentials:', { username, password });

        // You can now process the credentials (e.g., check against a database)

        // Send a response to the client
        res.send('Credentials received successfully');
    } else {
        res.status(400).send('Username and password are required');
    }
});

// Start the server on 10.0.1.33
const PORT = 3000;
const HOST = '10.0.1.33'; // Server's IP address

app.listen(PORT, HOST, () => {
    console.log(`Server running at http://${HOST}:${PORT}`);
});
