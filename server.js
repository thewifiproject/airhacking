// Import required modules
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

        // Send a response
        res.send('Credentials received successfully');
    } else {
        res.status(400).send('Username and password are required');
    }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
