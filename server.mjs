import express from 'express';
import bodyParser from 'body-parser';
import chalk from 'chalk';
import dotenv from 'dotenv';

// Load environment variables from a .env file (if present)
dotenv.config();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/', (req, res) => {
    const { hostname, ip } = req.body;

    if (!hostname || !ip) {
        return res.status(400).send('Hostname and IP address are required');
    }

    console.log('Received data:');
    console.log('Hostname:', hostname);
    console.log('IP Address:', ip);

    res.send('Data received successfully');
});

// Use 0.0.0.0 (listen on all interfaces) or localhost (127.0.0.1)
const PORT = process.env.PORT || 3000;
const IP_ADDRESS = process.env.IP_ADDRESS || '0.0.0.0';  // Default to 0.0.0.0 if not specified

app.listen(PORT, IP_ADDRESS, () => {
    console.log(chalk.green(`Server is running on http://${IP_ADDRESS}:${PORT}`));
});
