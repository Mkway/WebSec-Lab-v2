const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic routes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'websec-nodejs',
        timestamp: new Date().toISOString()
    });
});

app.get('/', (req, res) => {
    res.json({
        message: 'WebSec-Lab Node.js Server',
        version: '2.0.0',
        endpoints: ['/health', '/vulnerabilities']
    });
});

// Placeholder for vulnerability routes
app.use('/vulnerabilities', (req, res) => {
    res.json({
        message: 'Vulnerability endpoints coming soon',
        available: []
    });
});

app.listen(PORT, () => {
    console.log(`Node.js server running on port ${PORT}`);
});

module.exports = app;