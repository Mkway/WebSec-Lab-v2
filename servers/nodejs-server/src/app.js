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

// XSS Test Endpoints
app.get('/xss/vulnerable', (req, res) => {
    const input = req.query.input || '<script>alert("XSS")</script>';
    // 취약한 코드 - 직접 출력
    res.send(`<h1>User Input: ${input}</h1>`);
});

app.get('/xss/safe', (req, res) => {
    const input = req.query.input || '<script>alert("XSS")</script>';
    // 안전한 코드 - HTML 이스케이프
    const escapeHtml = (text) => text.replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
    res.send(`<h1>User Input: ${escapeHtml(input)}</h1>`);
});

app.use('/vulnerabilities', (req, res) => {
    res.json({
        message: 'WebSec-Lab Node.js Server',
        available: ['GET /xss/vulnerable', 'GET /xss/safe']
    });
});

app.listen(PORT, () => {
    console.log(`Node.js server running on port ${PORT}`);
});

module.exports = app;