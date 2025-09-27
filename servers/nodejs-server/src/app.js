const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const NoSQLInjection = require('./vulnerabilities/NoSQLInjection');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Swagger configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'WebSec-Lab Node.js API',
            version: '2.0.0',
            description: 'Node.js Web Security Testing Platform'
        },
        servers: [
            {
                url: `http://localhost:${PORT}`,
                description: 'Development server'
            }
        ]
    },
    apis: ['./src/app.js']
};

const specs = swaggerJsdoc(swaggerOptions);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Swagger UI
app.use('/swagger-ui', swaggerUi.serve, swaggerUi.setup(specs));
app.use('/docs', swaggerUi.serve, swaggerUi.setup(specs));
app.get('/swagger.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(specs);
});

// Basic routes
/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health Check
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Server health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: healthy
 *                 service:
 *                   type: string
 *                   example: websec-nodejs
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 */
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'websec-nodejs',
        timestamp: new Date().toISOString()
    });
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: Server Information
 *     tags: [Information]
 *     responses:
 *       200:
 *         description: Basic server information
 */
app.get('/', (req, res) => {
    res.json({
        message: 'WebSec-Lab Node.js Server',
        version: '2.0.0',
        endpoints: ['/health', '/vulnerabilities', '/swagger-ui', '/docs']
    });
});

// XSS Test Endpoints
/**
 * @swagger
 * /xss/vulnerable:
 *   get:
 *     summary: XSS - Vulnerable Endpoint
 *     tags: [XSS]
 *     parameters:
 *       - in: query
 *         name: input
 *         schema:
 *           type: string
 *         description: Input to test XSS vulnerability
 *     responses:
 *       200:
 *         description: XSS vulnerable response (HTML)
 */
app.get('/xss/vulnerable', (req, res) => {
    const input = req.query.input || '<script>alert("XSS")</script>';
    // 취약한 코드 - 직접 출력
    res.send(`<h1>User Input: ${input}</h1>`);
});

/**
 * @swagger
 * /xss/safe:
 *   get:
 *     summary: XSS - Safe Endpoint
 *     tags: [XSS]
 *     parameters:
 *       - in: query
 *         name: input
 *         schema:
 *           type: string
 *         description: Input to test (will be safely escaped)
 *     responses:
 *       200:
 *         description: XSS safe response (HTML with escaped input)
 */
app.get('/xss/safe', (req, res) => {
    const input = req.query.input || '<script>alert("XSS")</script>';
    // 안전한 코드 - HTML 이스케이프
    const escapeHtml = (text) => text.replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
    res.send(`<h1>User Input: ${escapeHtml(input)}</h1>`);
});

// NoSQL Injection Test Endpoints
const noSQLInjection = new NoSQLInjection();

app.get('/sql/vulnerable/login', async (req, res) => {
    try {
        const { username, password } = req.query;
        const payload = username || password || '{"$ne": null}';
        const target = username ? 'username' : 'password';

        const result = await noSQLInjection.executeVulnerableCode(payload, {
            test_type: 'login',
            target,
            username: username || 'admin',
            password: password || 'password'
        });

        res.json({
            success: true,
            data: result,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'vulnerable',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'vulnerable'
            }
        });
    }
});

app.get('/sql/safe/login', async (req, res) => {
    try {
        const { username, password } = req.query;
        const payload = username || password || 'admin';
        const target = username ? 'username' : 'password';

        const result = await noSQLInjection.executeSafeCode(payload, {
            test_type: 'login',
            target,
            username: username || 'admin',
            password: password || 'password'
        });

        res.json({
            success: true,
            data: result,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'safe',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'safe'
            }
        });
    }
});

app.get('/sql/vulnerable/search', async (req, res) => {
    try {
        const { query } = req.query;
        const payload = query || 'function() { return true; }';

        const result = await noSQLInjection.executeVulnerableCode(payload, {
            test_type: 'search'
        });

        res.json({
            success: true,
            data: result,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'vulnerable',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/sql/safe/search', async (req, res) => {
    try {
        const { query } = req.query;
        const payload = query || 'article';

        const result = await noSQLInjection.executeSafeCode(payload, {
            test_type: 'search'
        });

        res.json({
            success: true,
            data: result,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'nosql_injection',
                mode: 'safe',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Standard endpoints for dashboard compatibility
/**
 * @swagger
 * /vulnerabilities/xss:
 *   post:
 *     summary: Execute XSS Vulnerability Test
 *     tags: [Vulnerabilities]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               mode:
 *                 type: string
 *                 enum: [vulnerable, safe]
 *                 default: vulnerable
 *               payload:
 *                 type: string
 *                 default: '<script>alert("XSS")</script>'
 *     responses:
 *       200:
 *         description: XSS test result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                 metadata:
 *                   type: object
 */
app.post('/vulnerabilities/xss', (req, res) => {
    try {
        const { mode, payload } = req.body;
        const mode_safe = mode || 'vulnerable';
        const payload_safe = payload || '<script>alert("XSS")</script>';

        let result, attackSuccess;

        if (mode_safe === 'vulnerable') {
            // 취약한 코드 - 직접 출력
            result = `<h1>User Input: ${payload_safe}</h1>`;
            attackSuccess = payload_safe.includes('<script>') || payload_safe.includes('javascript:');
        } else {
            // 안전한 코드 - HTML 이스케이프
            const escapeHtml = (text) => text.replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
            result = `<h1>User Input: ${escapeHtml(payload_safe)}</h1>`;
            attackSuccess = false;
        }

        res.json({
            success: true,
            data: {
                result: result,
                vulnerability_detected: attackSuccess,
                payload_used: payload_safe,
                attack_success: attackSuccess,
                execution_time: '0.001s'
            },
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'xss',
                mode: mode_safe,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            metadata: {
                language: 'nodejs',
                vulnerability_type: 'xss',
                mode: req.body?.mode || 'vulnerable'
            }
        });
    }
});

app.use('/vulnerabilities', (req, res) => {
    res.json({
        message: 'WebSec-Lab Node.js Server',
        available: [
            'POST /vulnerabilities/xss',
            'GET /xss/vulnerable',
            'GET /xss/safe',
            'GET /sql/vulnerable/login',
            'GET /sql/safe/login',
            'GET /sql/vulnerable/search',
            'GET /sql/safe/search'
        ]
    });
});

app.listen(PORT, () => {
    console.log(`Node.js server running on port ${PORT}`);
});

module.exports = app;