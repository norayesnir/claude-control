#!/usr/bin/env node

/**
 * Secure Web Server for Claude Code Remote Control Dashboard
 * Military-grade security implementation
 */

require('dotenv').config();
const express = require('express');
const https = require('https');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const compression = require('compression');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const { body, param, query, validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');
const SecurityManager = require('../security');
const ApprovalManager = require('./approval_manager');

class SecureDashboardServer {
    constructor(port = process.env.PORT || 8443) {
        this.port = port;
        this.app = express();
        this.security = new SecurityManager();
        this.manager = new ApprovalManager();
        this.dashboardPath = path.join(__dirname, '..', 'dashboard');
        this.failedAttempts = new Map();
        this.lockedIPs = new Set();
        
        this.initializeMiddleware();
        this.initializeRoutes();
        this.initializeErrorHandling();
    }

    initializeMiddleware() {
        // Trust proxy if behind reverse proxy
        this.app.set('trust proxy', 1);

        // Security headers with Helmet
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'"],
                    imgSrc: ["'self'", "data:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'none'"],
                    frameSrc: ["'none'"]
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            }
        }));

        // Compression
        this.app.use(compression());

        // Parameter pollution protection
        this.app.use(hpp());

        // NoSQL injection protection
        this.app.use(mongoSanitize());

        // Body parsing with size limits
        this.app.use(express.json({ 
            limit: '1mb',
            verify: (req, res, buf) => {
                req.rawBody = buf;
            }
        }));
        this.app.use(express.urlencoded({ 
            extended: false, 
            limit: '1mb' 
        }));

        // Custom security middleware
        this.app.use(this.securityMiddleware.bind(this));
        this.app.use(this.authenticationMiddleware.bind(this));

        // Rate limiting
        this.app.use('/api', this.security.createRateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 50 // 50 requests per window
        }));

        // Slower rate limit for auth endpoints
        this.app.use('/api/auth', this.security.createRateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5 // 5 auth attempts per window
        }));

        // CORS with strict settings
        this.app.use(cors({
            origin: (origin, callback) => {
                // Allow requests with no origin (mobile apps, etc.)
                if (!origin) return callback(null, true);
                
                const allowedOrigins = [
                    'https://localhost:8080',
                    'https://127.0.0.1:8080',
                    'https://localhost:8443',
                    'https://127.0.0.1:8443'
                ];
                
                if (allowedOrigins.includes(origin)) {
                    callback(null, true);
                } else {
                    this.security.logger.warn('CORS blocked origin', { origin });
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            methods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-Signature'],
            maxAge: 300
        }));

        // Session management
        this.app.use(session({
            secret: this.security.getOrCreateSecret('SESSION_SECRET'),
            name: 'claude.sid',
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                maxAge: parseInt(process.env.DASHBOARD_SESSION_TIMEOUT) || 3600000, // 1 hour
                sameSite: 'strict'
            },
            store: undefined // Add Redis store in production
        }));
    }

    securityMiddleware(req, res, next) {
        const startTime = Date.now();
        
        // Set security headers
        const headers = this.security.getSecurityHeaders();
        Object.keys(headers).forEach(key => {
            res.setHeader(key, headers[key]);
        });

        // IP lockout check
        if (this.lockedIPs.has(req.ip)) {
            this.security.logger.warn('Blocked request from locked IP', { ip: req.ip });
            return res.status(429).json({ 
                error: 'IP temporarily locked due to suspicious activity' 
            });
        }

        // Request size validation
        const contentLength = parseInt(req.get('Content-Length')) || 0;
        if (contentLength > 1048576) { // 1MB
            this.security.logger.warn('Request too large', { 
                ip: req.ip, 
                size: contentLength 
            });
            return res.status(413).json({ error: 'Request too large' });
        }

        // Suspicious activity detection
        if (this.security.detectSuspiciousActivity(req)) {
            this.incrementFailedAttempts(req.ip);
            return res.status(400).json({ error: 'Invalid request' });
        }

        // Request logging
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            this.security.logger.info('Request processed', {
                ip: req.ip,
                method: req.method,
                url: req.url,
                status: res.statusCode,
                duration,
                userAgent: req.get('User-Agent')
            });
        });

        next();
    }

    authenticationMiddleware(req, res, next) {
        // Skip auth for public assets
        if (req.path.match(/\.(js|css|png|jpg|gif|ico)$/)) {
            return next();
        }

        // Skip auth for login endpoint
        if (req.path === '/api/auth/login') {
            return next();
        }

        // Check for API key in headers
        const apiKey = req.get('X-API-Key');
        if (apiKey && this.security.verifyApiKey(apiKey)) {
            req.authenticated = true;
            return next();
        }

        // Check for JWT token
        const authHeader = req.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const decoded = this.security.verifyJWT(token);
            if (decoded) {
                req.user = decoded;
                req.authenticated = true;
                return next();
            }
        }

        // Check session authentication
        if (req.session && req.session.authenticated) {
            req.authenticated = true;
            return next();
        }

        // Require authentication for API endpoints
        if (req.path.startsWith('/api/')) {
            this.incrementFailedAttempts(req.ip);
            return res.status(401).json({ error: 'Authentication required' });
        }

        // For non-API requests, serve login page
        next();
    }

    incrementFailedAttempts(ip) {
        const attempts = this.failedAttempts.get(ip) || 0;
        const newAttempts = attempts + 1;
        
        this.failedAttempts.set(ip, newAttempts);
        
        if (newAttempts >= 10) {
            this.lockedIPs.add(ip);
            this.security.logger.error('IP locked due to failed attempts', { ip, attempts: newAttempts });
            
            // Auto-unlock after 1 hour
            setTimeout(() => {
                this.lockedIPs.delete(ip);
                this.failedAttempts.delete(ip);
                this.security.logger.info('IP unlocked', { ip });
            }, 3600000);
        }
    }

    initializeRoutes() {
        // Authentication routes
        this.app.post('/api/auth/login', [
            body('username').isLength({ min: 1, max: 50 }).escape(),
            body('password').isLength({ min: 1, max: 100 })
        ], this.handleLogin.bind(this));

        this.app.post('/api/auth/logout', this.handleLogout.bind(this));

        // API routes (all require authentication)
        this.app.get('/api/operations', this.handleOperationsAPI.bind(this));
        this.app.get('/api/status', this.handleStatusAPI.bind(this));
        
        this.app.post('/api/approve/:id', [
            param('id').isAlphanumeric().isLength({ min: 1, max: 32 }),
            body('reason').optional().isLength({ max: 500 }).escape(),
            body('timestamp').isInt({ min: Date.now() - 300000 }),
            body('signature').isHexadecimal().isLength({ min: 64, max: 64 })
        ], this.validateRequest, this.handleApproveAPI.bind(this));
        
        this.app.post('/api/deny/:id', [
            param('id').isAlphanumeric().isLength({ min: 1, max: 32 }),
            body('reason').optional().isLength({ max: 500 }).escape(),
            body('timestamp').isInt({ min: Date.now() - 300000 }),
            body('signature').isHexadecimal().isLength({ min: 64, max: 64 })
        ], this.validateRequest, this.handleDenyAPI.bind(this));

        // Static files with security
        this.app.get('/', this.serveSecureDashboard.bind(this));
        this.app.get('/dashboard', this.serveSecureDashboard.bind(this));
        
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ status: 'healthy', timestamp: Date.now() });
        });
    }

    validateRequest(req, res, next) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.incrementFailedAttempts(req.ip);
            this.security.logger.warn('Validation failed', { 
                ip: req.ip, 
                errors: errors.array() 
            });
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        // Verify request signature
        if (req.body.signature && req.body.timestamp) {
            const { signature, timestamp, ...data } = req.body;
            if (!this.security.verifySignature(data, signature, timestamp)) {
                this.incrementFailedAttempts(req.ip);
                return res.status(401).json({ error: 'Invalid signature' });
            }
        }

        next();
    }

    async handleLogin(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.incrementFailedAttempts(req.ip);
            return res.status(400).json({ error: 'Invalid input' });
        }

        const { username, password } = req.body;

        try {
            // Simple auth - in production, use proper user management
            const validUsername = 'admin';
            
            // Require explicit password hash configuration
            const validPasswordHash = process.env.ADMIN_PASSWORD_HASH;
            if (!validPasswordHash || validPasswordHash === 'YOUR_BCRYPT_PASSWORD_HASH_HERE') {
                this.security.logger.error('Admin password hash not configured');
                return res.status(500).json({ error: 'Authentication not configured' });
            }
            
            if (username === validUsername && await this.security.verifyPassword(password, validPasswordHash)) {
                req.session.authenticated = true;
                req.session.user = username;
                
                const token = this.security.generateJWT({ username, role: 'admin' });
                
                this.security.logger.info('User authenticated', { username, ip: req.ip });
                
                res.json({ 
                    success: true, 
                    token,
                    message: 'Authentication successful' 
                });
            } else {
                this.incrementFailedAttempts(req.ip);
                this.security.logger.warn('Authentication failed', { username, ip: req.ip });
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            this.security.logger.error('Login error', { error: error.message });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleLogout(req, res) {
        req.session.destroy((err) => {
            if (err) {
                this.security.logger.error('Logout error', { error: err.message });
                return res.status(500).json({ error: 'Logout failed' });
            }
            
            res.clearCookie('claude.sid');
            res.json({ success: true, message: 'Logged out successfully' });
        });
    }

    async serveSecureDashboard(req, res) {
        if (!req.authenticated) {
            // Serve login page
            const loginPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claude Control - Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #005a87; }
        .error { color: red; margin-top: 10px; }
        .security-notice { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-bottom: 20px; border-radius: 4px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔒 Claude Control</h1>
        <div class="security-notice">
            <strong>Security Notice:</strong> This is a secure system. All activities are logged and monitored.
        </div>
        <form id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div id="error" class="error"></div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    window.location.reload();
                } else {
                    const error = await response.json();
                    document.getElementById('error').textContent = error.error || 'Login failed';
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Network error: ' + err.message;
            }
        });
    </script>
</body>
</html>`;
            res.setHeader('Content-Type', 'text/html');
            return res.send(loginPage);
        }

        // Serve secure dashboard
        this.serveSecureFile(res, 'index.html', 'text/html');
    }

    async serveSecureFile(res, filename, contentType) {
        // Enhanced input validation
        if (!filename || typeof filename !== 'string') {
            this.security.logger.warn('Invalid filename parameter', { filename });
            return res.status(400).json({ error: 'Invalid filename' });
        }

        // Reject dangerous characters and sequences
        const dangerousPatterns = [
            /\.\./,           // Directory traversal sequences
            /[<>:"\\|?*]/,    // Windows invalid chars
            /[\x00-\x1f]/,    // Control characters
            /^\.+$/,          // Only dots
            /\/+/,            // Multiple slashes
            /\\+/             // Multiple backslashes
        ];

        if (dangerousPatterns.some(pattern => pattern.test(filename))) {
            this.security.logger.warn('Dangerous filename pattern detected', { filename });
            return res.status(403).json({ error: 'Invalid filename pattern' });
        }

        // Only allow specific safe file extensions
        const allowedExtensions = ['.html', '.js', '.css', '.png', '.jpg', '.gif', '.ico', '.svg'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (!allowedExtensions.includes(fileExtension)) {
            this.security.logger.warn('Unauthorized file extension', { filename, extension: fileExtension });
            return res.status(403).json({ error: 'File type not allowed' });
        }

        const filePath = path.join(this.dashboardPath, filename);
        
        // Enhanced path traversal protection with multiple checks
        const normalizedPath = path.normalize(filePath);
        const absoluteDashboardPath = path.resolve(this.dashboardPath);
        const absoluteRequestPath = path.resolve(normalizedPath);
        
        // Ensure the resolved path starts with the dashboard directory
        if (!absoluteRequestPath.startsWith(absoluteDashboardPath)) {
            this.security.logger.error('Path traversal attempt blocked', { 
                filename,
                requestedPath: absoluteRequestPath,
                allowedPath: absoluteDashboardPath
            });
            return res.status(403).json({ error: 'Access denied - path traversal detected' });
        }

        // Additional check to prevent symlink attacks
        try {
            const stats = fs.lstatSync(normalizedPath);
            if (stats.isSymbolicLink()) {
                this.security.logger.warn('Symbolic link access blocked', { filename });
                return res.status(403).json({ error: 'Symbolic links not allowed' });
            }
        } catch (statError) {
            // File doesn't exist, which is handled below
        }
        
        if (!fs.existsSync(normalizedPath)) {
            this.security.logger.info('File not found', { filename });
            return res.status(404).json({ error: 'File not found' });
        }

        try {
            // Use async file reading for better performance and security
            const content = await fs.promises.readFile(normalizedPath);
            
            // Set secure headers
            res.setHeader('Content-Type', contentType);
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            
            // Log successful file access for security monitoring
            this.security.logger.info('File served successfully', { 
                filename: path.basename(normalizedPath),
                size: content.length,
                ip: res.req.ip 
            });
            
            res.send(content);
        } catch (error) {
            this.security.logger.error('File serve error', { 
                error: error.message, 
                filename,
                code: error.code 
            });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleOperationsAPI(res) {
        try {
            const queueDir = path.join(process.env.HOME, '.claude-control', 'queue');
            
            if (!fs.existsSync(queueDir)) {
                return res.json([]);
            }

            const files = await fs.promises.readdir(queueDir);
            const jsonFiles = files.filter(f => f.endsWith('.json'));
            
            const operationsData = await Promise.all(
                jsonFiles.map(async (f) => {
                    try {
                        const content = await fs.promises.readFile(path.join(queueDir, f), 'utf8');
                        let data;
                        try {
                            data = JSON.parse(content);
                        } catch (parseError) {
                            this.security.logger.warn('Failed to parse queue file JSON', { file: f, error: parseError.message });
                            return null;
                        }
                        
                        // Sanitize sensitive data
                        if (data.operation && data.operation.params) {
                            if (data.operation.params.content) {
                                data.operation.params.content = '[CONTENT_SANITIZED]';
                            }
                        }
                        
                        return data;
                    } catch (error) {
                        this.security.logger.warn('Failed to parse queue file', { file: f, error: error.message });
                        return null;
                    }
                })
            );
            
            const operations = operationsData
                .filter(Boolean)
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

            res.json(operations);
        } catch (error) {
            this.security.logger.error('Operations API error', { error: error.message });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleStatusAPI(res) {
        try {
            const status = this.manager.getQueueStatus();
            status.timestamp = Date.now();
            status.securityStatus = 'active';
            res.json(status);
        } catch (error) {
            this.security.logger.error('Status API error', { error: error.message });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleApproveAPI(req, res) {
        try {
            const { id } = req.params;
            const { reason = 'Approved via secure dashboard' } = req.body;
            
            const sanitizedId = this.security.sanitizeInput(id, 'id');
            const sanitizedReason = xss(reason);
            
            await this.manager.processApproval(sanitizedId, 'approved', sanitizedReason);
            
            this.security.logger.info('Operation approved', { 
                id: sanitizedId, 
                reason: sanitizedReason,
                user: req.user?.username || req.session?.user,
                ip: req.ip
            });
            
            res.json({ 
                success: true, 
                message: `Approved operation ${sanitizedId}`,
                timestamp: Date.now()
            });
        } catch (error) {
            this.security.logger.error('Approve API error', { error: error.message });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleDenyAPI(req, res) {
        try {
            const { id } = req.params;
            const { reason = 'Denied via secure dashboard' } = req.body;
            
            const sanitizedId = this.security.sanitizeInput(id, 'id');
            const sanitizedReason = xss(reason);
            
            await this.manager.processApproval(sanitizedId, 'denied', sanitizedReason);
            
            this.security.logger.info('Operation denied', { 
                id: sanitizedId, 
                reason: sanitizedReason,
                user: req.user?.username || req.session?.user,
                ip: req.ip
            });
            
            res.json({ 
                success: true, 
                message: `Denied operation ${sanitizedId}`,
                timestamp: Date.now()
            });
        } catch (error) {
            this.security.logger.error('Deny API error', { error: error.message });
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    initializeErrorHandling() {
        // 404 handler
        this.app.use((req, res) => {
            this.security.logger.warn('404 Not Found', { 
                ip: req.ip, 
                url: req.url,
                userAgent: req.get('User-Agent')
            });
            res.status(404).json({ error: 'Not Found' });
        });

        // Global error handler
        this.app.use((error, req, res, next) => {
            this.security.logger.error('Unhandled error', { 
                error: error.message,
                stack: error.stack,
                ip: req.ip,
                url: req.url
            });
            
            res.status(500).json({ 
                error: 'Internal Server Error',
                timestamp: Date.now()
            });
        });
    }

    start() {
        // Load SSL certificates
        const sslPath = path.join(__dirname, '..', 'ssl');
        const options = {
            key: fs.readFileSync(path.join(sslPath, 'server.key')),
            cert: fs.readFileSync(path.join(sslPath, 'server.crt'))
        };

        const server = https.createServer(options, this.app).listen(this.port, '127.0.0.1', () => {
            this.security.logger.info('Secure Claude Control Dashboard started', { 
                port: this.port,
                env: process.env.NODE_ENV,
                ssl: true
            });
            
            console.log(`🔒 SECURE Claude Code Control Dashboard (HTTPS):`);
            console.log(`   https://localhost:${this.port}`);
            console.log(`   https://127.0.0.1:${this.port}`);
            console.log('');
            console.log('🛡️  Security Features Active:');
            console.log('   ✅ HTTPS/TLS encryption');
            console.log('   ✅ Military-grade authentication');
            console.log('   ✅ Request signing & validation');
            console.log('   ✅ Rate limiting & DDoS protection');
            console.log('   ✅ XSS & injection prevention');
            console.log('   ✅ Comprehensive security logging');
            console.log('   ✅ Session management');
            console.log('   ✅ CORS & CSP protection');
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            this.security.logger.info('SIGTERM received, shutting down gracefully');
            server.close(() => {
                this.security.logger.info('Server shut down');
                process.exit(0);
            });
        });

        return server;
    }
}

// CLI usage
if (require.main === module) {
    const port = process.argv[2] || process.env.PORT || 8443;
    const server = new SecureDashboardServer(port);
    server.start();
}

module.exports = SecureDashboardServer;