#!/usr/bin/env node

/**
 * Security Module for Claude Control
 * Provides comprehensive security utilities and middleware
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

class SecurityManager {
    constructor() {
        this.API_KEYS = new Map();
        this.logger = this.createSecureLogger();
        this.JWT_SECRET = this.getOrCreateSecret('JWT_SECRET');
        this.ENCRYPTION_KEY = this.getOrCreateSecret('ENCRYPTION_KEY', 32);
        this.initializeSecurity();
    }

    // Secret Management
    getOrCreateSecret(name, length = 64) {
        const secretsFile = path.join(__dirname, '.secrets.json');
        let secrets = {};
        
        if (fs.existsSync(secretsFile)) {
            try {
                secrets = JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
            } catch (error) {
                this.logger.error('Failed to read secrets file', { error: error.message });
            }
        }

        if (!secrets[name]) {
            secrets[name] = crypto.randomBytes(length).toString('hex');
            fs.writeFileSync(secretsFile, JSON.stringify(secrets, null, 2), { mode: 0o600 });
            this.logger.info(`Generated new secret: ${name}`);
        }

        return secrets[name];
    }

    // Secure Logging
    createSecureLogger() {
        const logFormat = winston.format.combine(
            winston.format.timestamp(),
            winston.format.errors({ stack: true }),
            winston.format.json(),
            winston.format.printf(({ timestamp, level, message, ...meta }) => {
                // Sanitize sensitive data from logs
                const sanitized = this.sanitizeLogData({ ...meta });
                return JSON.stringify({ timestamp, level, message, ...sanitized });
            })
        );

        return winston.createLogger({
            level: 'info',
            format: logFormat,
            transports: [
                new DailyRotateFile({
                    filename: path.join(__dirname, 'logs', 'security-%DATE%.log'),
                    datePattern: 'YYYY-MM-DD',
                    zippedArchive: true,
                    maxSize: '20m',
                    maxFiles: '30d'
                }),
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    )
                })
            ],
            exceptionHandlers: [
                new DailyRotateFile({
                    filename: path.join(__dirname, 'logs', 'exceptions-%DATE%.log'),
                    datePattern: 'YYYY-MM-DD'
                })
            ]
        });
    }

    sanitizeLogData(data) {
        const sensitiveKeys = ['password', 'token', 'secret', 'key', 'authorization', 'jwt', 'signature', 'hash'];
        const sensitivePatterns = [
            /\b[A-Za-z0-9]{64,}\b/,          // Long hex strings (likely secrets)
            /[A-Za-z0-9+/]{40,}={0,2}/,      // Base64 encoded data
            /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, // Bearer tokens
            /[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}/, // UUIDs
            /ssh-[a-zA-Z0-9]+\s+[A-Za-z0-9+/]+=*/, // SSH keys
            /-----BEGIN [A-Z ]+-----/, // PEM format keys/certs
        ];
        
        function deepSanitize(obj) {
            if (typeof obj === 'string') {
                // Check for sensitive patterns in string values
                for (const pattern of sensitivePatterns) {
                    if (pattern.test(obj)) {
                        return '[REDACTED_SENSITIVE_DATA]';
                    }
                }
                return obj;
            }
            
            if (Array.isArray(obj)) {
                return obj.map(item => deepSanitize(item));
            }
            
            if (obj && typeof obj === 'object') {
                const sanitizedObj = {};
                for (const [key, value] of Object.entries(obj)) {
                    const lowerKey = key.toLowerCase();
                    
                    // Check if key indicates sensitive data
                    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
                        sanitizedObj[key] = '[REDACTED]';
                    } else {
                        sanitizedObj[key] = deepSanitize(value);
                    }
                }
                return sanitizedObj;
            }
            
            return obj;
        }
        
        return deepSanitize({ ...data });
    }

    // Rate Limiting & DDoS Protection
    createRateLimit(options = {}) {
        return rateLimit({
            windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
            max: options.max || 100, // limit each IP to 100 requests per windowMs
            message: {
                error: 'Too many requests from this IP, please try again later.',
                retryAfter: Math.ceil(options.windowMs / 1000) || 900
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => {
                // No automatic exemptions - all requests are rate limited
                return false;
            },
            handler: (req, res, next, options) => {
                this.logger.warn('Rate limit exceeded', {
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    path: req.path
                });
                res.status(options.statusCode).json({
                    error: 'Too many requests from this IP, please try again later.',
                    retryAfter: Math.ceil(options.windowMs / 1000)
                });
            }
        });
    }

    createSlowDown(options = {}) {
        return slowDown({
            windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
            delayAfter: options.delayAfter || 50, // allow 50 requests per windowMs without delay
            delayMs: options.delayMs || 500, // add 500ms delay per request after delayAfter
            maxDelayMs: options.maxDelayMs || 10000, // max delay of 10 seconds
            skipFailedRequests: false,
            skipSuccessfulRequests: false
        });
    }

    // Authentication & Authorization
    async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    generateJWT(payload, expiresIn = '24h') {
        return jwt.sign(payload, this.JWT_SECRET, { 
            expiresIn,
            issuer: 'claude-control',
            audience: 'claude-control-client'
        });
    }

    verifyJWT(token) {
        try {
            return jwt.verify(token, this.JWT_SECRET, {
                issuer: 'claude-control',
                audience: 'claude-control-client'
            });
        } catch (error) {
            this.logger.warn('JWT verification failed', { error: error.message });
            return null;
        }
    }

    generateApiKey() {
        const key = crypto.randomBytes(32).toString('hex');
        const keyId = crypto.randomBytes(8).toString('hex');
        const hashedKey = crypto.createHash('sha256').update(key).digest('hex');
        
        this.API_KEYS.set(keyId, {
            hash: hashedKey,
            created: new Date(),
            lastUsed: null,
            permissions: ['read', 'write']
        });
        
        this.logger.info('New API key generated', { keyId });
        return `${keyId}.${key}`;
    }

    verifyApiKey(apiKey) {
        if (!apiKey || !apiKey.includes('.')) return false;
        
        const [keyId, key] = apiKey.split('.');
        const storedKey = this.API_KEYS.get(keyId);
        
        if (!storedKey) return false;
        
        const hashedKey = crypto.createHash('sha256').update(key).digest('hex');
        
        if (storedKey.hash === hashedKey) {
            storedKey.lastUsed = new Date();
            return true;
        }
        
        this.logger.warn('Invalid API key attempt', { keyId });
        return false;
    }

    // Encryption (Secure AES-256-GCM Implementation)
    encrypt(text) {
        try {
            const iv = crypto.randomBytes(16);
            const key = Buffer.from(this.ENCRYPTION_KEY, 'hex');
            
            if (key.length !== 32) {
                throw new Error('Invalid encryption key length. Must be 32 bytes (256 bits).');
            }
            
            const cipher = crypto.createCipherGCM('aes-256-gcm', key);
            cipher.setIVLength(16);
            cipher.setAAD(Buffer.from('claude-control-v2'));
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            return {
                iv: iv.toString('hex'),
                encryptedData: encrypted,
                authTag: authTag.toString('hex'),
                version: 2
            };
        } catch (error) {
            this.logger.error('Encryption failed', { error: error.message });
            throw new Error('Encryption failed: ' + error.message);
        }
    }

    decrypt(encryptedObj) {
        try {
            const key = Buffer.from(this.ENCRYPTION_KEY, 'hex');
            
            if (key.length !== 32) {
                throw new Error('Invalid encryption key length. Must be 32 bytes (256 bits).');
            }
            
            const decipher = crypto.createDecipherGCM('aes-256-gcm', key);
            decipher.setIV(Buffer.from(encryptedObj.iv, 'hex'));
            decipher.setAAD(Buffer.from(encryptedObj.version === 2 ? 'claude-control-v2' : 'claude-control'));
            decipher.setAuthTag(Buffer.from(encryptedObj.authTag, 'hex'));
            
            let decrypted = decipher.update(encryptedObj.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            this.logger.error('Decryption failed', { error: error.message });
            throw new Error('Decryption failed: Invalid data or key');
        }
    }

    // Input Validation & Sanitization
    sanitizeInput(input, type = 'string') {
        if (typeof input !== 'string') {
            input = String(input);
        }

        // Basic XSS prevention
        input = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
        input = input.replace(/javascript:/gi, '');
        input = input.replace(/on\w+\s*=/gi, '');

        switch (type) {
            case 'filename':
                return input.replace(/[^a-zA-Z0-9._-]/g, '').substring(0, 255);
            case 'path':
                return path.normalize(input).replace(/\.\./g, '');
            case 'command':
                return input.replace(/[;&|`$(){}[\]]/g, '');
            case 'id':
                return input.replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
            default:
                return input.substring(0, 1000);
        }
    }

    validateInput(input, rules) {
        const errors = [];
        
        for (const [field, rule] of Object.entries(rules)) {
            const value = input[field];
            
            if (rule.required && (!value || value.toString().trim() === '')) {
                errors.push(`${field} is required`);
                continue;
            }
            
            if (value && rule.minLength && value.length < rule.minLength) {
                errors.push(`${field} must be at least ${rule.minLength} characters`);
            }
            
            if (value && rule.maxLength && value.length > rule.maxLength) {
                errors.push(`${field} must be at most ${rule.maxLength} characters`);
            }
            
            if (value && rule.pattern && !rule.pattern.test(value)) {
                errors.push(`${field} has invalid format`);
            }
        }
        
        return errors;
    }

    // Security Headers
    getSecurityHeaders() {
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': this.getCSP(),
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        };
    }

    getCSP() {
        return [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "font-src 'self'",
            "object-src 'none'",
            "media-src 'none'",
            "frame-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ].join('; ');
    }

    // Request Signing
    signRequest(data, timestamp = Date.now()) {
        const payload = JSON.stringify({ data, timestamp });
        return crypto.createHmac('sha256', this.JWT_SECRET).update(payload).digest('hex');
    }

    verifySignature(data, signature, timestamp, maxAge = 300000) {
        const now = Date.now();
        if (now - timestamp > maxAge) {
            this.logger.warn('Request signature expired', { timestamp, now });
            return false;
        }

        const expectedSignature = this.signRequest(data, timestamp);
        const isValid = crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );

        if (!isValid) {
            this.logger.warn('Invalid request signature detected', { 
                timestamp,
                signatureValid: false,
                requestAge: now - timestamp 
            });
        }

        return isValid;
    }

    // Security Monitoring
    detectSuspiciousActivity(req) {
        const suspiciousPatterns = [
            /\.\./,  // Path traversal
            /<script/i,  // XSS attempts
            /union.*select/i,  // SQL injection
            /exec\(/i,  // Code injection
            /eval\(/i,  // Code injection
            /system\(/i,  // System calls
            /passthru\(/i,  // Command execution
            /shell_exec\(/i,  // Command execution
        ];

        const requestData = JSON.stringify({
            url: req.url,
            query: req.query,
            body: req.body,
            headers: req.headers
        });

        for (const pattern of suspiciousPatterns) {
            if (pattern.test(requestData)) {
                this.logger.error('Suspicious activity detected', {
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    url: req.url,
                    pattern: pattern.toString()
                });
                return true;
            }
        }

        return false;
    }

    // Initialize security measures
    initializeSecurity() {
        // Create logs directory
        const logsDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }

        // Set secure file permissions
        try {
            fs.chmodSync(path.join(__dirname, '.secrets.json'), 0o600);
            fs.chmodSync(logsDir, 0o750);
        } catch (error) {
            // Ignore if files don't exist yet
        }

        this.logger.info('Security manager initialized');
    }
}

module.exports = SecurityManager;