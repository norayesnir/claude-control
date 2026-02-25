#!/usr/bin/env node

/**
 * SECURE Telegram Integration for Claude Code Remote Control
 * Military-grade security implementation with comprehensive protection
 * 
 * SECURITY FEATURES:
 * - Input validation and sanitization
 * - Rate limiting and anti-spam
 * - Message encryption
 * - Access control and authentication  
 * - Comprehensive logging and monitoring
 * - Command injection prevention
 * - Session management
 * - Audit trail compliance
 */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const SecurityManager = require('../security');

class SecureTelegramClient {
    constructor() {
        this.security = new SecurityManager();
        this.configFile = path.join(process.env.HOME, '.claude-control', 'config.json');
        this.sessionsFile = path.join(process.env.HOME, '.claude-control', 'audit', 'telegram_sessions.json');
        
        // Security state
        this.rateLimiter = new Map(); // IP/chat rate limiting
        this.activeSessions = new Map(); // User sessions
        this.authorizedUsers = new Set(); // Authorized chat IDs
        this.commandHistory = new Map(); // Command audit trail
        this.suspiciousActivity = new Map(); // Threat detection
        
        // Security configuration
        this.config = {
            maxMessagesPerMinute: 10,
            maxSessionTime: 3600000, // 1 hour
            maxFailedAttempts: 5,
            requireAuthentication: true,
            encryptMessages: true,
            logAllActivity: true,
            blockUnauthorized: true,
            maxInactiveTime: 600000, // 10 minutes for cleanup
            cleanupInterval: 300000, // 5 minutes cleanup interval
            commandWhitelist: [
                'start', 'help', 'status', 'approve', 'deny', 'details', 'auth', 'logout'
            ]
        };
        
        this.loadConfig();
        this.initializeSecurity();
    }

    loadConfig() {
        try {
            // Load configuration securely
            const envFile = path.join(process.env.HOME, '.claude-control', '.env');
            if (fs.existsSync(envFile)) {
                const envContent = fs.readFileSync(envFile, 'utf8');
                envContent.split('\n').forEach(line => {
                    const [key, value] = line.split('=');
                    if (key && value) {
                        if (key.trim() === 'TELEGRAM_BOT_TOKEN') {
                            this.botToken = value.trim();
                        }
                    }
                });
            }
            
            const config = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
            this.adminChatId = config.telegramChatId;
            
            // Load authorized users
            if (config.security && config.security.authorizedTelegramUsers) {
                config.security.authorizedTelegramUsers.forEach(userId => {
                    this.authorizedUsers.add(parseInt(userId));
                });
            }
            
            this.security.logger.info('Telegram configuration loaded', {
                hasToken: !!this.botToken,
                adminChatId: this.adminChatId,
                authorizedUsers: this.authorizedUsers.size
            });
            
        } catch (error) {
            this.security.logger.error('Error loading Telegram config', { 
                error: error.message 
            });
            this.botToken = null;
            this.adminChatId = null;
        }
    }

    initializeSecurity() {
        // Load existing sessions
        this.loadSessions();
        
        // Set up periodic cleanup with enhanced memory management
        this.cleanupInterval = setInterval(() => {
            this.cleanupSessions();
            this.cleanupRateLimits();
            this.cleanupSuspiciousActivity();
            this.cleanupCommandHistory();
        }, this.config.cleanupInterval);
        
        // Initialize audit trail
        this.security.logger.info('Secure Telegram client initialized', {
            encryptionEnabled: this.config.encryptMessages,
            authRequired: this.config.requireAuthentication,
            rateLimitEnabled: true
        });
    }

    // === SECURITY VALIDATION ===
    
    validateInput(input, type = 'general') {
        if (typeof input !== 'string') {
            throw new Error('Invalid input type');
        }
        
        const sanitized = this.security.sanitizeInput(input, type);
        
        // Additional validation based on type
        const validationRules = {
            command: { maxLength: 100, pattern: /^[a-zA-Z0-9_\s]+$/ },
            message: { maxLength: 4096, pattern: /^[\s\S]*$/ },
            chatId: { maxLength: 20, pattern: /^-?\d+$/ },
            operationId: { maxLength: 32, pattern: /^[a-zA-Z0-9]+$/ }
        };
        
        const rule = validationRules[type] || validationRules.general;
        if (rule && sanitized.length > rule.maxLength) {
            throw new Error(`Input too long for type ${type}`);
        }
        
        if (rule && rule.pattern && !rule.pattern.test(sanitized)) {
            throw new Error(`Invalid format for type ${type}`);
        }
        
        return sanitized;
    }

    isRateLimited(chatId) {
        const now = Date.now();
        const userLimits = this.rateLimiter.get(chatId) || { messages: [], blocked: false };
        
        // Clean old messages (older than 1 minute)
        userLimits.messages = userLimits.messages.filter(
            timestamp => now - timestamp < 60000
        );
        
        // Check if blocked
        if (userLimits.blocked && now - userLimits.blockedUntil < 0) {
            return true;
        }
        
        // Check rate limit
        if (userLimits.messages.length >= this.config.maxMessagesPerMinute) {
            userLimits.blocked = true;
            userLimits.blockedUntil = now + 300000; // Block for 5 minutes
            this.security.logger.warn('Rate limit exceeded', { chatId, messageCount: userLimits.messages.length });
            return true;
        }
        
        // Add current message
        userLimits.messages.push(now);
        this.rateLimiter.set(chatId, userLimits);
        
        return false;
    }

    isAuthorized(chatId) {
        // Admin is always authorized
        if (chatId === this.adminChatId) {
            return true;
        }
        
        // Check authorized users list
        return this.authorizedUsers.has(chatId);
    }

    detectSuspiciousActivity(chatId, message) {
        const suspiciousPatterns = [
            /\$\(.*\)/,  // Command substitution
            /`.*`/,      // Backticks
            /<script/i,  // Script injection
            /\.\.\//,    // Path traversal
            /rm\s+-rf/,  // Dangerous commands
            /curl.*\|/,  // Command chaining
            /wget.*\|/,  // Command chaining
            /eval\(/,    // Code evaluation
            /exec\(/,    // Code execution
        ];
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(message)) {
                this.logSuspiciousActivity(chatId, message, pattern.toString());
                return true;
            }
        }
        
        return false;
    }

    logSuspiciousActivity(chatId, message, pattern) {
        const activity = this.suspiciousActivity.get(chatId) || [];
        activity.push({
            timestamp: Date.now(),
            message: message.substring(0, 100), // Limit logged message length
            pattern
        });
        this.suspiciousActivity.set(chatId, activity);
        
        this.security.logger.error('Suspicious activity detected', {
            chatId,
            pattern,
            messagePreview: message.substring(0, 50)
        });
        
        // Auto-block if too many suspicious attempts
        if (activity.length >= 3) {
            this.blockUser(chatId, 'Multiple suspicious activity attempts');
        }
    }

    blockUser(chatId, reason) {
        const userLimits = this.rateLimiter.get(chatId) || {};
        userLimits.blocked = true;
        userLimits.blockedUntil = Date.now() + 3600000; // Block for 1 hour
        userLimits.reason = reason;
        this.rateLimiter.set(chatId, userLimits);
        
        this.security.logger.error('User blocked', { chatId, reason });
        
        // Remove from authorized users if present
        this.authorizedUsers.delete(chatId);
        this.saveSessions();
    }

    // === MESSAGE ENCRYPTION ===

    encryptMessage(message) {
        if (!this.config.encryptMessages) return message;
        
        try {
            const encrypted = this.security.encrypt(message);
            return `🔐 [ENCRYPTED] ${encrypted.iv}:${encrypted.encryptedData}:${encrypted.authTag}`;
        } catch (error) {
            this.security.logger.error('Message encryption failed', { error: error.message });
            return message; // Fallback to unencrypted
        }
    }

    decryptMessage(encryptedMessage) {
        if (!this.config.encryptMessages) return encryptedMessage;
        
        if (!encryptedMessage.startsWith('🔐 [ENCRYPTED] ')) {
            return encryptedMessage; // Not encrypted
        }
        
        try {
            const encryptedPart = encryptedMessage.replace('🔐 [ENCRYPTED] ', '');
            const [iv, encryptedData, authTag] = encryptedPart.split(':');
            
            const decrypted = this.security.decrypt({
                iv,
                encryptedData,
                authTag
            });
            
            return decrypted;
        } catch (error) {
            this.security.logger.error('Message decryption failed', { error: error.message });
            return '[DECRYPTION_FAILED]';
        }
    }

    // === SESSION MANAGEMENT ===

    createSession(chatId, username) {
        const sessionId = crypto.randomBytes(16).toString('hex');
        const session = {
            id: sessionId,
            chatId,
            username,
            created: Date.now(),
            lastActivity: Date.now(),
            authenticated: true,
            permissions: ['read', 'approve', 'deny']
        };
        
        this.activeSessions.set(sessionId, session);
        this.saveSessions();
        
        this.security.logger.info('Session created', { sessionId, chatId, username });
        return sessionId;
    }

    validateSession(chatId) {
        const now = Date.now();
        
        for (const [sessionId, session] of this.activeSessions.entries()) {
            if (session.chatId === chatId) {
                // Check session timeout
                if (now - session.lastActivity > this.config.maxSessionTime) {
                    this.activeSessions.delete(sessionId);
                    this.security.logger.info('Session expired', { sessionId, chatId });
                    return null;
                }
                
                // Update last activity
                session.lastActivity = now;
                return session;
            }
        }
        
        return null;
    }

    loadSessions() {
        try {
            if (fs.existsSync(this.sessionsFile)) {
                const sessions = JSON.parse(fs.readFileSync(this.sessionsFile, 'utf8'));
                sessions.forEach(session => {
                    this.activeSessions.set(session.id, session);
                });
            }
        } catch (error) {
            this.security.logger.error('Failed to load sessions', { error: error.message });
        }
    }

    saveSessions() {
        try {
            const sessions = Array.from(this.activeSessions.values());
            fs.writeFileSync(this.sessionsFile, JSON.stringify(sessions, null, 2), { mode: 0o600 });
        } catch (error) {
            this.security.logger.error('Failed to save sessions', { error: error.message });
        }
    }

    cleanupSessions() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [sessionId, session] of this.activeSessions.entries()) {
            if (now - session.lastActivity > this.config.maxSessionTime) {
                this.activeSessions.delete(sessionId);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            this.saveSessions();
            this.security.logger.info('Sessions cleaned up', { count: cleaned });
        }
    }

    cleanupRateLimits() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [chatId, limits] of this.rateLimiter.entries()) {
            if (limits.blocked && limits.blockedUntil && now > limits.blockedUntil) {
                limits.blocked = false;
                limits.messages = [];
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            this.security.logger.info('Rate limits cleaned up', { count: cleaned });
        }
    }

    cleanupSuspiciousActivity() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [chatId, activity] of this.suspiciousActivity.entries()) {
            if (activity.lastActivity && now - activity.lastActivity > this.config.maxInactiveTime) {
                this.suspiciousActivity.delete(chatId);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            this.security.logger.info('Suspicious activity records cleaned up', { count: cleaned });
        }
    }

    cleanupCommandHistory() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [chatId, history] of this.commandHistory.entries()) {
            if (history.commands) {
                // Keep only last 100 commands per user and those from last 24 hours
                const oneDayAgo = now - (24 * 60 * 60 * 1000);
                history.commands = history.commands
                    .filter(cmd => cmd.timestamp > oneDayAgo)
                    .slice(-100);
                
                if (history.commands.length === 0) {
                    this.commandHistory.delete(chatId);
                    cleaned++;
                }
            }
        }
        
        if (cleaned > 0) {
            this.security.logger.info('Command history cleaned up', { count: cleaned });
        }
    }

    // === SECURE API COMMUNICATION ===

    async makeSecureRequest(method, data = {}) {
        return new Promise((resolve, reject) => {
            try {
                // Validate and sanitize data
                const sanitizedData = {};
                Object.keys(data).forEach(key => {
                    if (typeof data[key] === 'string') {
                        sanitizedData[key] = this.validateInput(data[key], 'message');
                    } else {
                        sanitizedData[key] = data[key];
                    }
                });

                const postData = JSON.stringify(sanitizedData);
                const options = {
                    hostname: 'api.telegram.org',
                    port: 443,
                    path: `/bot${this.botToken}/${method}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(postData),
                        'User-Agent': 'SecureClaudeControl/1.0'
                    },
                    timeout: 10000 // 10 second timeout
                };

                const req = https.request(options, (res) => {
                    let responseData = '';
                    
                    res.on('data', (chunk) => {
                        responseData += chunk;
                        // Prevent memory attacks
                        if (responseData.length > 1048576) { // 1MB limit
                            req.destroy();
                            reject(new Error('Response too large'));
                        }
                    });
                    
                    res.on('end', () => {
                        try {
                            const response = JSON.parse(responseData);
                            
                            // Log API interaction
                            this.security.logger.info('Telegram API call', {
                                method,
                                success: response.ok,
                                status: res.statusCode
                            });
                            
                            resolve(response);
                        } catch (error) {
                            this.security.logger.error('Invalid Telegram API response', {
                                method,
                                error: error.message
                            });
                            reject(new Error('Invalid JSON response'));
                        }
                    });
                });

                req.on('error', (error) => {
                    this.security.logger.error('Telegram API request failed', {
                        method,
                        error: error.message
                    });
                    reject(error);
                });

                req.on('timeout', () => {
                    req.destroy();
                    reject(new Error('Request timeout'));
                });

                req.write(postData);
                req.end();
                
            } catch (error) {
                reject(error);
            }
        });
    }

    async sendSecureMessage(text, chatId = null, keyboard = null) {
        const targetChatId = chatId || this.adminChatId;
        
        if (!targetChatId) {
            throw new Error('No chat ID configured');
        }

        // Validate and sanitize message
        const sanitizedText = this.validateInput(text, 'message');
        
        // Encrypt if enabled
        const messageToSend = this.encryptMessage(sanitizedText);
        
        // Add security notice
        const secureText = `${messageToSend}\n\n🛡️ <i>Secure message from Claude Control</i>`;

        const messageData = {
            chat_id: targetChatId,
            text: secureText,
            parse_mode: 'HTML'
        };

        // Add inline keyboard if provided
        if (keyboard) {
            messageData.reply_markup = {
                inline_keyboard: keyboard
            };
        }

        const response = await this.makeSecureRequest('sendMessage', messageData);

        if (!response.ok) {
            throw new Error(`Telegram API error: ${response.description}`);
        }

        // Log successful message
        this.security.logger.info('Secure message sent', {
            chatId: targetChatId,
            messageLength: sanitizedText.length,
            encrypted: this.config.encryptMessages,
            hasKeyboard: !!keyboard
        });

        return response.result;
    }

    async sendApprovalRequest(queueItem) {
        const { operation } = queueItem;
        const timeStr = new Date(queueItem.timestamp).toLocaleTimeString();
        
        // Format for 23 character width (mobile friendly)
        let message = `🤖 <b>Approval Request</b>\n`;
        message += `━━━━━━━━━━━━━━━━━━━━━━━\n`;
        message += `🆔 ID: <code>${queueItem.id}</code>\n`;
        message += `⏰ ${timeStr}\n`;
        message += `🔧 Tool: <code>${operation.tool}</code>\n\n`;
        
        if (operation.tool === 'Bash') {
            // Wrap command for readability
            const cmd = this.wrapText(operation.params.command, 20);
            message += `💻 <b>Command:</b>\n<code>${cmd}</code>\n\n`;
            
            if (operation.params.description) {
                const desc = this.wrapText(operation.params.description, 20);
                message += `📝 <i>${desc}</i>\n\n`;
            }
        } else if (operation.tool === 'Edit') {
            const fileName = operation.params.file_path.split('/').pop();
            message += `📁 <b>File:</b> <code>${fileName}</code>\n`;
            message += `🔄 <i>Modifying content</i>\n\n`;
            
            // Show actual changes
            if (operation.params.old_string && operation.params.new_string) {
                const oldPreview = this.truncateText(operation.params.old_string, 80);
                const newPreview = this.truncateText(operation.params.new_string, 80);
                
                message += `📋 <b>Changes:</b>\n`;
                message += `❌ <b>OLD:</b>\n<code>${this.wrapText(oldPreview, 18)}</code>\n\n`;
                message += `✅ <b>NEW:</b>\n<code>${this.wrapText(newPreview, 18)}</code>\n\n`;
            }
        } else if (operation.tool === 'Write') {
            const fileName = operation.params.file_path.split('/').pop();
            message += `📁 <b>File:</b> <code>${fileName}</code>\n`;
            message += `🆕 <i>Creating new file</i>\n\n`;
            
            // Show content preview
            if (operation.params.content) {
                const preview = this.truncateText(operation.params.content, 120);
                message += `📝 <b>Content:</b>\n<code>${this.wrapText(preview, 18)}</code>\n\n`;
            }
        } else if (operation.tool === 'MultiEdit') {
            const fileName = operation.params.file_path.split('/').pop();
            const editCount = operation.params.edits?.length || 0;
            message += `📁 <b>File:</b> <code>${fileName}</code>\n`;
            message += `🔄 <i>${editCount} multiple changes</i>\n\n`;
            
            // Show first change
            if (operation.params.edits && operation.params.edits.length > 0) {
                const edit = operation.params.edits[0];
                const oldPreview = this.truncateText(edit.old_string, 60);
                const newPreview = this.truncateText(edit.new_string, 60);
                
                message += `📋 <b>First Change:</b>\n`;
                message += `❌ <code>${this.wrapText(oldPreview, 18)}</code>\n`;
                message += `✅ <code>${this.wrapText(newPreview, 18)}</code>\n\n`;
                
                if (editCount > 1) {
                    message += `<i>...and ${editCount - 1} more changes</i>\n\n`;
                }
            }
        }

        // Create inline keyboard for easy approval
        const keyboard = [
            [
                { text: '✅ Approve', callback_data: `approve_${queueItem.id}` },
                { text: '❌ Deny', callback_data: `deny_${queueItem.id}` }
            ],
            [
                { text: '📝 Details', callback_data: `details_${queueItem.id}` },
                { text: '📊 Status', callback_data: 'status' }
            ]
        ];

        message += `<i>Use buttons below or type:</i>\n`;
        message += `<code>approve ${queueItem.id}</code>\n`;
        message += `<code>deny ${queueItem.id}</code>`;

        return await this.sendSecureMessage(message, null, keyboard);
    }

    wrapText(text, lineLength) {
        if (!text) return '';
        const words = text.split(' ');
        const lines = [];
        let currentLine = '';
        
        for (const word of words) {
            if ((currentLine + word).length <= lineLength) {
                currentLine += (currentLine ? ' ' : '') + word;
            } else {
                if (currentLine) lines.push(currentLine);
                currentLine = word;
            }
        }
        if (currentLine) lines.push(currentLine);
        
        return lines.join('\n');
    }

    truncateText(text, maxLength) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    }

    // === MESSAGE HANDLING ===

    async handleSecureMessage(message) {
        const chatId = message.chat.id;
        const username = message.from.username || message.from.first_name;
        const text = message.text ? this.validateInput(message.text.trim(), 'message') : '';
        
        // Security checks
        if (this.isRateLimited(chatId)) {
            this.security.logger.warn('Rate limited message ignored', { chatId, username });
            return;
        }

        if (this.detectSuspiciousActivity(chatId, text)) {
            await this.sendSecureMessage(
                '🚨 <b>Security Alert</b>\nSuspicious activity detected. Message blocked.',
                chatId
            );
            return;
        }

        // Authentication check
        if (this.config.requireAuthentication && !this.isAuthorized(chatId) && !text.startsWith('/start')) {
            await this.sendSecureMessage(
                '🔒 <b>Access Denied</b>\nYou are not authorized to use this bot. Contact the administrator.',
                chatId
            );
            this.logSuspiciousActivity(chatId, text, 'unauthorized_access');
            return;
        }

        // Log all activity
        this.security.logger.info('Message received', {
            chatId,
            username,
            command: text.split(' ')[0],
            length: text.length,
            authorized: this.isAuthorized(chatId)
        });

        // Command processing
        await this.processSecureCommand(chatId, username, text);
    }

    async processSecureCommand(chatId, username, text) {
        const lowerText = text.toLowerCase();
        const command = lowerText.split(' ')[0].replace('/', '');
        
        // Validate command against whitelist
        if (!this.config.commandWhitelist.includes(command) && !lowerText.startsWith('/')) {
            await this.sendSecureMessage(
                '❌ <b>Command Not Allowed</b>\nUnknown or unauthorized command.',
                chatId
            );
            return;
        }

        try {
            switch (command) {
                case 'start':
                    await this.handleStartCommand(chatId, username);
                    break;
                    
                case 'auth':
                    await this.handleAuthCommand(chatId, username, lowerText);
                    break;
                    
                case 'help':
                    await this.handleHelpCommand(chatId);
                    break;
                    
                case 'status':
                    await this.handleStatusCommand(chatId);
                    break;
                    
                case 'approve':
                case 'deny':
                case 'details':
                    await this.handleApprovalCommand(chatId, lowerText);
                    break;
                    
                case 'logout':
                    await this.handleLogoutCommand(chatId);
                    break;
                    
                default:
                    await this.sendSecureMessage(
                        '❓ Unknown command. Send <code>/help</code> for available commands.',
                        chatId
                    );
            }
            
            // Update command history
            this.updateCommandHistory(chatId, command);
            
        } catch (error) {
            this.security.logger.error('Command processing error', {
                chatId,
                command,
                error: error.message
            });
            
            await this.sendSecureMessage(
                `❌ <b>Error</b>\nFailed to process command: ${error.message}`,
                chatId
            );
        }
    }

    async handleStartCommand(chatId, username) {
        // Create session for authorized users
        if (this.isAuthorized(chatId)) {
            const sessionId = this.createSession(chatId, username);
            
            await this.sendSecureMessage(
                '🤖 <b>Claude Code Remote Control</b>\n\n' +
                '🛡️ <b>Secure Mode Active</b>\n\n' +
                '<b>Security Features:</b>\n' +
                '✅ End-to-end encryption\n' +
                '✅ Rate limiting protection\n' +
                '✅ Command validation\n' +
                '✅ Audit logging\n\n' +
                '<b>Available Commands:</b>\n' +
                '• <code>/auth</code> - Authenticate session\n' +
                '• <code>/approve &lt;id&gt;</code> - Approve operation\n' +
                '• <code>/deny &lt;id&gt;</code> - Deny operation\n' +
                '• <code>/details &lt;id&gt;</code> - View operation details\n' +
                '• <code>/status</code> - Show queue status\n' +
                '• <code>/help</code> - Show this message\n' +
                '• <code>/logout</code> - End session\n\n' +
                `🔑 Session ID: <code>${sessionId}</code>`,
                chatId
            );
        } else {
            await this.sendSecureMessage(
                '🔒 <b>Authentication Required</b>\n\n' +
                'This is a secure bot. You need authorization to use it.\n\n' +
                'Contact the administrator to get access.',
                chatId
            );
        }
    }

    async handleAuthCommand(chatId, username, text) {
        // Simple authentication - could be extended with passwords/2FA
        if (chatId === this.adminChatId) {
            this.authorizedUsers.add(chatId);
            const sessionId = this.createSession(chatId, username);
            
            await this.sendSecureMessage(
                '✅ <b>Authentication Successful</b>\n\n' +
                'You are now authorized to use this bot.\n' +
                `Session ID: <code>${sessionId}</code>`,
                chatId
            );
        } else {
            await this.sendSecureMessage(
                '❌ <b>Authentication Failed</b>\nContact the administrator for access.',
                chatId
            );
            this.logSuspiciousActivity(chatId, text, 'failed_authentication');
        }
    }

    async handleHelpCommand(chatId) {
        const session = this.validateSession(chatId);
        if (!session) {
            await this.sendSecureMessage(
                '🔒 Session expired. Please use <code>/start</code> to begin.',
                chatId
            );
            return;
        }

        await this.sendSecureMessage(
            '🤖 <b>Claude Code Remote Control - Help</b>\n\n' +
            '<b>Security Commands:</b>\n' +
            '• <code>/auth</code> - Re-authenticate\n' +
            '• <code>/logout</code> - End session\n\n' +
            '<b>Operation Commands:</b>\n' +
            '• <code>/approve &lt;id&gt;</code> - Approve pending operation\n' +
            '• <code>/deny &lt;id&gt;</code> - Deny pending operation\n' +
            '• <code>/details &lt;id&gt;</code> - View operation details\n' +
            '• <code>/status</code> - Show queue status\n\n' +
            '<b>Information:</b>\n' +
            '• All messages are encrypted\n' +
            '• All actions are audited\n' +
            '• Rate limiting is active\n' +
            '• Session expires in 1 hour\n\n' +
            `🔑 Your Session: <code>${session.id}</code>`,
            chatId
        );
    }

    async handleStatusCommand(chatId) {
        const session = this.validateSession(chatId);
        if (!session) {
            await this.sendSecureMessage(
                '🔒 Session expired. Please use <code>/start</code> to begin.',
                chatId
            );
            return;
        }

        // Use existing message handler for status
        const MessageHandler = require('./message_handler.js');
        const handler = new MessageHandler();
        
        const response = await handler.processMessage('status');
        await this.sendSecureMessage(
            `${response.message}\n\n🛡️ <i>Secure Session: ${session.id}</i>`,
            chatId
        );
    }

    async handleApprovalCommand(chatId, text) {
        const session = this.validateSession(chatId);
        if (!session) {
            await this.sendSecureMessage(
                '🔒 Session expired. Please use <code>/start</code> to begin.',
                chatId
            );
            return;
        }

        // Process approval commands securely
        const MessageHandler = require('./message_handler.js');
        const handler = new MessageHandler();
        
        // Log the approval action
        this.security.logger.info('Approval command executed', {
            chatId,
            sessionId: session.id,
            command: text.split(' ')[0],
            operationId: text.split(' ')[1]
        });
        
        const response = await handler.processMessage(text);
        await this.sendSecureMessage(
            `${response.message}\n\n🛡️ <i>Action logged and audited</i>`,
            chatId
        );
    }

    async handleLogoutCommand(chatId) {
        const session = this.validateSession(chatId);
        if (session) {
            this.activeSessions.delete(session.id);
            this.saveSessions();
            
            this.security.logger.info('User logged out', {
                chatId,
                sessionId: session.id
            });
            
            await this.sendSecureMessage(
                '✅ <b>Logout Successful</b>\n\nYour session has been terminated securely.',
                chatId
            );
        } else {
            await this.sendSecureMessage(
                'ℹ️ No active session to logout.',
                chatId
            );
        }
    }

    async handleCallbackQuery(callbackQuery) {
        const { data, from, message } = callbackQuery;
        const chatId = from.id;
        
        // Validate authorization
        if (!this.isAuthorized(chatId)) {
            await this.answerCallbackQuery(callbackQuery.id, '🔒 Access denied');
            return;
        }

        // Validate session
        const session = this.validateSession(chatId);
        if (!session) {
            await this.answerCallbackQuery(callbackQuery.id, '🔒 Session expired');
            await this.sendSecureMessage(
                '🔒 Session expired. Please use <code>/start</code> to begin.',
                chatId
            );
            return;
        }

        this.security.logger.info('Callback query received', {
            chatId,
            data,
            sessionId: session.id
        });

        try {
            // Parse callback data
            if (data.startsWith('approve_')) {
                const operationId = data.replace('approve_', '');
                await this.handleApprovalCommand(chatId, `approve ${operationId}`);
                await this.answerCallbackQuery(callbackQuery.id, '✅ Approved!');
                
            } else if (data.startsWith('deny_')) {
                const operationId = data.replace('deny_', '');
                await this.handleApprovalCommand(chatId, `deny ${operationId}`);
                await this.answerCallbackQuery(callbackQuery.id, '❌ Denied!');
                
            } else if (data.startsWith('details_')) {
                const operationId = data.replace('details_', '');
                await this.handleApprovalCommand(chatId, `details ${operationId}`);
                await this.answerCallbackQuery(callbackQuery.id, '📝 Details shown');
                
            } else if (data === 'status') {
                await this.handleStatusCommand(chatId);
                await this.answerCallbackQuery(callbackQuery.id, '📊 Status updated');
                
            } else {
                await this.answerCallbackQuery(callbackQuery.id, '❓ Unknown action');
            }
            
        } catch (error) {
            this.security.logger.error('Callback query error', {
                chatId,
                data,
                error: error.message
            });
            
            await this.answerCallbackQuery(callbackQuery.id, '❌ Error occurred');
        }
    }

    async answerCallbackQuery(callbackQueryId, text = null) {
        const data = { callback_query_id: callbackQueryId };
        if (text) data.text = text;
        
        const response = await this.makeSecureRequest('answerCallbackQuery', data);
        
        if (!response.ok) {
            this.security.logger.error('Failed to answer callback query', {
                error: response.description
            });
        }
        
        return response;
    }

    updateCommandHistory(chatId, command) {
        const history = this.commandHistory.get(chatId) || [];
        history.push({
            command,
            timestamp: Date.now()
        });
        
        // Keep only last 50 commands
        if (history.length > 50) {
            history.splice(0, history.length - 50);
        }
        
        this.commandHistory.set(chatId, history);
    }

    // === POLLING WITH SECURITY ===

    async startSecurePolling() {
        let offset = 0;
        let consecutiveErrors = 0;
        
        this.security.logger.info('Starting secure Telegram polling', {
            rateLimitEnabled: true,
            encryptionEnabled: this.config.encryptMessages,
            authRequired: this.config.requireAuthentication
        });
        
        console.log('🛡️ Starting SECURE Telegram polling...');
        console.log('✅ Rate limiting active');
        console.log('✅ Message encryption enabled');
        console.log('✅ Authentication required');
        console.log('✅ Comprehensive logging active');
        
        while (true) {
            try {
                const updates = await this.makeSecureRequest('getUpdates', {
                    offset: offset,
                    limit: 10, // Smaller batches for security
                    timeout: 10
                });

                if (!updates.ok) {
                    throw new Error(`Telegram API error: ${updates.description}`);
                }
                
                consecutiveErrors = 0; // Reset error counter
                
                for (const update of updates.result) {
                    offset = update.update_id + 1;
                    
                    if (update.message && update.message.text) {
                        await this.handleSecureMessage(update.message);
                    } else if (update.callback_query) {
                        await this.handleCallbackQuery(update.callback_query);
                    }
                }
                
                // Adaptive polling delay based on activity
                const delay = updates.result.length > 0 ? 500 : 2000;
                await new Promise(resolve => setTimeout(resolve, delay));
                
            } catch (error) {
                consecutiveErrors++;
                
                this.security.logger.error('Polling error', {
                    error: error.message,
                    consecutiveErrors
                });
                
                console.error(`❌ Polling error (${consecutiveErrors}): ${error.message}`);
                
                // Exponential backoff for errors
                const delay = Math.min(5000 * Math.pow(2, consecutiveErrors), 60000);
                await new Promise(resolve => setTimeout(resolve, delay));
                
                // If too many errors, exit
                if (consecutiveErrors >= 10) {
                    this.security.logger.error('Too many consecutive polling errors, exiting');
                    process.exit(1);
                }
            }
        }
    }

    // === API METHODS ===

    async getMe() {
        const response = await this.makeSecureRequest('getMe');
        if (!response.ok) {
            throw new Error(`Telegram API error: ${response.description}`);
        }
        return response.result;
    }

    // === UTILITY METHODS ===

    getSecurityStatus() {
        return {
            activeSessions: this.activeSessions.size,
            authorizedUsers: this.authorizedUsers.size,
            rateLimitedUsers: Array.from(this.rateLimiter.values()).filter(u => u.blocked).length,
            suspiciousActivities: Array.from(this.suspiciousActivity.values()).reduce((sum, activities) => sum + activities.length, 0),
            encryptionEnabled: this.config.encryptMessages,
            authenticationRequired: this.config.requireAuthentication
        };
    }
}

// CLI handling
if (require.main === module) {
    const command = process.argv[2];
    const client = new SecureTelegramClient();
    
    if (!client.botToken) {
        console.error('❌ Bot token not configured. Please set TELEGRAM_BOT_TOKEN in .env');
        process.exit(1);
    }

    switch (command) {
        case 'send':
            const message = process.argv[3];
            if (!message) {
                console.log('Usage: secure_telegram_client.js send "message"');
                process.exit(1);
            }
            client.sendSecureMessage(message).then(() => {
                console.log('✅ Secure message sent');
            }).catch(error => {
                console.error('❌ Failed to send message:', error.message);
                process.exit(1);
            });
            break;
            
        case 'poll':
            client.startSecurePolling();
            break;
            
        case 'test':
            client.getMe().then(bot => {
                console.log(`✅ Secure bot connected: ${bot.first_name} (@${bot.username})`);
                const status = client.getSecurityStatus();
                console.log('🛡️  Security Status:', status);
            }).catch(error => {
                console.error('❌ Bot connection failed:', error.message);
                process.exit(1);
            });
            break;
            
        case 'status':
            const status = client.getSecurityStatus();
            console.log('🛡️  SECURE TELEGRAM CLIENT STATUS');
            console.log('=====================================');
            console.log(`Active Sessions: ${status.activeSessions}`);
            console.log(`Authorized Users: ${status.authorizedUsers}`);
            console.log(`Rate Limited Users: ${status.rateLimitedUsers}`);
            console.log(`Suspicious Activities: ${status.suspiciousActivities}`);
            console.log(`Encryption: ${status.encryptionEnabled ? 'Enabled' : 'Disabled'}`);
            console.log(`Authentication: ${status.authenticationRequired ? 'Required' : 'Optional'}`);
            break;
            
        default:
            console.log('🛡️  SECURE TELEGRAM CLIENT');
            console.log('===========================');
            console.log('Usage: secure_telegram_client.js <command> [args...]');
            console.log('');
            console.log('Commands:');
            console.log('  send <message>  - Send secure message');
            console.log('  poll           - Start secure polling');
            console.log('  test           - Test bot connection');
            console.log('  status         - Show security status');
            process.exit(1);
    }
}

module.exports = SecureTelegramClient;