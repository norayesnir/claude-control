#!/usr/bin/env node

/**
 * Claude Code Remote Control - Approval Manager
 * This script manages the approval queue and communicates via secure channels
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const QUEUE_DIR = path.join(process.env.HOME, '.claude-control', 'queue');
const CONFIG_FILE = path.join(process.env.HOME, '.claude-control', 'config.json');

class ApprovalManager {
    constructor() {
        this.ensureDirectories();
        this.loadConfig();
    }

    ensureDirectories() {
        if (!fs.existsSync(QUEUE_DIR)) {
            fs.mkdirSync(QUEUE_DIR, { recursive: true });
        }
    }

    loadConfig() {
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                this.config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
            } else {
                this.config = {
                    autoApprove: [],
                    denyPatterns: [],
                    requireApproval: ["*"],
                    telegramEnabled: true
                };
                this.saveConfig();
            }
        } catch (error) {
            console.error('Error loading config:', error);
            process.exit(1);
        }
    }

    saveConfig() {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(this.config, null, 2));
    }

    async addToQueue(operation) {
        const id = crypto.randomBytes(8).toString('hex');
        const queueItem = {
            id,
            timestamp: new Date().toISOString(),
            operation,
            status: 'pending'
        };

        const queueFile = path.join(QUEUE_DIR, `${id}.json`);
        fs.writeFileSync(queueFile, JSON.stringify(queueItem, null, 2));

        // Send notification
        if (this.config.telegramEnabled || this.config.iMessageEnabled) {
            await this.sendNotification(queueItem);
        }

        return id;
    }

    async sendNotification(queueItem) {
        const message = this.formatNotificationMessage(queueItem);
        
        try {
            if (this.config.telegramEnabled) {
                // Send via secure Telegram client - pass the entire queueItem for enhanced display
                await this.sendViaSecureTelegram(queueItem);
                console.log(`📱 Sent secure Telegram notification for operation ${queueItem.id}`);
            } else if (this.config.iMessageEnabled) {
                // Send via iMessage (fallback)
                await this.sendViaiMessage(message, queueItem.id);
            } else {
                console.log('📱 No messaging channels enabled, logging notification');
                this.logNotification(queueItem.id, message);
            }
        } catch (error) {
            console.error('Failed to send notification:', error.message);
            this.logNotification(queueItem.id, message);
        }
    }

    async sendViaSecureTelegram(queueItem) {
        // Check if secure client is available
        const secureClientPath = path.join(__dirname, 'secure_telegram_client.js');
        const regularClientPath = path.join(__dirname, 'telegram_client.js');
        
        if (fs.existsSync(secureClientPath)) {
            // Use secure client with enhanced approval request
            const SecureTelegramClient = require('./secure_telegram_client.js');
            const client = new SecureTelegramClient();
            
            try {
                await client.sendApprovalRequest(queueItem);
                console.log(`🛡️ Sent secure approval request for operation ${queueItem.id}`);
            } catch (error) {
                console.error('Secure client failed, falling back to regular client:', error.message);
                // Fallback to regular client using secure spawn
                const message = this.formatNotificationMessage(queueItem);
                await this.secureSpawnClient(regularClientPath, ['send', message]);
            }
        } else {
            // Fallback to regular client using secure spawn
            const message = this.formatNotificationMessage(queueItem);
            await this.secureSpawnClient(regularClientPath, ['send', message]);
        }
    }

    async sendViaiMessage(message, operationId) {
        // Get phone number from config
        const phoneNumber = this.config.phoneNumber;
        if (!phoneNumber || phoneNumber === 'YOUR_PHONE_NUMBER_HERE') {
            console.log('📱 Phone number not configured, skipping iMessage notification');
            return;
        }

        // Send directly via iMessage using imsg with secure command execution
        try {
            await this.secureSpawnCommand('imsg', [
                'send',
                '--to', phoneNumber,
                '--text', message,
                '--service', 'imessage'
            ], { timeout: 5000 });
            console.log(`📱 Sent iMessage notification for operation ${operationId}`);
        } catch (error) {
            console.error(`❌ Failed to send iMessage: ${error.message}`);
            throw error;
        }
    }

    logNotification(operationId, message) {
        // Fallback: log the message for manual processing
        const logFile = path.join(process.env.HOME, '.claude-control', 'pending_notifications.log');
        const logEntry = `${new Date().toISOString()} - ${operationId}: ${message}\n`;
        require('fs').appendFileSync(logFile, logEntry);
    }

    formatNotificationMessage(queueItem) {
        const { operation } = queueItem;
        const timeStr = new Date(queueItem.timestamp).toLocaleTimeString();
        
        let message = `🤖 Claude Code Approval Request [${queueItem.id}]\n`;
        message += `⏰ Time: ${timeStr}\n`;
        message += `🔧 Tool: ${operation.tool}\n`;
        
        if (operation.tool === 'Bash') {
            message += `💻 Command: \`${operation.params.command}\`\n`;
            message += `📝 Description: ${operation.params.description || 'No description'}\n`;
        } else if (operation.tool === 'Edit') {
            message += `📁 File: ${operation.params.file_path}\n`;
            message += `🔄 Action: Modifying existing content\n`;
            
            // Show actual changes for Edit operations
            if (operation.params.old_string && operation.params.new_string) {
                const oldPreview = this.truncateText(operation.params.old_string, 200);
                const newPreview = this.truncateText(operation.params.new_string, 200);
                message += `\n📋 Changes:\n`;
                message += `❌ OLD:\n\`\`\`\n${oldPreview}\n\`\`\`\n`;
                message += `✅ NEW:\n\`\`\`\n${newPreview}\n\`\`\`\n`;
            }
        } else if (operation.tool === 'Write') {
            message += `📁 File: ${operation.params.file_path}\n`;
            message += `🆕 Action: Creating new file\n`;
            
            // Show content preview for Write operations
            if (operation.params.content) {
                const contentPreview = this.truncateText(operation.params.content, 300);
                message += `\n📝 Content Preview:\n\`\`\`\n${contentPreview}\n\`\`\`\n`;
            }
        } else if (operation.tool === 'MultiEdit') {
            message += `📁 File: ${operation.params.file_path}\n`;
            message += `🔄 Action: Multiple edits (${operation.params.edits?.length || 0} changes)\n`;
            
            // Show first few edits
            if (operation.params.edits && operation.params.edits.length > 0) {
                message += `\n📋 First Changes:\n`;
                const editsToShow = operation.params.edits.slice(0, 2);
                editsToShow.forEach((edit, i) => {
                    const oldPreview = this.truncateText(edit.old_string, 100);
                    const newPreview = this.truncateText(edit.new_string, 100);
                    message += `${i + 1}. OLD: \`${oldPreview}\`\n`;
                    message += `   NEW: \`${newPreview}\`\n`;
                });
                if (operation.params.edits.length > 2) {
                    message += `   ... and ${operation.params.edits.length - 2} more changes\n`;
                }
            }
        }
        
        message += `\n🎛️ Reply with:\n`;
        message += `✅ "Approve ${queueItem.id}" to allow\n`;
        message += `❌ "Deny ${queueItem.id}" to block\n`;
        message += `📝 "Details ${queueItem.id}" for more info`;

        return message.replace(/"/g, '\\"');
    }

    truncateText(text, maxLength) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    }

    checkAutoApproval(operation) {
        const { tool, params } = operation;
        
        // Check auto-approve patterns
        for (const pattern of this.config.autoApprove) {
            if (this.matchesPattern(operation, pattern)) {
                return 'approve';
            }
        }

        // Check deny patterns
        for (const pattern of this.config.denyPatterns) {
            if (this.matchesPattern(operation, pattern)) {
                return 'deny';
            }
        }

        return 'ask';
    }

    matchesPattern(operation, pattern) {
        const { tool, params } = operation;
        
        if (typeof pattern === 'string') {
            // Simple tool matching
            return tool === pattern || pattern === '*';
        }
        
        if (typeof pattern === 'object') {
            // Complex pattern matching
            if (pattern.tool && pattern.tool !== tool) return false;
            if (pattern.command && tool === 'Bash') {
                return new RegExp(pattern.command).test(params.command);
            }
            if (pattern.file && (tool === 'Edit' || tool === 'Write')) {
                return new RegExp(pattern.file).test(params.file_path);
            }
        }
        
        return false;
    }

    async processApproval(approvalId, action, reason = '') {
        const queueFile = path.join(QUEUE_DIR, `${approvalId}.json`);
        
        if (!fs.existsSync(queueFile)) {
            throw new Error(`Approval request ${approvalId} not found`);
        }

        const queueItem = JSON.parse(fs.readFileSync(queueFile, 'utf8'));
        queueItem.status = action;
        queueItem.reason = reason;
        queueItem.processedAt = new Date().toISOString();

        fs.writeFileSync(queueFile, JSON.stringify(queueItem, null, 2));

        return queueItem;
    }

    getQueueStatus() {
        const files = fs.readdirSync(QUEUE_DIR).filter(f => f.endsWith('.json'));
        const items = files.map(f => {
            const content = fs.readFileSync(path.join(QUEUE_DIR, f), 'utf8');
            return JSON.parse(content);
        });

        return {
            pending: items.filter(i => i.status === 'pending').length,
            approved: items.filter(i => i.status === 'approved').length,
            denied: items.filter(i => i.status === 'denied').length,
            total: items.length
        };
    }

    // Secure command execution to prevent injection attacks
    async secureSpawnClient(clientPath, args) {
        return new Promise((resolve, reject) => {
            // Validate client path to prevent path traversal
            const normalizedPath = path.normalize(clientPath);
            if (normalizedPath.includes('..') || !normalizedPath.endsWith('.js')) {
                reject(new Error('Invalid client path'));
                return;
            }

            // Validate arguments
            const safeArgs = args.filter(arg => 
                typeof arg === 'string' && 
                arg.length < 10000 && 
                !arg.includes('\n') && 
                !arg.includes('\r')
            );

            const child = spawn('node', [normalizedPath, ...safeArgs], {
                stdio: 'inherit',
                timeout: 10000,
                env: process.env
            });

            child.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`Client process exited with code ${code}`));
                }
            });

            child.on('error', (error) => {
                reject(new Error(`Failed to start client process: ${error.message}`));
            });

            // Kill process after timeout
            setTimeout(() => {
                if (!child.killed) {
                    child.kill();
                    reject(new Error('Client process timeout'));
                }
            }, 10000);
        });
    }

    // Secure command execution method to prevent injection attacks
    async secureSpawnCommand(command, args, options = {}) {
        return new Promise((resolve, reject) => {
            // Command allowlist for security
            const allowedCommands = [
                'imsg', 'node', 'npm', 'git', 'ls', 'pwd', 'whoami', 'date', 'echo'
            ];
            
            // Input validation
            if (!command || typeof command !== 'string') {
                reject(new Error('Invalid command'));
                return;
            }
            
            // Check command allowlist
            if (!allowedCommands.includes(command)) {
                this.security?.logger?.error('Blocked unauthorized command', { command });
                reject(new Error('Command not allowed'));
                return;
            }
            
            if (!Array.isArray(args)) {
                reject(new Error('Arguments must be an array'));
                return;
            }

            // Enhanced argument sanitization
            const sanitizedArgs = args.map(arg => {
                if (typeof arg !== 'string') {
                    throw new Error('All arguments must be strings');
                }
                // Remove any shell metacharacters and limit length
                const sanitized = arg.replace(/[;&|`$(){}[\]<>\\]/g, '').substring(0, 1000);
                
                // Additional validation for specific patterns
                if (/\.\.[\/\\]/.test(sanitized)) {
                    throw new Error('Path traversal attempt detected');
                }
                
                return sanitized;
            });

            const child = spawn(command, sanitizedArgs, {
                stdio: 'pipe',
                timeout: options.timeout || 5000,
                env: process.env
            });

            let stdout = '';
            let stderr = '';

            child.stdout?.on('data', (data) => {
                stdout += data.toString();
            });

            child.stderr?.on('data', (data) => {
                stderr += data.toString();
            });

            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    reject(new Error(`Command failed with code ${code}: ${stderr}`));
                }
            });

            child.on('error', (error) => {
                reject(new Error(`Failed to execute command: ${error.message}`));
            });

            // Set timeout
            if (options.timeout) {
                setTimeout(() => {
                    if (!child.killed) {
                        child.kill();
                        reject(new Error('Command timeout'));
                    }
                }, options.timeout);
            }
        });
    }
}

// CLI handling
if (require.main === module) {
    const manager = new ApprovalManager();
    const command = process.argv[2];
    const args = process.argv.slice(3);

    switch (command) {
        case 'add':
            const operation = JSON.parse(args[0]);
            manager.addToQueue(operation).then(id => {
                console.log(`Added to queue: ${id}`);
            });
            break;
        
        case 'approve':
            const approveId = args[0];
            const reason = args[1] || '';
            manager.processApproval(approveId, 'approved', reason).then(() => {
                console.log(`Approved: ${approveId}`);
            });
            break;
        
        case 'deny':
            const denyId = args[0];
            const denyReason = args[1] || '';
            manager.processApproval(denyId, 'denied', denyReason).then(() => {
                console.log(`Denied: ${denyId}`);
            });
            break;
        
        case 'status':
            const status = manager.getQueueStatus();
            console.log('Queue Status:', status);
            break;
        
        default:
            console.log('Usage: approval_manager.js <add|approve|deny|status> [args...]');
            process.exit(1);
    }
}

module.exports = ApprovalManager;