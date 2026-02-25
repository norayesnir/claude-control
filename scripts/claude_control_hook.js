#!/usr/bin/env node

/**
 * Claude Code Hook for Claude Control Integration
 * 
 * Features:
 * - Easy on/off toggle
 * - Dual approval (terminal + phone)
 * - Enhanced notifications with actual code changes
 * - Secure integration with approval queue
 * - Interactive terminal prompts
 * - Auto-timeout for approvals
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

class ClaudeControlHook {
    constructor() {
        this.configFile = path.join(process.env.HOME, '.claude-control', 'config.json');
        this.hookConfigFile = path.join(process.env.HOME, '.claude-control', 'hook-config.json');
        this.loadConfig();
    }

    loadConfig() {
        try {
            // Load main config
            this.config = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
            
            // Load hook-specific config
            const defaultHookConfig = {
                enabled: true,
                allowTerminalApproval: true,
                allowPhoneApproval: true,
                autoTimeoutMs: 300000, // 5 minutes
                requireApproval: ["Edit", "Write", "MultiEdit", "Bash"],
                autoApprove: ["Read", "Glob", "Grep"],
                dangerousPatterns: [
                    "rm -rf", "sudo", "curl.*[|&;]", "wget.*[|&;]", 
                    "sh.*[|&;]", "bash.*[|&;]", "exec", "eval"
                ]
            };

            if (fs.existsSync(this.hookConfigFile)) {
                this.hookConfig = { ...defaultHookConfig, ...JSON.parse(fs.readFileSync(this.hookConfigFile, 'utf8')) };
            } else {
                this.hookConfig = defaultHookConfig;
                this.saveHookConfig();
            }
        } catch (error) {
            console.error('❌ Failed to load hook config:', error.message);
            process.exit(1);
        }
    }

    saveHookConfig() {
        fs.writeFileSync(this.hookConfigFile, JSON.stringify(this.hookConfig, null, 2));
    }

    isEnabled() {
        return this.hookConfig.enabled;
    }

    async handleToolCall(toolCall) {
        if (!this.isEnabled()) {
            console.log('🔓 Hook disabled - allowing operation');
            return { allowed: true, reason: 'Hook disabled' };
        }

        const { tool, params } = toolCall;

        // Auto-approve safe operations
        if (this.hookConfig.autoApprove.includes(tool)) {
            console.log(`✅ Auto-approved: ${tool}`);
            return { allowed: true, reason: 'Auto-approved safe operation' };
        }

        // Check dangerous patterns
        if (this.isDangerous(toolCall)) {
            console.log('🚨 DANGEROUS OPERATION BLOCKED!');
            this.logSecurityAlert(toolCall, 'dangerous_pattern_detected');
            return { allowed: false, reason: 'Dangerous operation blocked' };
        }

        // Check if approval required
        if (this.hookConfig.requireApproval.includes(tool)) {
            return await this.requestApproval(toolCall);
        }

        // Default allow
        return { allowed: true, reason: 'No approval required' };
    }

    isDangerous(toolCall) {
        const { tool, params } = toolCall;
        
        if (tool === 'Bash') {
            const command = params.command || '';
            return this.hookConfig.dangerousPatterns.some(pattern => 
                new RegExp(pattern, 'i').test(command)
            );
        }

        return false;
    }

    async requestApproval(toolCall) {
        console.log('\n🤖 Claude Code wants to perform an operation:');
        this.displayOperation(toolCall);

        // Send to approval queue (phone notification)
        const approvalId = await this.addToApprovalQueue(toolCall);
        
        console.log(`\n📱 Notification sent to your phone (ID: ${approvalId})`);
        console.log('⌨️  Or approve here in terminal:');

        // Create dual approval system
        const result = await Promise.race([
            this.waitForTerminalApproval(approvalId),
            this.waitForPhoneApproval(approvalId),
            this.createTimeout()
        ]);

        return result;
    }

    displayOperation(toolCall) {
        const { tool, params } = toolCall;
        
        console.log(`🔧 Tool: ${tool}`);
        
        if (tool === 'Edit') {
            console.log(`📁 File: ${params.file_path}`);
            if (params.old_string && params.new_string) {
                console.log('\n📋 Changes:');
                console.log('❌ OLD:');
                console.log(this.truncateText(params.old_string, 200));
                console.log('\n✅ NEW:');
                console.log(this.truncateText(params.new_string, 200));
            }
        } else if (tool === 'Write') {
            console.log(`📁 File: ${params.file_path}`);
            if (params.content) {
                console.log('\n📝 Content Preview:');
                console.log(this.truncateText(params.content, 300));
            }
        } else if (tool === 'Bash') {
            console.log(`💻 Command: ${params.command}`);
            console.log(`📝 Description: ${params.description || 'No description'}`);
        } else if (tool === 'MultiEdit') {
            console.log(`📁 File: ${params.file_path}`);
            console.log(`🔄 Changes: ${params.edits?.length || 0} edits`);
            if (params.edits && params.edits[0]) {
                console.log('\n📋 First Change:');
                console.log('❌ OLD:', this.truncateText(params.edits[0].old_string, 100));
                console.log('✅ NEW:', this.truncateText(params.edits[0].new_string, 100));
                if (params.edits.length > 1) {
                    console.log(`   ... and ${params.edits.length - 1} more changes`);
                }
            }
        }
    }

    truncateText(text, maxLength) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    }

    async addToApprovalQueue(toolCall) {
        try {
            const ApprovalManager = require('./approval_manager.js');
            const manager = new ApprovalManager();
            
            const operation = {
                tool: toolCall.tool,
                params: toolCall.params,
                context: {
                    timestamp: new Date().toISOString(),
                    source: 'claude_code_hook'
                }
            };

            const approvalId = await manager.addToQueue(operation);
            return approvalId;
        } catch (error) {
            console.error('❌ Failed to add to approval queue:', error.message);
            return Date.now().toString(); // Fallback ID
        }
    }

    async waitForTerminalApproval(approvalId) {
        if (!this.hookConfig.allowTerminalApproval) {
            return new Promise(() => {}); // Never resolve
        }

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        return new Promise((resolve) => {
            const askApproval = () => {
                rl.question('\n❓ Approve this operation? [y/N/d=details]: ', (answer) => {
                    const response = answer.toLowerCase().trim();
                    
                    if (response === 'y' || response === 'yes') {
                        console.log('✅ Operation approved via terminal');
                        this.markApproved(approvalId, 'terminal');
                        rl.close();
                        resolve({ allowed: true, reason: 'Approved via terminal', source: 'terminal' });
                    } else if (response === 'n' || response === 'no' || response === '') {
                        console.log('❌ Operation denied via terminal');
                        this.markDenied(approvalId, 'terminal');
                        rl.close();
                        resolve({ allowed: false, reason: 'Denied via terminal', source: 'terminal' });
                    } else if (response === 'd' || response === 'details') {
                        console.log(`\n📝 Operation ID: ${approvalId}`);
                        console.log('📱 Check your phone for full details with buttons');
                        askApproval(); // Ask again
                    } else {
                        console.log('❓ Please enter y (yes), n (no), or d (details)');
                        askApproval(); // Ask again
                    }
                });
            };

            askApproval();
        });
    }

    async waitForPhoneApproval(approvalId) {
        if (!this.hookConfig.allowPhoneApproval) {
            return new Promise(() => {}); // Never resolve
        }

        // Poll for phone approval
        return new Promise((resolve) => {
            let polling = true;
            
            const checkApproval = () => {
                if (!polling) return; // Stop polling if approval already processed
                
                const status = this.checkApprovalStatus(approvalId);
                
                if (status === 'approved') {
                    polling = false;
                    console.log('✅ Operation approved via phone');
                    resolve({ allowed: true, reason: 'Approved via phone', source: 'phone' });
                } else if (status === 'denied') {
                    polling = false;
                    console.log('❌ Operation denied via phone');
                    resolve({ allowed: false, reason: 'Denied via phone', source: 'phone' });
                } else {
                    // Check again in 2 seconds if still polling
                    if (polling) {
                        setTimeout(checkApproval, 2000);
                    }
                }
            };

            checkApproval();
        });
    }

    createTimeout() {
        return new Promise((resolve) => {
            setTimeout(() => {
                console.log('⏰ Approval timed out - denying operation');
                resolve({ allowed: false, reason: 'Approval timeout', source: 'timeout' });
            }, this.hookConfig.autoTimeoutMs);
        });
    }

    checkApprovalStatus(approvalId) {
        try {
            const queueFile = path.join(process.env.HOME, '.claude-control', 'queue', `${approvalId}.json`);
            if (fs.existsSync(queueFile)) {
                const item = JSON.parse(fs.readFileSync(queueFile, 'utf8'));
                return item.status;
            }
        } catch (error) {
            // Ignore errors
        }
        return 'pending';
    }

    markApproved(approvalId, source) {
        try {
            const queueFile = path.join(process.env.HOME, '.claude-control', 'queue', `${approvalId}.json`);
            if (fs.existsSync(queueFile)) {
                const item = JSON.parse(fs.readFileSync(queueFile, 'utf8'));
                item.status = 'approved';
                item.approvedBy = source;
                item.processedAt = new Date().toISOString();
                fs.writeFileSync(queueFile, JSON.stringify(item, null, 2));
            }
        } catch (error) {
            console.error('Failed to mark approved:', error.message);
        }
    }

    markDenied(approvalId, source) {
        try {
            const queueFile = path.join(process.env.HOME, '.claude-control', 'queue', `${approvalId}.json`);
            if (fs.existsSync(queueFile)) {
                const item = JSON.parse(fs.readFileSync(queueFile, 'utf8'));
                item.status = 'denied';
                item.deniedBy = source;
                item.processedAt = new Date().toISOString();
                fs.writeFileSync(queueFile, JSON.stringify(item, null, 2));
            }
        } catch (error) {
            console.error('Failed to mark denied:', error.message);
        }
    }

    logSecurityAlert(toolCall, alertType) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            type: 'security_alert',
            alert: alertType,
            tool: toolCall.tool,
            params: toolCall.params,
            blocked: true
        };
        
        const logFile = path.join(process.env.HOME, '.claude-control', 'security-alerts.log');
        fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    }

    // Control methods
    enable() {
        this.hookConfig.enabled = true;
        this.saveHookConfig();
        console.log('✅ Claude Control hook enabled');
    }

    disable() {
        this.hookConfig.enabled = false;
        this.saveHookConfig();
        console.log('🔓 Claude Control hook disabled');
    }

    status() {
        console.log('\n🎣 CLAUDE CONTROL HOOK STATUS');
        console.log('================================');
        console.log(`Status: ${this.hookConfig.enabled ? '✅ Enabled' : '🔓 Disabled'}`);
        console.log(`Terminal Approval: ${this.hookConfig.allowTerminalApproval ? '✅ Enabled' : '❌ Disabled'}`);
        console.log(`Phone Approval: ${this.hookConfig.allowPhoneApproval ? '✅ Enabled' : '❌ Disabled'}`);
        console.log(`Auto-timeout: ${this.hookConfig.autoTimeoutMs / 1000}s`);
        console.log(`Auto-approve: ${this.hookConfig.autoApprove.join(', ')}`);
        console.log(`Require approval: ${this.hookConfig.requireApproval.join(', ')}`);
    }
}

// CLI handling
if (require.main === module) {
    const hook = new ClaudeControlHook();
    const command = process.argv[2];

    switch (command) {
        case 'enable':
            hook.enable();
            break;
        case 'disable':
            hook.disable();
            break;
        case 'status':
            hook.status();
            break;
        case 'test':
            // Test with a sample operation
            const testOperation = {
                tool: 'Edit',
                params: {
                    file_path: '/test/example.js',
                    old_string: 'const old = "test";',
                    new_string: 'const improved = "better test";'
                }
            };
            hook.handleToolCall(testOperation).then(result => {
                console.log('Test result:', result);
                process.exit(0);
            }).catch(error => {
                console.error('Test failed:', error);
                process.exit(1);
            });
            break;
        default:
            console.log('Usage: claude_control_hook.js <enable|disable|status|test>');
            console.log('');
            console.log('🎣 Claude Control Hook - Approval System');
            console.log('');
            console.log('Commands:');
            console.log('  enable   - Enable the hook');
            console.log('  disable  - Disable the hook');
            console.log('  status   - Show current status');
            console.log('  test     - Test the approval flow');
            break;
    }
}

module.exports = ClaudeControlHook;