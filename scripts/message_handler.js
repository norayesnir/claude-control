#!/usr/bin/env node

/**
 * Claude Control Message Handler for Claude Code Remote Control
 * Processes approval/denial messages from secure messaging channels
 */

const fs = require('fs');
const path = require('path');
const ApprovalManager = require('./approval_manager.js');

class MessageHandler {
    constructor() {
        this.manager = new ApprovalManager();
        this.commands = {
            'approve': this.handleApprove.bind(this),
            'deny': this.handleDeny.bind(this),
            'details': this.handleDetails.bind(this),
            'status': this.handleStatus.bind(this),
            'queue': this.handleQueue.bind(this),
            'help': this.handleHelp.bind(this)
        };
    }

    async processMessage(messageText) {
        const text = messageText.trim().toLowerCase();
        const parts = text.split(/\s+/);
        const command = parts[0];
        const args = parts.slice(1);

        if (this.commands[command]) {
            return await this.commands[command](args);
        } else {
            return this.formatResponse("Unknown command. Type 'help' for available commands.");
        }
    }

    async handleApprove(args) {
        const id = args[0];
        const reason = args.slice(1).join(' ') || 'Approved by user';

        if (!id) {
            return this.formatResponse("Usage: approve <id> [reason]");
        }

        try {
            await this.manager.processApproval(id, 'approved', reason);
            return this.formatResponse(`✅ Approved operation ${id}`);
        } catch (error) {
            return this.formatResponse(`❌ Error: ${error.message}`);
        }
    }

    async handleDeny(args) {
        const id = args[0];
        const reason = args.slice(1).join(' ') || 'Denied by user';

        if (!id) {
            return this.formatResponse("Usage: deny <id> [reason]");
        }

        try {
            await this.manager.processApproval(id, 'denied', reason);
            return this.formatResponse(`❌ Denied operation ${id}`);
        } catch (error) {
            return this.formatResponse(`❌ Error: ${error.message}`);
        }
    }

    async handleDetails(args) {
        const id = args[0];
        if (!id) {
            return this.formatResponse("Usage: details <id>");
        }

        try {
            const queueFile = path.join(process.env.HOME, '.claude-control', 'queue', `${id}.json`);
            if (!fs.existsSync(queueFile)) {
                return this.formatResponse(`Operation ${id} not found`);
            }

            const item = JSON.parse(fs.readFileSync(queueFile, 'utf8'));
            return this.formatOperationDetails(item);
        } catch (error) {
            return this.formatResponse(`❌ Error: ${error.message}`);
        }
    }

    async handleStatus(args) {
        const status = this.manager.getQueueStatus();
        let response = "📊 Claude Code Control Status\n\n";
        response += `🟡 Pending: ${status.pending}\n`;
        response += `✅ Approved: ${status.approved}\n`;
        response += `❌ Denied: ${status.denied}\n`;
        response += `📋 Total: ${status.total}`;
        return this.formatResponse(response);
    }

    async handleQueue(args) {
        const queueDir = path.join(process.env.HOME, '.claude-control', 'queue');
        const files = fs.readdirSync(queueDir)
            .filter(f => f.endsWith('.json'))
            .map(f => {
                const content = fs.readFileSync(path.join(queueDir, f), 'utf8');
                return JSON.parse(content);
            })
            .filter(item => item.status === 'pending')
            .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        if (files.length === 0) {
            return this.formatResponse("No pending operations in queue");
        }

        let response = `📋 Pending Operations (${files.length}):\n\n`;
        files.slice(0, 5).forEach(item => {
            const time = new Date(item.timestamp).toLocaleTimeString();
            response += `🔸 ${item.id} - ${item.operation.tool} (${time})\n`;
        });

        if (files.length > 5) {
            response += `\n... and ${files.length - 5} more`;
        }

        return this.formatResponse(response);
    }

    async handleHelp(args) {
        const help = `🤖 Claude Code Remote Control Commands:

✅ approve <id> [reason] - Approve operation
❌ deny <id> [reason] - Deny operation  
📝 details <id> - Show operation details
📊 status - Show queue statistics
📋 queue - List pending operations
❓ help - Show this help

Examples:
• approve 1645123456 looks good
• deny 1645123456 too risky
• details 1645123456`;

        return this.formatResponse(help);
    }

    formatResponse(text) {
        return {
            success: true,
            message: text
        };
    }

    formatOperationDetails(item) {
        const { operation } = item;
        const time = new Date(item.timestamp).toLocaleString();
        
        let details = `🔍 Operation Details [${item.id}]\n\n`;
        details += `⏰ Time: ${time}\n`;
        details += `🔧 Tool: ${operation.tool}\n`;
        details += `📁 Project: ${operation.context?.project || 'Unknown'}\n\n`;
        
        if (operation.tool === 'Bash') {
            details += `💻 Command: ${operation.params.command}\n`;
            details += `📝 Description: ${operation.params.description || 'No description'}\n`;
        } else if (operation.tool === 'Edit') {
            details += `📄 File: ${operation.params.file_path}\n`;
            details += `📝 Changes: Edit existing content\n`;
        } else if (operation.tool === 'Write') {
            details += `📄 File: ${operation.params.file_path}\n`;
            details += `📝 Action: Write new file\n`;
        }
        
        details += `\n🎛️ Reply with "approve ${item.id}" or "deny ${item.id}"`;
        
        return this.formatResponse(details);
    }
}

// CLI usage
if (require.main === module) {
    const handler = new MessageHandler();
    const message = process.argv[2];
    
    if (!message) {
        console.log('Usage: message_handler.js "<message>"');
        process.exit(1);
    }
    
    handler.processMessage(message).then(response => {
        console.log(JSON.stringify(response, null, 2));
    }).catch(error => {
        console.error('Error:', error);
        process.exit(1);
    });
}

module.exports = MessageHandler;