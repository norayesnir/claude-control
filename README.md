# Claude Control - Secure Remote Control for Claude Code

## 🚀 Features

### 🛡️ **Military-Grade Security**

- **Input validation** and sanitization for all operations
- **Rate limiting** with automatic spam protection  
- **Message encryption** with AES-256-GCM
- **Session management** with secure timeouts
- **Comprehensive audit logging** for compliance
- **Command injection prevention** with whitelist filtering

### 📱 **Enhanced Telegram Integration**

- **See actual code changes** - OLD vs NEW code displayed beautifully
- **One-tap approvals** with interactive buttons
- **Mobile-optimized** formatting for easy reading
- **Real-time notifications** for all operations
- **Multiple notification channels** (Telegram + Terminal)

### 🎮 **Dual Approval System**

- **Terminal approval** - Type `y/n/d` when prompted  
- **Phone approval** - Tap buttons in Telegram
- **Race condition** - First approval wins
- **Auto-timeout** - Operations denied after 5 minutes
- **Easy toggle** - Enable/disable with one command

### 🔒 **Smart Operation Control**

- **Auto-approve** safe operations (Read, Glob, Grep)
- **Require approval** for file changes (Edit, Write, Bash)
- **Block dangerous** commands (rm -rf, sudo, etc.)
- **Customizable** patterns and rules

## 📦 Installation

### Prerequisites

- [Claude Code](https://claude.ai/code) installed and configured
- Node.js 16+
- Telegram account (optional but recommended)

### Quick Setup

1. **Clone or download** this repository to `~/.claude-control/`
2. **Install dependencies:**

   ```bash
   cd ~/.claude-control
   npm install
   ```

3. **Make control script executable:**

   ```bash
   chmod +x claude-control
   ```

4. **Configure Telegram** (optional):
   - Create a bot with [@BotFather](https://t.me/botfather)
   - Update `TELEGRAM_BOT_TOKEN` in `.env`
   - Get your chat ID and update config

5. **Start the system:**

   ```bash
   ./claude-control start
   ```

## ⚙️ Configuration

### Environment Variables (`.env`)

```env
# Telegram Configuration
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_ENABLED=true

# Security Settings  
ENCRYPTION_KEY=your_32_byte_hex_key
SESSION_SECRET=your_session_secret
JWT_SECRET=your_jwt_secret

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_MS=900000
```

### Hook Configuration (`hook-config.json`)

```json
{
  "enabled": true,
  "allowTerminalApproval": true,
  "allowPhoneApproval": true,
  "autoTimeoutMs": 300000,
  "requireApproval": ["Edit", "Write", "MultiEdit", "Bash"],
  "autoApprove": ["Read", "Glob", "Grep"],
  "dangerousPatterns": [
    "rm -rf", "sudo", "curl.*[|&;]"
  ]
}
```

### Main Configuration (`config.json`)

```json
{
  "security": {
    "authorizedTelegramUsers": [123456789],
    "authenticationRequired": true,
    "encryptionEnabled": true
  },
  "telegramEnabled": true,
  "telegramChatId": 123456789
}
```

## 🎮 Usage

### Control Commands

```bash
# System Control
./claude-control start              # Start the approval system
./claude-control stop               # Stop the approval system  
./claude-control status             # Show system status
./claude-control restart            # Restart the system

# Hook Control
./claude-control hook enable        # Enable approval hook
./claude-control hook disable       # Disable approval hook
./claude-control hook status        # Show hook status
./claude-control hook test          # Test the approval flow

# Telegram Control
./claude-control telegram start     # Start Telegram polling
./claude-control telegram test      # Test bot connection
./claude-control telegram status    # Show Telegram status

# Approval Management
./claude-control approve <id>       # Approve operation
./claude-control deny <id>          # Deny operation
./claude-control queue              # Show pending operations
```

### Approval Workflow

1. **Claude Code attempts an operation** (e.g., editing a file)
2. **Hook intercepts** and displays the operation details:

   ```
   🤖 Claude Code wants to perform an operation:
   🔧 Tool: Edit
   📁 File: /path/to/file.js
   
   📋 Changes:
   ❌ OLD:
   const old = "code";
   
   ✅ NEW:
   const improved = "better code";
   ```

3. **Notifications sent** to both terminal and Telegram
4. **You approve** from either location:
   - **Terminal:** Type `y` (approve), `n` (deny), or `d` (details)
   - **Telegram:** Tap ✅ Approve or ❌ Deny buttons

5. **Operation proceeds** or gets blocked based on your decision

## 📱 Telegram Setup

### Step 1: Create a Bot

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token

### Step 2: Get Your Chat ID  

1. Start your bot by messaging it `/start`
2. Run `./claude-control telegram test` to see your chat ID in the logs
3. Add your chat ID to the config

### Step 3: Configure and Test

1. Update `.env` with your bot token
2. Update `config.json` with your chat ID
3. Run `./claude-control telegram test` to verify connection

## 🔐 Security Features

### Operation Filtering

- **Safe operations** (Read, Glob, Grep) are auto-approved
- **File changes** (Edit, Write) require approval
- **Bash commands** are analyzed for dangerous patterns
- **Dangerous operations** are immediately blocked

### Encryption & Authentication  

- All Telegram messages are encrypted with AES-256-GCM
- Session-based authentication with secure timeouts
- Rate limiting to prevent spam and abuse
- Comprehensive audit logging for compliance

### Input Validation

- All user inputs are sanitized and validated
- XSS and injection attack prevention
- Path traversal protection for file operations
- Command injection prevention with whitelisting

## 🛠️ Advanced Configuration

### Custom Approval Patterns

Edit `hook-config.json` to customize which operations require approval:

```json
{
  "requireApproval": ["Edit", "Write", "MultiEdit", "Bash", "CustomTool"],
  "autoApprove": ["Read", "Glob", "Grep"],
  "dangerousPatterns": [
    "rm -rf", "sudo", "curl.*[|&;]", "your_custom_pattern"
  ]
}
```

### Timeout Configuration

Adjust the auto-timeout period:

```json
{
  "autoTimeoutMs": 600000  // 10 minutes
}
```

### Notification Channels

Enable/disable notification channels:

```json
{
  "allowTerminalApproval": true,
  "allowPhoneApproval": true
}
```

## 🚨 Troubleshooting

### Common Issues

**Bot not responding:**

```bash
./claude-control telegram test
```

Check your bot token and network connection.

**Hook not intercepting operations:**

```bash
./claude-control hook status
./claude-control hook enable
```

**Permission denied:**

```bash
chmod +x claude-control
```

**Missing dependencies:**

```bash
npm install
```

### Debug Mode

Enable verbose logging by setting `LOG_LEVEL=debug` in `.env`:

```env
LOG_LEVEL=debug
```

## 📚 API Reference

### Hook Integration

To integrate with Claude Code hooks, implement the tool call handler:

```javascript
const ClaudeControlHook = require('./scripts/claude_control_hook.js');

const hook = new ClaudeControlHook();

// Handle tool calls
const result = await hook.handleToolCall({
  tool: 'Edit',
  params: {
    file_path: '/path/to/file.js',
    old_string: 'old code',
    new_string: 'new code'
  }
});

console.log(result.allowed); // true/false
```

### Approval Manager

Programmatically add operations to the approval queue:

```javascript
const ApprovalManager = require('./scripts/approval_manager.js');

const manager = new ApprovalManager();
const id = await manager.addToQueue({
  tool: 'Edit',
  params: { /* operation parameters */ }
});
```

## 🔧 Development

### Project Structure

```
.claude-control/
├── scripts/
│   ├── claude_control_hook.js       # Main hook implementation
│   ├── secure_telegram_client.js    # Secure Telegram client with AES-256-GCM
│   ├── approval_manager.js          # Approval queue management
│   └── message_handler.js           # Secure message processing
├── claude-control                   # Control script (./claude-control commands)
├── config.json                      # Main configuration
├── security.js                      # Core security utilities
└── README.md                        # Documentation
```

### Adding Custom Tools

To add support for custom tools, update the hook configuration:

```json
{
  "requireApproval": ["Edit", "Write", "YourCustomTool"],
  "customToolHandlers": {
    "YourCustomTool": "./custom_handlers/your_tool.js"
  }
}
```

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable  
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/norayesnir/claude-control.git
cd claude-control
npm install
npm test
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Claude Code](https://claude.ai/code) - The amazing AI coding assistant
- [Telegram Bot API](https://core.telegram.org/bots/api) - For the messaging integration
- The open source community for inspiration and feedback

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/norayesnir/claude-control/issues)
- **Discussions:** [GitHub Discussions](https://github.com/norayesnir/claude-control/discussions)
- **Security:** Email <security@yourdomain.com> for security-related issues

---

**Made with ❤️ for the Claude Code community**

*Transform your AI coding experience with military-grade security and beautiful approvals!* 🚀✨

<a href="https://buymeacoffee.com/rinseschaeh" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>