# Claude Control - Quick Start Guide

**Secure remote control for Claude Code with military-grade encryption and Telegram integration.**

## 🎯 What This Does

- ✅ **Approval Workflow**: All Claude Code operations require your secure approval
- ✅ **Command Interception**: Pre-Tool-Use hook catches every operation 
- ✅ **Queue System**: Operations wait for your decision (configurable timeout)
- ✅ **Secure Telegram Integration**: Direct Bot API with AES-256-GCM encryption
- ✅ **Web Dashboard**: Mobile-friendly control interface with HTTPS
- ✅ **Military-Grade Security**: Input validation, rate limiting, audit logging

### File Structure
```
~/.claude-control/
├── config.json              # System configuration
├── .env                     # Environment variables (secrets)
├── hooks/
│   └── pre_tool_use.sh      # Claude Code hook script
├── scripts/
│   ├── approval_manager.js   # Core approval logic
│   ├── message_handler.js    # Processes your commands
│   ├── secure_telegram_client.js # Secure Telegram integration
│   └── secure_dashboard_server.js # HTTPS web interface
├── dashboard/
│   └── index.html           # Mobile control interface
└── queue/                   # Pending operations storage
```

## 🚀 Setup Instructions

### 1. Configure Environment Variables

```bash
# Copy and edit configuration
cp .env.example .env
cp config.json.example config.json
cp hook-config.json.example hook-config.json

# Generate secure encryption key (REQUIRED)
node -e "console.log('ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))" >> .env

# Generate session secret (REQUIRED)
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(64).toString('hex'))" >> .env
```

### 2. Configure Telegram Bot

```bash
# 1. Create a Telegram bot:
#    - Message @BotFather on Telegram
#    - Send: /newbot
#    - Follow prompts, save the bot token

# 2. Add bot token to .env file:
echo "TELEGRAM_BOT_TOKEN=your_bot_token_here" >> .env

# 3. Get your chat ID by running:
./claude-control telegram test
# Message your bot /start, then check logs for your chat ID

# 4. Add chat ID to config.json:
# Edit config.json and add your chat ID to:
# "telegramChatId": 123456789,
# "authorizedTelegramUsers": [123456789]
```

### 3. Start the System

```bash
# Test everything works
./claude-control status

# Start the approval system
./claude-control start

# Test the hook system
./claude-control hook test

# Enable the hook for Claude Code
./claude-control hook enable
```

## 🎮 How to Use

### Test the System
```bash
# This will trigger an approval request
echo '{"tool": "Write", "params": {"file_path": "/tmp/test.txt", "content": "Hello World"}}' | \
node scripts/claude_control_hook.js
```

### Approve Operations
**Via Telegram:**
- You'll get a message with ✅ Approve and ❌ Deny buttons
- Tap the button to approve/deny

**Via Terminal:**
- Run: `./claude-control approve <operation_id>`
- Or: `./claude-control deny <operation_id> "reason"`

**Via Web Dashboard:**
- Open: `https://localhost:8443` (or configured port)
- View pending operations and click Approve/Deny

### Emergency Controls
```bash
# Stop all operations
./claude-control stop

# Disable hook (allows Claude Code to run freely)
./claude-control hook disable

# Check system status
./claude-control status

# View pending approvals
./claude-control queue
```

## 🔒 Security Features

- **AES-256-GCM Encryption**: All messages encrypted end-to-end
- **Authentication**: Multi-factor auth (terminal + phone)
- **Rate Limiting**: Prevents abuse and spam
- **Input Validation**: Blocks XSS, injection, and path traversal
- **Audit Logging**: Complete operation history with timestamps
- **Session Management**: Secure sessions with rolling expiration
- **Memory Management**: Automatic cleanup prevents resource leaks

## 📱 Mobile-Optimized Telegram Interface

**Enhanced approval messages include:**
- 📋 **Operation Details**: Tool name, file paths, parameters
- 🔍 **Code Changes**: OLD vs NEW content with syntax highlighting  
- ⏰ **Timestamps**: When the request was made
- 🛡️ **Security Info**: Validation status and risk assessment
- 🎮 **One-tap Buttons**: ✅ Approve / ❌ Deny

## 🔧 Configuration

### Environment Variables (`.env`)
```bash
NODE_ENV=production
TELEGRAM_BOT_TOKEN=your_bot_token
ENCRYPTION_KEY=64_character_hex_string
SESSION_SECRET=64_character_hex_string
```

### Main Config (`config.json`)
```json
{
  "telegramEnabled": true,
  "telegramChatId": 123456789,
  "security": {
    "authorizedTelegramUsers": [123456789],
    "encryptionEnabled": true,
    "auditLog": true
  }
}
```

### Hook Config (`hook-config.json`)
```json
{
  "enabled": true,
  "allowTerminalApproval": true, 
  "allowPhoneApproval": true,
  "autoTimeoutMs": 300000,
  "requireApproval": ["Edit", "Write", "MultiEdit", "Bash"],
  "autoApprove": ["Read", "Glob", "Grep"]
}
```

## 🚨 Troubleshooting

### Bot Not Responding
```bash
# Test bot connection
./claude-control telegram test

# Check configuration
./claude-control status

# View logs
tail -f logs/security-*.log
```

### Hook Not Working
```bash
# Check hook status
./claude-control hook status

# Re-enable hook
./claude-control hook enable

# Test hook manually
./claude-control hook test
```

### Permission Issues
```bash
# Fix script permissions
chmod +x claude-control
chmod +x scripts/*.js
```

## 🎯 Next Steps

1. **Customize Security**: Edit `hook-config.json` for your workflow
2. **Monitor Activity**: Check `logs/` directory for security events
3. **Test Thoroughly**: Run various Claude Code operations to verify
4. **Backup Config**: Keep secure backups of your `.env` and `config.json`

---

**⚠️ Security Note**: Keep your `.env` file private and never commit it to version control. Regularly rotate your bot token and encryption keys for maximum security.