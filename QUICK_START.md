# Claude Control - Quick Start Guide

**Secure remote control for Claude Code with military-grade encryption and Telegram integration.**

## 🎯 What This Does

- ✅ **Approval Workflow**: All Claude Code operations require your secure approval
- ✅ **Command Interception**: Pre-Tool-Use hook catches every operation 
- ✅ **Queue System**: Operations wait for your decision (configurable timeout)
- ✅ **Secure Telegram Integration**: Direct Bot API with AES-256-GCM encryption
- ✅ **Military-Grade Security**: Input validation, rate limiting, audit logging

### File Structure
```
~/.claude-control/
├── config.json              # System configuration
├── scripts/
│   ├── claude_control_hook.js    # Main hook implementation
│   ├── secure_telegram_client.js # Telegram client with encryption
│   ├── approval_manager.js       # Queue management
│   └── message_handler.js        # Message processing
├── security.js              # Core security utilities
├── claude-control           # Control script
└── README.md                # Full documentation
```

## ⚡ Quick Setup (5 minutes)

### 1. Install Dependencies
```bash
cd ~/.claude-control
npm install
chmod +x claude-control
```

### 2. Configure Telegram Bot
```bash
# Create bot with @BotFather on Telegram
# Copy your bot token and chat ID
```

### 3. Update Configuration
Edit `config.json`:
```json
{
  "security": {
    "authorizedTelegramUsers": [YOUR_CHAT_ID_HERE]
  },
  "telegramEnabled": true
}
```

### 4. Start the System
```bash
./claude-control start
```

### 5. Test the Integration
```bash
./claude-control telegram test
./claude-control hook test
```

## 🚀 How It Works

1. **Claude Code attempts an operation** (Edit, Write, Bash, etc.)
2. **Pre-tool-use hook intercepts** and shows you exactly what will happen
3. **Secure notification sent** to your Telegram with code preview
4. **You approve or deny** via Telegram buttons or terminal
5. **Operation proceeds** only if approved

## 📱 Telegram Bot Setup

### Step 1: Create Bot
1. Message [@BotFather](https://t.me/botfather)
2. Send `/newbot` and choose a name
3. Copy the bot token

### Step 2: Get Chat ID
1. Start your bot (send `/start`)
2. Run: `./claude-control telegram test`
3. Your chat ID will be displayed in the output

### Step 3: Configure
Add your details to `config.json`:
```json
{
  "security": {
    "authorizedTelegramUsers": [123456789]
  },
  "telegramEnabled": true
}
```

## 🎮 Usage Commands

```bash
# System Control
./claude-control start       # Start approval system
./claude-control stop        # Stop approval system
./claude-control status      # Show system status

# Hook Management
./claude-control hook enable   # Enable Claude Code hook
./claude-control hook disable  # Disable Claude Code hook
./claude-control hook test     # Test approval flow

# Telegram
./claude-control telegram start  # Start Telegram polling
./claude-control telegram test   # Test bot connection

# Manual Approvals
./claude-control approve <id>    # Approve operation by ID
./claude-control deny <id>       # Deny operation by ID
./claude-control queue           # Show pending operations
```

## ⚙️ Configuration Options

### Hook Configuration (`hook-config.json`)
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

### Security Settings (`config.json`)
```json
{
  "security": {
    "authenticationRequired": true,
    "encryptionEnabled": true,
    "logAll": true,
    "denyByDefault": true
  }
}
```

## 🔒 Security Features

- **AES-256-GCM encryption** for all Telegram messages
- **Input validation** prevents injection attacks
- **Rate limiting** protects against spam
- **Audit logging** tracks all operations
- **Command whitelisting** blocks dangerous operations
- **Session management** with secure timeouts

## 🚨 Troubleshooting

### Bot Not Responding
```bash
./claude-control telegram test
```
Check token and network connection.

### Hook Not Working
```bash
./claude-control hook status
./claude-control hook enable
```

### Permissions Issues
```bash
chmod +x claude-control
chmod +x scripts/*.js
```

### Missing Dependencies
```bash
npm install
```

## 📊 Example Approval Flow

When Claude Code tries to edit a file, you'll see:

**Terminal:**
```
🤖 Claude Code wants to perform an operation:
🔧 Tool: Edit
📁 File: /path/to/file.js

📋 Changes:
❌ OLD: const old = "code";
✅ NEW: const improved = "better code";

[y/n/d] Approve? (timeout in 5 minutes)
```

**Telegram:**
```
🤖 Claude Code Approval Request [abc123]
⏰ Time: 14:30:25
🔧 Tool: Edit
📁 File: /path/to/file.js

📋 Changes:
❌ OLD:
```const old = "code";```

✅ NEW:
```const improved = "better code";```

🎛️ Reply with:
✅ "Approve abc123" to allow
❌ "Deny abc123" to block
```

## 🎯 Next Steps

1. **Read the full [README.md](README.md)** for advanced configuration
2. **Test the system** with some safe operations
3. **Customize approval patterns** in `hook-config.json`
4. **Set up monitoring** with the audit logs
5. **Join the community** for support and updates

---

**Need help?** Check the [full documentation](README.md) or [open an issue](https://github.com/norayesnir/claude-control/issues).