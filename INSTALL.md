# Claude Control Installation Guide

## Quick Install

### 1. Prerequisites
- **Claude Code** installed and configured
- **Node.js 16+** and npm
- **Telegram account** (optional but recommended)

### 2. Installation
```bash
# Clone or download to Claude Code directory
cd ~/.claude-control
git clone https://github.com/your-username/claude-control.git .

# Install dependencies
npm install

# Make control script executable
chmod +x claude-control
```

### 3. Configuration
```bash
# Copy example configs
cp .env.example .env
cp config.json.example config.json
cp hook-config.json.example hook-config.json

# Edit configuration files
nano .env          # Add your bot token
nano config.json   # Add your chat ID
```

### 4. Telegram Setup (Optional)
1. **Create bot with [@BotFather](https://t.me/botfather)**
2. **Get bot token** and add to `.env`:
   ```env
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   ```
3. **Get your chat ID** by running:
   ```bash
   ./claude-control telegram test
   # Message your bot /start, then check logs for your chat ID
   ```
4. **Add chat ID** to `config.json`:
   ```json
   {
     "security": {
       "authorizedTelegramUsers": [123456789]
     },
     "telegramChatId": 123456789
   }
   ```

### 5. Start the System
```bash
# Test everything works
./claude-control status

# Start the approval system
./claude-control start

# Test the hook
./claude-control hook test
```

## Configuration Details

### Environment Variables (`.env`)
- `TELEGRAM_BOT_TOKEN` - Your Telegram bot token
- `TELEGRAM_ENABLED` - Enable/disable Telegram integration
- `SESSION_SECRET` - Secret for session encryption (generate new one)
- `ENCRYPTION_KEY` - Key for message encryption (32 bytes hex)

### Main Configuration (`config.json`)
- `telegramEnabled` - Enable Telegram integration
- `telegramChatId` - Your Telegram chat ID
- `security.authorizedTelegramUsers` - Array of authorized user IDs
- `requireApproval` - Tools that need approval
- `autoApprove` - Tools that auto-approve

### Hook Configuration (`hook-config.json`)
- `enabled` - Enable/disable the hook system
- `allowTerminalApproval` - Allow approval from terminal
- `allowPhoneApproval` - Allow approval from Telegram
- `autoTimeoutMs` - Timeout for approvals (milliseconds)
- `dangerousPatterns` - Regex patterns to block immediately

## Verification

### Test Bot Connection
```bash
./claude-control telegram test
# Should show: ✅ Secure bot connected: YourBot (@yourbotname)
```

### Test Hook System
```bash
./claude-control hook test
# Should prompt for approval with code changes visible
```

### Test Full Integration
```bash
./claude-control hook enable
# Try making a code change with Claude Code
# You should receive both terminal and Telegram notifications
```

## Troubleshooting

### Bot Token Issues
```bash
# Test connection
./claude-control telegram test

# Common issues:
# - Wrong token format
# - Token not active
# - Network connectivity
```

### Hook Not Working
```bash
# Check status
./claude-control hook status

# Enable hook
./claude-control hook enable

# Check logs
tail -f logs/security-*.log
```

### Permission Issues
```bash
# Make script executable
chmod +x claude-control

# Check file ownership
ls -la claude-control
```

### Dependencies
```bash
# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

## Security Notes

1. **Keep `.env` secure** - Never commit to git
2. **Use strong secrets** - Generate new session/JWT secrets
3. **Limit authorized users** - Only add trusted Telegram accounts
4. **Monitor logs** - Check `logs/` directory regularly
5. **Update regularly** - Keep dependencies current

## File Structure
```
~/.claude-control/
├── claude-control           # Control script
├── scripts/                 # Core scripts
│   ├── claude_control_hook.js  # Hook implementation
│   ├── secure_telegram_client.js
│   ├── approval_manager.js
│   └── message_handler.js
├── config.json             # Main config
├── .env                    # Environment vars
├── hook-config.json        # Hook settings
└── logs/                   # Log files
```

## Next Steps

1. **Customize approval rules** in `hook-config.json`
2. **Set up monitoring** for the log files
3. **Configure auto-start** on system boot (optional)
4. **Test thoroughly** with Claude Code operations

For support, see the [main README](README.md) or open an issue on GitHub.