#!/bin/bash

# Claude Control Setup Script v2.0.0
# Secure remote control for Claude Code with Telegram integration

set -e

CONTROL_DIR="$HOME/.claude-control"
CLAUDE_SETTINGS="$HOME/.claude-code/settings/settings.json"

echo "🚀 Setting up Claude Control v2.0.0..."

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check if Node.js is installed
if ! command -v node >/dev/null 2>&1; then
    echo "❌ Node.js not found. Please install Node.js 16+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version $NODE_VERSION is too old. Please install Node.js 16+ first."
    exit 1
fi

echo "✅ Prerequisites check passed (Node.js $(node -v))"

# Create Claude Code settings directory if it doesn't exist
mkdir -p "$(dirname "$CLAUDE_SETTINGS")"

# Backup existing settings
if [ -f "$CLAUDE_SETTINGS" ]; then
    cp "$CLAUDE_SETTINGS" "$CLAUDE_SETTINGS.backup.$(date +%s)"
    echo "📁 Backed up existing Claude settings"
fi

# Create or update Claude Code settings with our hook
HOOK_SCRIPT="$CONTROL_DIR/hooks/pre_tool_use.sh"

# Read existing settings or create new ones
if [ -f "$CLAUDE_SETTINGS" ]; then
    SETTINGS=$(cat "$CLAUDE_SETTINGS")
else
    SETTINGS='{"hooks": []}'
fi

# Create new settings with our hook
NEW_SETTINGS=$(node -e "
const settings = $SETTINGS;
if (!settings.hooks) settings.hooks = [];

// Remove any existing Claude Control hooks
settings.hooks = settings.hooks.filter(h => !h.command || !h.command.includes('claude-control'));

// Add our secure hook
settings.hooks.push({
    event: 'pre_tool_use',
    command: '$HOOK_SCRIPT',
    description: 'Claude Control - Secure approval workflow'
});

console.log(JSON.stringify(settings, null, 2));
")

# Write new settings
echo "$NEW_SETTINGS" > "$CLAUDE_SETTINGS"
echo "⚙️  Updated Claude Code settings with secure hook"

# Set up configuration files
echo "📝 Setting up configuration files..."

# Copy example configs if they don't exist
if [ ! -f "$CONTROL_DIR/.env" ]; then
    cp "$CONTROL_DIR/.env.example" "$CONTROL_DIR/.env"
    echo "📄 Created .env file from example"
    echo "⚠️  Please edit .env and add your bot token and encryption keys!"
fi

if [ ! -f "$CONTROL_DIR/config.json" ]; then
    cp "$CONTROL_DIR/config.json.example" "$CONTROL_DIR/config.json"
    echo "📄 Created config.json file from example"
fi

if [ ! -f "$CONTROL_DIR/hook-config.json" ]; then
    cp "$CONTROL_DIR/hook-config.json.example" "$CONTROL_DIR/hook-config.json"
    echo "📄 Created hook-config.json file from example"
fi

# Install Node.js dependencies
echo "📦 Installing secure dependencies..."
cd "$CONTROL_DIR"
npm install --production

# Set up proper permissions
echo "🔒 Setting up secure permissions..."
chmod +x "$CONTROL_DIR/claude-control"
chmod +x "$CONTROL_DIR/hooks/pre_tool_use.sh"
chmod +x "$CONTROL_DIR/scripts"/*.js
chmod 600 "$CONTROL_DIR/.env" 2>/dev/null || true

# Create logs directory
mkdir -p "$CONTROL_DIR/logs"

echo ""
echo "✅ Claude Control setup complete!"
echo ""
echo "🎯 Next steps:"
echo "   1. Edit .env file with your Telegram bot token:"
echo "      nano $CONTROL_DIR/.env"
echo ""
echo "   2. Generate secure encryption keys:"
echo "      cd $CONTROL_DIR"
echo "      node -e \"console.log('ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))\" >> .env"
echo "      node -e \"console.log('SESSION_SECRET=' + require('crypto').randomBytes(64).toString('hex'))\" >> .env"
echo ""
echo "   3. Configure your Telegram chat ID in config.json"
echo ""
echo "   4. Test the system:"
echo "      ./claude-control status"
echo "      ./claude-control telegram test"
echo ""
echo "   5. Start Claude Control:"
echo "      ./claude-control start"
echo ""
echo "🔒 Security Features Enabled:"
echo "   • AES-256-GCM encryption"
echo "   • Multi-factor authentication"
echo "   • Rate limiting & input validation"
echo "   • Comprehensive audit logging"
echo "   • Memory leak prevention"
echo ""
echo "📖 For detailed instructions, see:"
echo "   • README.md - Complete documentation"
echo "   • QUICK_START.md - Quick setup guide"
echo "   • INSTALL.md - Installation instructions"
echo ""
echo "🎉 Your secure Claude Code remote control is ready!"