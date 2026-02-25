#!/bin/bash

# Claude Code Pre-Tool-Use Hook for Remote Control
# This hook intercepts all tool calls and requires approval via secure channels

CONTROL_DIR="$HOME/.claude-control"
APPROVAL_SCRIPT="$CONTROL_DIR/scripts/approval_manager.js"
QUEUE_DIR="$CONTROL_DIR/queue"

# Ensure approval manager is executable
chmod +x "$APPROVAL_SCRIPT" 2>/dev/null

# Debug logging first
echo "🐛 HOOK CALLED: $(date)" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 Args count: $#" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 All args: $*" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 Arg 1: $1" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 Arg 2: $2" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 Arg 3: $3" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 PWD: $PWD" >> "$HOME/.claude-control/hook_debug.log"
echo "🐛 Environment:" >> "$HOME/.claude-control/hook_debug.log"
env | grep CLAUDE >> "$HOME/.claude-control/hook_debug.log"

# Check if STDIN has data
if [ ! -t 0 ]; then
    echo "🐛 STDIN available:" >> "$HOME/.claude-control/hook_debug.log"
    echo "🐛 Reading STDIN..." >> "$HOME/.claude-control/hook_debug.log"
    HOOK_INPUT=$(cat)
    echo "$HOOK_INPUT---" >> "$HOME/.claude-control/hook_debug.log"
else
    echo "🐛 No STDIN data available" >> "$HOME/.claude-control/hook_debug.log"
    HOOK_INPUT=""
fi

echo "🐛 HOOK INPUT: $HOOK_INPUT" >> "$HOME/.claude-control/hook_debug.log"

# Parse the JSON to extract tool information
TOOL_NAME=$(echo "$HOOK_INPUT" | node -e "
    try {
        const data = JSON.parse(require('fs').readFileSync('/dev/stdin', 'utf8'));
        console.log(data.tool_name || 'unknown');
    } catch(e) { console.log('unknown'); }
")

TOOL_PARAMS=$(echo "$HOOK_INPUT" | node -e "
    try {
        const data = JSON.parse(require('fs').readFileSync('/dev/stdin', 'utf8'));
        console.log(JSON.stringify(data.tool_input || {}));
    } catch(e) { console.log('{}'); }
")

# Create operation object
OPERATION=$(cat <<EOF
{
  "tool": "$TOOL_NAME",
  "params": $TOOL_PARAMS,
  "context": {
    "project": "$PWD",
    "user": "$USER",
    "timestamp": "$(date -Iseconds)"
  }
}
EOF
)

# Add to approval queue and get ID
echo "🐛 Adding to queue with operation: $OPERATION" >> "$HOME/.claude-control/hook_debug.log"
APPROVAL_OUTPUT=$(node "$APPROVAL_SCRIPT" add "$OPERATION" 2>&1)
echo "🐛 Approval script output: $APPROVAL_OUTPUT" >> "$HOME/.claude-control/hook_debug.log"
APPROVAL_ID=$(echo "$APPROVAL_OUTPUT" | grep -o '[0-9]*' | head -1 | tr -d '\n\r')
echo "🐛 Extracted approval ID: $APPROVAL_ID" >> "$HOME/.claude-control/hook_debug.log"

if [ -z "$APPROVAL_ID" ]; then
    echo '{"action": "deny", "reason": "Failed to add to approval queue"}'
    exit 0
fi

# Give a moment for file system operations to complete
sleep 0.5

# Secure Telegram notification is sent automatically by approval_manager.js

# Wait for approval with timeout (5 minutes)
TIMEOUT=300
ELAPSED=0
SLEEP_INTERVAL=1

echo "🐛 Starting approval wait loop for ID: $APPROVAL_ID" >> "$HOME/.claude-control/hook_debug.log"

while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$QUEUE_DIR/$APPROVAL_ID.json" ]; then
        STATUS=$(node -e "
            try {
                const fs = require('fs');
                const item = JSON.parse(fs.readFileSync('$QUEUE_DIR/$APPROVAL_ID.json', 'utf8'));
                console.log(item.status);
            } catch(e) {
                console.log('pending');
            }
        " 2>/dev/null)
        
        echo "🐛 Current status for $APPROVAL_ID: $STATUS (elapsed: ${ELAPSED}s)" >> "$HOME/.claude-control/hook_debug.log"
        echo "🐛 Looking for file: $QUEUE_DIR/$APPROVAL_ID.json" >> "$HOME/.claude-control/hook_debug.log"
        
        case "$STATUS" in
            "approved")
                echo "🐛 APPROVED - returning allow" >> "$HOME/.claude-control/hook_debug.log"
                echo '{"action": "allow"}'
                exit 0
                ;;
            "denied")
                echo "🐛 DENIED - returning deny" >> "$HOME/.claude-control/hook_debug.log"
                REASON=$(node -e "
                    try {
                        const fs = require('fs');
                        const item = JSON.parse(fs.readFileSync('$QUEUE_DIR/$APPROVAL_ID.json', 'utf8'));
                        console.log(item.reason || 'Operation denied by user');
                    } catch(e) {
                        console.log('Operation denied');
                    }
                " 2>/dev/null)
                echo "{\"action\": \"deny\", \"reason\": \"$REASON\"}"
                exit 0
                ;;
            *)
                # Still pending, continue waiting
                ;;
        esac
    else
        echo "🐛 Queue file not found: $QUEUE_DIR/$APPROVAL_ID.json" >> "$HOME/.claude-control/hook_debug.log"
        echo "🐛 Debug: QUEUE_DIR=$QUEUE_DIR, APPROVAL_ID=$APPROVAL_ID, HOME=$HOME" >> "$HOME/.claude-control/hook_debug.log"
        echo "🐛 Full path would be: $QUEUE_DIR/$APPROVAL_ID.json" >> "$HOME/.claude-control/hook_debug.log"
    fi
    
    sleep $SLEEP_INTERVAL
    ELAPSED=$((ELAPSED + SLEEP_INTERVAL))
done

# Timeout - deny by default
echo '{"action": "deny", "reason": "Approval timeout (5 minutes) - operation cancelled for security"}'
exit 0