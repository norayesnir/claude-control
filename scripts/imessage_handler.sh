#!/bin/bash

# iMessage Response Handler for Claude Code Remote Control
# Usage: Run this script to process your iMessage responses

CONTROL_DIR="$HOME/.claude-control"
MESSAGE_HANDLER="$CONTROL_DIR/scripts/message_handler.js"

echo "📱 Claude Code iMessage Control Active"
echo "💡 Reply to approval messages with: approve <id> or deny <id>"
echo "📝 Other commands: status, queue, help"
echo "🔄 Monitoring for new responses..."
echo ""

# Function to check for new messages and process commands
process_imessage_responses() {
    # Get recent messages from iMessage
    RECENT_MESSAGES=$(imsg --recent 5 --json 2>/dev/null || echo "[]")
    
    # Process each message for approval commands
    echo "$RECENT_MESSAGES" | jq -c '.[]?' 2>/dev/null | while read -r message; do
        if [ -z "$message" ]; then continue; fi
        
        TEXT=$(echo "$message" | jq -r '.text // empty' 2>/dev/null)
        TIMESTAMP=$(echo "$message" | jq -r '.timestamp // empty' 2>/dev/null)
        
        if [ -n "$TEXT" ]; then
            # Check if it's a control command
            if echo "$TEXT" | grep -E "^(approve|deny|status|queue|help|details)" >/dev/null; then
                echo "📨 Processing command: $TEXT"
                
                # Process the command
                RESPONSE=$(node "$MESSAGE_HANDLER" "$TEXT" 2>/dev/null | jq -r '.message // empty')
                
                if [ -n "$RESPONSE" ]; then
                    echo "📤 Sending response..."
                    echo "$RESPONSE" | imsg --text 2>/dev/null
                    echo "✅ Response sent"
                else
                    echo "❌ Failed to process command"
                fi
                echo ""
            fi
        fi
    done
}

# Monitor mode - check for new messages every 10 seconds
if [ "$1" = "--monitor" ]; then
    echo "🔄 Starting continuous monitoring mode..."
    while true; do
        process_imessage_responses
        sleep 10
    done
else
    # Single check mode
    process_imessage_responses
fi