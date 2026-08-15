#!/bin/bash
# Auto-start CryptoSentinel on boot
# This script is called by the container startup process

cd /home/z/my-project
export PATH="$HOME/.npm-global/bin:$PATH"

# Check if server is already running
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null)
if [ "$HTTP" = "200" ]; then
    echo "CryptoSentinel already running"
    exit 0
fi

echo "Starting CryptoSentinel..."
bash /home/z/my-project/start-bulletproof.sh
