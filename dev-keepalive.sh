#!/bin/bash
trap '' SIGPIPE SIGTERM
cd /home/z/my-project
while true; do
  NODE_OPTIONS="--unhandled-rejections=warn --max-old-space-size=512" npx next dev -p 3000 --webpack 2>&1
  sleep 3
done
