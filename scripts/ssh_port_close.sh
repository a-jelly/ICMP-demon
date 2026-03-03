#!/bin/bash

export PATH=$PATH:/usr/bin

REMOTE="$1"
if [ -z "$REMOTE" ]; then
    echo "Usage: $0 <remote_ip>"
    exit 1
fi

echo "Request from $REMOTE"

# Got all opened ports for our IP
HANDLES=$(nft -a list chain inet filter input 2>/dev/null \
    | grep "saddr $REMOTE tcp dport 22" \
    | awk '{print $NF}')

if [ -z "$HANDLES" ]; then
    echo "No open rules found for $REMOTE"
    exit 1
fi

# Remove all one by one
COUNT=0
while IFS= read -r HANDLE; do
    nft delete rule inet filter input handle "$HANDLE"
    COUNT=$((COUNT + 1))
done <<< "$HANDLES"

echo "Port 22 closed for $REMOTE ($COUNT rule(s) removed)"