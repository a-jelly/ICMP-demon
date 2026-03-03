#!/bin/bash

export PATH=$PATH:/usr/bin

REMOTE="$1"
if [ -z "$REMOTE" ]; then
    echo "Usage: $0 <remote_ip>"
    exit 1
fi

echo "Request from $REMOTE"

# Create table and chain if not exist
nft add table inet filter 2>/dev/null || true
nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; } 2>/dev/null || true

# Add reject if not yet
if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport 22 reject"; then
    nft add rule inet filter input tcp dport 22 reject
fi

# May be port was already  opened?
if nft list chain inet filter input 2>/dev/null | grep -q "saddr $REMOTE tcp dport 22 accept"; then
    echo "Port 22 already open for $REMOTE"
    exit 0
fi

# Add accept before reject
nft insert rule inet filter input ip saddr "$REMOTE" tcp dport 22 accept
echo "Port 22 opened for $REMOTE"