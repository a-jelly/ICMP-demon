#!/bin/bash
export PATH=$PATH:/usr/bin
echo "Go!"
REMOTE=$1
echo "Request from $REMOTE"
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; }
nft insert rule inet filter input ip saddr $REMOTE tcp dport 22 accept
echo "Port 22 opened for $REMOTE"
