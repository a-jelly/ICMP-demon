#!/bin/bash
export PATH=$PATH:/usr/bin
echo "Go!"
REMOTE=$1
echo "Request from $REMOTE"
# recreate
HANDLE=`nft -a list table inet filter | grep -m1 "saddr $REMOTE" | awk '{print $NF}'`

if [ -z $HANDLE ]; then
    echo "Cannot find rule for addr $REMOTE!"
else
    nft delete rule inet filter input handle $HANDLE
    echo "Port 22 closed for $REMOTE"
fi
