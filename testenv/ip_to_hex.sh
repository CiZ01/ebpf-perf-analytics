#!/bin/bash

if [ $# -gt 2 ]; then
    echo "Usage: $0 <ip_address>"
    exit 1
fi

ip_address=$1

# check if the ip address is valid
if ! [[ $ip_address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Invalid IP address format"
    exit 1
fi

# convert ip to hex
hex_ip=$(printf '%02x' $(echo $ip_address | tr '.' ' '))

if [ "$2" = "-f" ]; then
	echo $hex_ip | sed 's/\(..\)\(..\)/\1\2:/g; s/:$//'
	exit 0
fi

echo "$hex_ip"

