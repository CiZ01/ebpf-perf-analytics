#! /bin/bash

veth1_addr="192.168.0.2"
veth0_addr="192.168.0.1"


ip link add veth0 type veth peer name veth1
ip addr add "$veth0_addr"/24 dev veth0

# setting namespace
ip netns add red
ip link set veth1 netns red

ip netns exec red ip addr add "$veth1_addr"/24 dev veth1

ip link set dev veth0 up
ip netns exec red ip link set dev veth1 up

#echo "Test..."

#ping -I veth0 "veth1_addr" || { echo "non connesso"; exit 1;} 

#ip netns exec red ping -I veth1 "$veth0_addr" || { echo "non connesso ns"; exit 1; }

echo "Done"
exit 0
