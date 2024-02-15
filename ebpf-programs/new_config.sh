#! /bin/bash

veth1_addr=192.168.0.2
veth0_addr=192.168.0.1

ip link add veth0 type veth peer name veth1
# setting namespace
ip netns add red
ip netns add blue

ip link set veth1 netns red
ip link set veth0 netns blue

ip netns exec blue ip addr add "$veth0_addr"/24 dev veth0
ip netns exec red ip addr add "$veth1_addr"/24 dev veth1

ip netns exec blue ip link set dev veth0 up
ip netns exec red ip link set dev veth1 up

#add mac addr
ip netns exec blue arp -s "$veth1_addr" 96:e4:4a:b6:cd:0d
ip netns exec red arp -s "$veth0_addr" 96:02:4f:ca:8f:2e
#echo "Test..."

#ping -I veth0 "veth1_addr" || { echo "non connesso"; exit 1;}

#ip netns exec red ping -I veth1 "$veth0_addr" || { echo "non connesso ns"; exit 1; }

echo "Done"
exit 0
