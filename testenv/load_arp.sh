#! /bin/bash


# blue -> router
sudo ip netns exec blue sudo arp -i veth1 -s 192.168.1.2 a6:4c:cc:7d:35:77

# router -> blue
sudo ip netns exec router sudo arp -i veth3 -s 192.168.3.1 96:e4:4a:b6:cd:0d


# red -> router
sudo ip netns exec red sudo ip -6 neigh add 2000:0db8::1 lladdr 1a:ed:ee:3d:86:03 dev veth0

# router -> red
sudo ip netns exec router sudo ip -6 neigh add 2001:0db8::1 lladdr de:dc:35:8f:a6:d0 dev veth2

