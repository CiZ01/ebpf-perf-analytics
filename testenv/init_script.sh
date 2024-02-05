#! /bin/bash

ns_name=$1
MAGIC_IP='64:ff9::'

# mount bppfs point
# this should be performend inside this script because every time `ip exec` is called
# the mounts are wiped

mount -t bpf bpffs /sys/fs/bpf

# enabling forwarding
sysctl net.ipv4.conf.all.forwarding=1 > /dev/null
sysctl net.ipv6.conf.all.forwarding=1 > /dev/null

# start shell
bash --rcfile ~/."$ns_name"_bashrc
