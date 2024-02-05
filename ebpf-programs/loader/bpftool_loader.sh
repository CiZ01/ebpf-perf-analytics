#! /bin/bash


# this script is used to load xdp program using bpftool command

if [ $# -ne 4 ]; then
	echo "Usage: bloader <filename> <interface> <prog_name> <pin_dir>"
	exit 1
fi

PIN_PATH='/sys/fs/bpf'
filename=$1 
interface=$2
prog_name=$3
pin_dir=$4

# check if /sys/fs/bpf is mounted
if [ ! -d $PIN_PATH ]; then
	mount -t bpf bpffs $PIN_PATH
fi

# check if the interface exists
if [ ! -d "/sys/class/net/$interface" ]; then
	echo "Interface $interface does not exist"
	exit 1
fi

# check if the pin directory exists yet
if [ -d "$PIN_PATH/$pin_dir" ]; then
	echo "Pin directory $pin_dir already exists"
	exit 1
fi

# load xdp program
bpftool prog load $filename "$PIN_PATH/$pin_dir" || { echo "Failed to load the xdp program"; exit 1; }

# get the id of the loaded xdp program
prog_id=$(bpftool prog show --json | jq -r '.[] | select(.name=="'$prog_name'") | .id') || { echo "Failed to get the id of the xdp program"; exit 1; }

# attach the xdp program to the interface
bpftool net attach xdp id "$prog_id" dev "$interface"

echo "XDP program $prog_name loaded and attached to interface $interface"
echo $( bpftool prog show id $prog_id )

exit 0

