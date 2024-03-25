#! /bin/bash

ifname=ens3fp0np0
vip_address=10.10.2.1
ip_src=10.10.2.1
ip_dst=10.10.2.2
mac_dst=1c:34:da:41:c8:05
ip_proto=17

# get opts
while getopts "p:" opt; do
    case $opt in
        p)
            case $OPTARG in
                "tcp")
                    ip_proto=6
                ;;
                "udp")
                    ip_proto=17
                ;;
                *)
                    echo "Invalid protocol: $proto" >&2
                    exit 1
                ;;
            esac
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
        ;;
    esac
done

#print opts

echo "Using interface: $ifname"
echo "Using VIP: $vip_address"
echo "Using source IP: $ip_src"
echo "Using destination IP: $ip_dst"
echo "Using destination MAC: $mac_dst"
echo "Using protocol: $ip_proto"

sudo ./xdp_tx_iptunnel -i $ifname -a $vip_address -p 5001 -s $ip_src -d $ip_dst -m $mac_dst -P $ip_proto