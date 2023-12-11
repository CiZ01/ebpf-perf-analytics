from bcc import BPF
import sys
from pyroute2 import IPRoute
from nat64.printer import *
from time import sleep
from configparser import ConfigParser
from ctypes import *
import socket
import binascii

HDR_FILE = "nat64/nat_helpers.h"


def ip_to_cint(ip_address) -> int:
    ip_binary = socket.inet_aton(ip_address)

    ip_hex = binascii.hexlify(ip_binary).decode("utf-8")

    return int(ip_hex, 16)


def load_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(path)

    return cfg


if len(sys.argv) > 1:
    if sys.argv[1] == "-c":
        # LOAD CONFIG
        cfg_path = sys.argv[2]
        cfg = load_cfg(cfg_path)

        # interfaces names are comma separated
        interfaces = cfg["INTERFACES"]["interfaces"].split(",")

        # router ip address for each interface
        ip_address = cfg["IP_ADDRESS"]
    else:
        interfaces = sys.argv[1:].copy()
        ip_address = {
            "veth_4": "192.168.1.1",
            "veth_6": "2000:db8:1::1",
        }
else:
    interfaces = ["veth0"]
    ip_address = {
        "veth_4": "192.168.1.1",
        "veth_6": "2000:db8:1::1",
    }

# check if the specified interface exists
ip = IPRoute()

try:
    in_idxs = [ip.link_lookup(ifname=interface)[0] for interface in interfaces]
except Exception as e:
    printx(e, "err")
    exit(1)

b = BPF(src_file="nat64.bpf.c", hdr_file=HDR_FILE, cflags=["-w"])

in_fn = b.load_func("xdp_router_func", BPF.XDP)

router_ip4 = b["router_ip4"]

for i in range(len(interfaces)):
    interface = interfaces[i]
    in_idx = in_idxs[i]

    b.attach_xdp(interface, in_fn, 0)
    router_ip4[c_uint32(in_idx)] = c_uint32(ip_to_cint(ip_address["veth_4"] + f"{i+1}"))
    printx(f"Attached XDP program to {interface}", "info")
print()


printx("Running...", "info")
while True:
    try:
        sleep(1)
        pass
    except KeyboardInterrupt:
        printx("Stopping...", "info")
        break


printx("Removing filter from device", "info")
for interace in interfaces:
    b.remove_xdp(interace, 0)
    printx(f"Removed XDP program from {interace}", "info")

printx("Done", "ok")
