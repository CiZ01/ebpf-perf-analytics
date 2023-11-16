from bcc import BPF
import sys
from pyroute2 import IPRoute
from color import *
from time import sleep
from configparser import ConfigParser
from ctypes import *
import socket
import binascii

HDR_FILE = "nat64/nat_helpers.h"
IP_BOUNDARY_START = 0xC0A80901  # 192.168.9.1
IP_BOUNDARY_END = 0xC0A809FE  # 192.168.9.254


def gen_natting_table(table, start: hex, end: hex):
    """
    generate a series of ip4 address from a boundary in hex
    and assign to them a NULL value in the table
    """ 
    class in6_addr(Structure):
        _fields_ = [("in6_u", c_uint8 * 16)]

    i_start, i_end = int(start), int(end)
    for ip in range(i_start, i_end):
        table[c_uint(ip)] = POINTER(in6_addr)()
    return


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

b = BPF(src_file="router.bpf.c", hdr_file=HDR_FILE, cflags=["-w"])
# print(b.disassemble_func("xdp_router_func"))

in_fn = b.load_func("xdp_router_func", BPF.XDP)


natting_table = b["natting_table"]
gen_natting_table(natting_table, IP_BOUNDARY_START, IP_BOUNDARY_END)

for i in range(len(interfaces)):
    interface = interfaces[i]
    in_idx = in_idxs[i]

    b.attach_xdp(interface, in_fn, 0)
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
