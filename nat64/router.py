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
PROTO = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "58": "IPv6-ICMP",
}

flags = BPF.XDP_FLAGS_SKB_MODE


class in6_addr(Structure):
    _fields_ = [("in6_u", c_uint8 * 16)]


def gen_natting_table(table, start: hex, end: hex):
    """
    generate a series of ip4 address from a boundary in hex
    and assign to them a NULL value in the table
    """

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
        interfaces_6to4 = cfg["INTERFACES_6to4"]["interfaces"].split(",")
        interfaces_4to6 = cfg["INTERFACES_4to6"]["interfaces"].split(",")

        # router ip address for each interface
        ip_address = cfg["IP_ADDRESS"]
    else:
        # NOT WORKING
        interfaces_6to4 = sys.argv[1:].copy()
        ip_address = {
            "veth_4": "192.168.1.1",
            "veth_6": "2000:db8:1::1",
        }
else:
    # NOT WORKING
    interfaces_6to4 = ["veth0"]
    ip_address = {
        "veth_4": "192.168.1.1",
        "veth_6": "2000:db8:1::1",
    }

# check if the specified interface exists
ip = IPRoute()

try:
    in_idxs = [ip.link_lookup(ifname=interface)[0] for interface in interfaces_6to4]
except Exception as e:
    printx(e, "err")
    exit(1)

b = BPF(src_file="router.bpf.c", hdr_file=HDR_FILE, cflags=["-w"])
# print(b.disassemble_func("xdp_router_func"))

six_four_fn = b.load_func("xdp_router_func", BPF.XDP)
four_six_fn = b.load_func("xdp_router_4_func", BPF.XDP)

natting_table = b["natting_table"]
gen_natting_table(natting_table, IP_BOUNDARY_START, IP_BOUNDARY_END)

if True:
    # load 6 to 4 interface
    for i in range(len(interfaces_6to4)):
        interface = interfaces_6to4[i]
        in_idx = in_idxs[i]

        b.attach_xdp(interface, six_four_fn, flags)
        printx(f"Attached XDP program 6to4 to {interface}", "info")

if True:
    # load 4 to 6 interface
    for i in range(len(interfaces_4to6)):
        interface = interfaces_4to6[i]
        in_idx = in_idxs[i]

        b.attach_xdp(interface, four_six_fn, flags)
        printx(f"Attached XDP program 4to6 to {interface}", "info")
print()

printx("Running...", "info")

prev_dest_ip = 0
prev_src_ip = 0
pkt_counter = 0
prev_protocol = 0
printx("Trace:", "info")
while True:
    try:
        # print trace
        """(task, pid, cpu, flags, ts, msg) = b.trace_fields()
        msg = str(msg, encoding="utf-8")
        if msg.startswith("PROTOCOL"):
            prev_protocol = msg.split()[1]
        if msg.startswith("SRC"):
            ip_src, ip_dst = msg.split()[1], msg.split()[3]
            if prev_src_ip == ip_src and prev_dest_ip == ip_dst:
                pkt_counter += 1
                print(
                    f"| {ip_src} | {ip_dst} | [ {pkt_counter} ]",
                    end="\r",
                )
            else:
                prev_dest_ip = ip_dst
                prev_src_ip = ip_src
                print(
                    f"| {ip_src} | {ip_dst} | [ {pkt_counter} ]",
                    end="\r",
                )
                pkt_counter = 0"""
        sleep(1)
        pass
    except ValueError:
        continue
    except KeyboardInterrupt:
        print()
        printx("End Tracing \n", "info")
        printx("Stopping...", "info")
        break


printx("Removing filter from device", "info")
for interace in interfaces_6to4 + interfaces_4to6:
    b.remove_xdp(interace, flags)
    printx(f"Removed XDP program from {interace}", "info")

printx("Done", "ok")
