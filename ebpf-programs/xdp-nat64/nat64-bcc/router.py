from bcc import BPF
import sys
from pyroute2 import IPRoute
from printer import printx, print_event
from time import sleep
from configparser import ConfigParser
from ctypes import *
import socket
import binascii
from in6_struct import in6_addr

TRACE = 0

HDR_FILE = "nat64/nat_helpers.h"
IP_BOUNDARY_START = 0xC0A80901  # 192.168.9.1
IP_BOUNDARY_END = 0xC0A809FE  # 192.168.9.254

PROTO = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
}

flags = BPF.XDP_FLAGS_SKB_MODE


def gen_natting_table(table, start: hex, end: hex, csv_filename: str = None):
    """
    generate a series of ip4 address from a boundary in hex
    and assign to them a NULL value in the table
    """

    i_start, i_end = int(start), int(end)
    for ip in range(i_start, i_end):
        table[c_uint(ip)] = POINTER(in6_addr)()

    if csv_filename:
        with open(csv_filename, "r") as f:
            for line in f.readlines()[1:]:
                ip4, ip6 = line.split(";")
                ip4 = ip_to_hex(ip4)
                ip6 = ip6.strip()  # remove \n
                table[c_uint(ip4)] = POINTER(in6_addr)(in6_addr().setFromString(ip6))

    return


def ip_to_hex(ip_address) -> int:
    """
    convert an ip address in string format to an int
    in 16 bit hex format
    """
    ip_binary = socket.inet_aton(ip_address)

    ip_hex = binascii.hexlify(ip_binary).decode("utf-8")
    return int(ip_hex, 16)


def load_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(path)

    return cfg


if len(sys.argv) > 1:
    if "-c" in sys.argv:
        # LOAD CONFIG
        cfg_path = sys.argv[sys.argv.index("-c") + 1]
        cfg = load_cfg(cfg_path)

        # interfaces names are comma separated
        interfaces_6to4 = cfg["INTERFACES_6to4"]["interfaces"].split(",")
        interfaces_4to6 = cfg["INTERFACES_4to6"]["interfaces"].split(",")

        csv_filename = cfg["ADDRESSES_FILE"]["filename"]
    if "-t" in sys.argv:
        TRACE = 1

# check if the specified interface exists
ip = IPRoute()

try:
    in_idxs = [ip.link_lookup(ifname=interface)[0] for interface in interfaces_6to4]
except Exception as e:
    printx(e, "err")
    exit(1)

b = BPF(src_file="router.c", hdr_file=HDR_FILE, cflags=["-w", "-DTRACE=1"])

six_four_fn = b.load_func("xdp_router_func", BPF.XDP)
four_six_fn = b.load_func("xdp_router_4_func", BPF.XDP)

# set ip4_cnt
ip4_cnt = b["ip4_cnt"]
ip4_cnt[c_uint(0)] = c_uint(IP_BOUNDARY_START)

""" natting_4to6 = b["natting_4to6"]
gen_natting_table(natting_4to6, IP_BOUNDARY_START, IP_BOUNDARY_END, csv_filename)
 """
# load 6 to 4 interface
for i in range(len(interfaces_6to4)):
    interface = interfaces_6to4[i]
    in_idx = in_idxs[i]

    b.attach_xdp(interface, six_four_fn, flags)
    printx(f"Attached XDP program 6to4 to {interface}", "info")

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

if TRACE:
    printx("Trace:", "info")
    b["logs"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
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
