from bcc import BPF
from argparse import ArgumentParser
from pyroute2 import IPRoute
from time import sleep

HDR_FILE = "parser_helpers.h"

# manage options
parser = ArgumentParser(description="cksum-snooper")
parser.add_argument(
    "interface",
    type=str,
    help="Interface to attach XDP program to",
)
parser.add_argument(
    "-m",
    "--mode",
    type=str,
    required=False,
    default="skb",
    choices=["skb", "native"],
    help="XDP program mode",
)

args = parser.parse_args()

veth = args.interface
mode = BPF.XDP_FLAGS_SKB_MODE if args.mode == "skb" else BPF.XDP_FLAGS_DRV_MODE

ipr = IPRoute()
try:
    idx = ipr.link_lookup(ifname=veth)[0]
except IndexError:
    print(f"Interface {veth} not found")
    exit(1)

b = BPF(src_file="cksum-snpr.c", hdr_file=HDR_FILE, cflags=["-w"])

in_fn = b.load_func("xdp_cksum_func", BPF.XDP)

b.attach_xdp(veth, fn=in_fn, flags=mode)

print("Snooping on cksums. Ctrl+C to stop...")
while 1:
    try:
        sleep(1)
        """   _, _, _, _, _, msg = b.trace_fields()
        print(f"{msg}") """
    except KeyboardInterrupt:
        print("Exiting...")
        b.remove_xdp(veth, flags=mode)
        exit(0)
