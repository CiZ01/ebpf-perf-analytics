from bcc import BPF
from color import *
import sys
from pyroute2 import IPRoute

if len(sys.argv) > 1:
    interface = sys.argv[1]
else:
    interface = "veth0"

ip = IPRoute()

try:
    in_idx = ip.link_lookup(ifname=interface)[0]
except:
    printx(f"Interface {interface} not found", "err")
    exit(1)

b = BPF(src_file="router.bpf.c", cflags=["-w"])

in_fn = b.load_func("xdp_pass_func", BPF.XDP)

b.attach_xdp(interface, in_fn, 0)
printx("Running...", "info")
while True:
    try:
        pass
    except KeyboardInterrupt:
        printx("Stopping...", "info")
        break

printx("Removing filter from device", "info")
b.remove_xdp(interface, 0)
