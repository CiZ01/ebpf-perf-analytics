import sys
import ctypes
import pyroute2
import subprocess as sp
from configparser import ConfigParser


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


def attach_xdp_program(mode, interface, bpf_program):
    sp.call(
        # xdp-loader load -m skb -s xdp_router_6to4 veth-r-1 xdp_router_kern.o
        f"sudo xdp-loader load -m {mode} -s {section} {interface} {bpf_program}",
        shell=True,
    )


def main():
    # load BPF program
    attach_xdp_program(mode, interface, bpf_program)


main()
