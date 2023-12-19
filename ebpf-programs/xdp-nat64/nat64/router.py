import os
import ctypes
import pyroute2
import subprocess as sp
from argparse import ArgumentParser


# parse arguments
parser = ArgumentParser(description="XDP NAT64 router")
parser.add_argument(
    "-i",
    "--interface",
    type=str,
    required=True,
    help="Network interface to attach XDP program to",
)
parser.add_argument(
    "-m",
    "--mode",
    choices=["native", "skb"],
    default="native",
    help="XDP program mode",
)
parser.add_argument(
    "-p",
    "--program",
    type=str,
    required=True,
    help="Path to XDP program object file",
)

args = parser.parse_args()
mode = args.mode
interface = args.interface
bpf_program = args.program


def attach_xdp_program(mode, interface, bpf_program):
    sp.call(
        f"sudo xdp-loader load -m {mode} {interface} {bpf_program}",
        shell=True,
    )


def main():
    # load BPF program
    attach_xdp_program(mode, interface, bpf_program)


main()
