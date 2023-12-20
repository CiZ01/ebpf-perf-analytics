import sys
import ctypes
import pyroute2
import subprocess as sp
import resource as res
from configparser import ConfigParser
from time import sleep


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


def attach_xdp_program(mode, interface, bpf_program, section):
    # xdp-loader load -m skb -s xdp_router_6to4 veth-r-1 xdp_router_kern.o
    return sp.call(
        f"sudo xdp-loader load -m {mode} -s {section} {interface} {bpf_program}",
        shell=True,
    )


def detach_all_xdp_programs():
    for interface in interfaces_6to4:
        sp.call(f"sudo xdp-loader unload --all {interface}", shell=True)
    for interface in interfaces_4to6:
        sp.call(f"sudo xdp-loader unload --all {interface}", shell=True)


def main():
    res.setrlimit(res.RLIMIT_MEMLOCK, (-1, -1))
    # load BPF program
    mode = "skb"
    sections = ["xdp_router_6to4", "xdp_router_4to6"]
    bpf_program = "xdp_router_kern.o"

    for interface in interfaces_6to4:
        ret = attach_xdp_program(mode, interface, bpf_program, sections[0])
        if ret != 0:
            print(f"Error attaching XDP program to {interface}")
            detach_all_xdp_programs()
            exit(1)
        print(f"Attached XDP program 6to4 to {interface}")

    for interface in interfaces_4to6:
        ret = attach_xdp_program(mode, interface, bpf_program, sections[1])
        if ret != 0:
            print(f"Error attaching XDP program to {interface}")
            detach_all_xdp_programs()
            exit(1)
        print(f"Attached XDP program 4to6 to {interface}")

    print("Running...")
    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            print("Removing XDP programs...")
            detach_all_xdp_programs()
            exit(0)


if __name__ == "__main__":
    main()
