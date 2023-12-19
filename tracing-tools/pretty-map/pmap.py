from argparse import ArgumentParser
import subprocess
import os
import re
import socket
import struct

DEFAULT_OURPUT_FILE = "output.csv"


def ipv4_int_to_str(ipv4_int):
    return socket.inet_ntoa(struct.pack("!I", ipv4_int))


def ipv6_ints_to_str(ipv6_ints):
    return ":".join([hex(socket.ntohs(int(value)))[2:] for value in ipv6_ints])


parser = ArgumentParser()
parser.add_argument("mapname", help="the file to read")
parser.add_argument(
    "--nzero", "-nz", help="do not print zero values", action="store_true"
)
parser.add_argument("--output", "-o", help="output to a csv file", type=str)

args = parser.parse_args()

OUTPUT_FILE = args.output if args.output else False
NZ_FLAG = args.nzero if args.nzero else False


mapname = args.mapname

# check if the map is pinned
if not os.path.isfile(f"/sys/fs/bpf/{mapname}"):
    print("Map does not pin")

    # check if the map exists
    ret = subprocess.run(["bpftool", "map", "show", "name", f"{mapname}"])
    if ret.returncode != 0:
        print("Map does not exist")
        exit(1)

    # pin the map
    ret = subprocess.run(
        [
            "bpftool",
            "map",
            "pin",
            "name",
            f"{mapname}",
            f"/sys/fs/bpf/{mapname}",
        ]
    )
    if ret.returncode != 0:
        print("Failed to pin map")
        exit(1)

    print("Map pinned")

if OUTPUT_FILE:
    with open(OUTPUT_FILE, "w") as output_file:
        output_file.write("ipv4;ipv6\n")

# read the map
with open(f"/sys/fs/bpf/{mapname}", "rb") as f:
    for line in f.readlines():
        if not line.startswith(b"#"):
            ipv4_str = ipv4_int_to_str(int(line.split(b":")[0]))

            ipv6_32_match = re.search(rb"\[([\d\s,]+)\]", line)
            ipv6_str = ipv6_ints_to_str(
                [
                    value.decode("utf-8")
                    for value in ipv6_32_match.group(1).split(b",")[:-1]
                ]
            )

            if (NZ_FLAG and ipv6_str != "0:0:0:0:0:0:0:0") or not NZ_FLAG:
                if OUTPUT_FILE:
                    with open(OUTPUT_FILE, "a") as output_file:
                        output_file.write(f"{ipv4_str};{ipv6_str}\n")
                else:
                    print(f"{ipv4_str};{ipv6_str}")
