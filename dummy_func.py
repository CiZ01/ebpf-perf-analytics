from bcc import BPF

b = BPF(src_file="nat64.bpf.c", cflags=["-w"])

