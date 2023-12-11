from bcc import BPF


program = r"""
TRACEPOINT_PROBE(xdp, xdp_redirect){
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}

"""

b = BPF(text=program, cflags=["-w"])

while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        print("%-18.9f %-16s %-6d %-6d %-2x" % (ts, task, pid, cpu, flags))
    except KeyboardInterrupt:
        printx("Exiting...", "info")
        break

printx("Done", "ok")
exit(0)
