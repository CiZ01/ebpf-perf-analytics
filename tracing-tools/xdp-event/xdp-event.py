from bcc import BPF


program = """
TRACEPOINT_PROBE(cpu, ){
    bpf_trace_printk("xdp_redirect");
    return 0;
};

"""

b = BPF(text=program)

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
