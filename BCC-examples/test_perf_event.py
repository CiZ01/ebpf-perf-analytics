#!/usr/bin/env python
# Copyright (c) 2016 PLUMgrid
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import multiprocessing
import os
import time

text = """
BPF_PERF_ARRAY(cnt1, NUM_CPUS);
BPF_PERF_ARRAY(cnt2, NUM_CPUS);
BPF_ARRAY(prev, u64, NUM_CPUS);
BPF_ARRAY(prev2, u64, NUM_CPUS);
BPF_HISTOGRAM(stats, u64, 64);

int do_sys_getuid(void *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 val = cnt1.perf_read(CUR_CPU_IDENTIFIER);
    u64 val2 = cnt2.perf_read(CUR_CPU_IDENTIFIER);

    if (((s64)val < 0) && ((s64)val > -256))
        return 0;

    prev.update(&cpu, &val);
    prev2.update(&cpu, &val2);
    return 0;
}
int do_ret_sys_getuid(void *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 val = cnt1.perf_read(CUR_CPU_IDENTIFIER);
    u64 val2 = cnt2.perf_read(CUR_CPU_IDENTIFIER);

    if (((s64)val < 0) && ((s64)val > -256))
        return 0;

    u64 *pval = prev.lookup(&cpu);
    u64 *pval2 = prev2.lookup(&cpu);
    
    return 0;
}
"""
b = bcc.BPF(text=text, debug=0, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
event_name = b.get_syscall_fnname("getuid")
b.attach_kprobe(event=event_name, fn_name="do_sys_getuid")
b.attach_kretprobe(event=event_name, fn_name="do_ret_sys_getuid")
cnt1 = b["cnt1"]
cnt2 = b["cnt2"]
prev = b["prev"]
prev2 = b["prev2"]
try:
    cnt1.open_perf_event(bcc.PerfType.HARDWARE, bcc.PerfHWConfig.CPU_CYCLES)
    cnt2.open_perf_event(bcc.PerfType.HARDWARE, bcc.PerfHWConfig.INSTRUCTIONS)
except:
    raise

for i in range(0, 100):
    os.getuid()

print(prev.items())
print([prev2[i].value for i in range(0, multiprocessing.cpu_count())])
print(cnt2.items())
