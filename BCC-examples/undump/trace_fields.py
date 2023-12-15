#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

from __future__ import print_function
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_SOURCE

prog = """
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""
b = BPF(text=prog, cflags=["-w"])

b.attach_uprobe(name="c", sym="main", fn_name="hello")


print("PID MESSAGE")
try:
    b.trace_print(fmt="{1} {5}")
except KeyboardInterrupt:
    exit()
