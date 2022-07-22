#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF

prog = """
#include <linux/netdevice.h>

int gro_trace(struct pt_regs *cts, struct napi_struct *napi, struct sk_buff *skb){
    bpf_trace_printk("Pkt Size:\t%d\\n", skb->len );
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="napi_gro_receive", fn_name="gro_trace")

print("Start Tracing... Ctrl-C to stop")
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()

    print(ms.decode())
