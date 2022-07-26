#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF

prog = """
#include <linux/netdevice.h>

int gro_entrance_trace(struct pt_regs *ctx, struct napi_struct *napi, struct sk_buff *skb){
    bpf_trace_printk("Before\t%d\t%d\t%d\\n", skb->protocol, skb->len, skb->data_len );
    return 0;
}
int gro_exit_trace(struct pt_regs *ctx, struct sk_buff *skb){
    bpf_trace_printk("After\t%x\t%d\t%d\\n", skb->protocol, skb->len, skb->data_len );
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="napi_gro_receive", fn_name="gro_entrance_trace")
b.attach_kprobe(event="netif_receive_skb_internal", fn_name="gro_exit_trace")

print("Start Tracing... Ctrl-C to stop")
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()

    print(ms.decode())
