#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_SAMPLED(main, 0, 0x01);

    bpf_printk("xdp_pass_func\n");

    BPF_MYKPERF_END_TRACE_SAMPLED(main, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
