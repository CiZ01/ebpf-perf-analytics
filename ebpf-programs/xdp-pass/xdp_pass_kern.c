#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

__u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

BPF_MYKPERF_INIT_TRACE();

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main, 0);

    //volatile int cpu = bpf_get_smp_processor_id();

    BPF_MYKPERF_END_TRACE_ARRAY(main, 0, 0);

    // bpf_printk("value: %lld\n", end - start);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
