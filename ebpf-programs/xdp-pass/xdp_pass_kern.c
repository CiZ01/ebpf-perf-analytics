#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYPERF_START_TRACE_MULTIPLEXED(main);

    // volatile int cpu = bpf_get_smp_processor_id();

    BPF_MYPERF_END_TRACE_MULTIPLEXED(main);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
