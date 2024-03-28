#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE(0);
__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE(main, 0);

    /* BPF_MYKPERF_START_TRACE(test, 0);
    BPF_MYKPERF_START_TRACE(test_2, 0);

    BPF_MYKPERF_END_TRACE(test_2, 0);

    BPF_MYKPERF_END_TRACE(test, 0); */

    BPF_MYKPERF_END_TRACE(main, 0);
    // volatile __u64 x = bpf_mykperf_read_rdpmc(0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
