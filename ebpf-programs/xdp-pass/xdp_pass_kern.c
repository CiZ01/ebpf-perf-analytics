#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

#ifdef TRACE
const volatile long wakeup_data_size = 1000 * sizeof(struct record);

static __always_inline long get_flags()
{
    long sz;

    if (!wakeup_data_size)
        return 0;

    sz = bpf_ringbuf_query(&ring_output, BPF_RB_AVAIL_DATA);
    return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
#endif

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
