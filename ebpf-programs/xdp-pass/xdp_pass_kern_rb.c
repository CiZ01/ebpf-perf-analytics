#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_map SEC(".maps");
__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

BPF_MYKPERF_INIT_TRACE(0);

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE(main, 0);

    __u64 start, end;

    struct record *rec = {0};
    start = bpf_mykperf_read_rdpmc(0);

    end = bpf_mykperf_read_rdpmc(0);
    rec->value = end - start;

    bpf_ringbuf_output(&rb_map, rec, sizeof(struct record), BPF_RB_NO_WAKEUP);

    BPF_MYKPERF_END_TRACE(main, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
