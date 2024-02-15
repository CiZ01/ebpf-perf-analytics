#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int get_perf_event(void) __ksym;

SEC("xdp")
int xdp_sum_func(struct xdp_md *ctx)
{
    int ret;
    ret = get_perf_event();
    bpf_printk("Sum: %d", ret);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";