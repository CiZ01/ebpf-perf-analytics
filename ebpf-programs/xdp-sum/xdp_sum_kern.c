#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int onic_sum(int a) __ksym;

SEC("xdp")
int xdp_sum_func(struct xdp_md *ctx)
{
    int ret;
    ret = onic_sum(5);
    bpf_printk("Sum: %d", ret);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";