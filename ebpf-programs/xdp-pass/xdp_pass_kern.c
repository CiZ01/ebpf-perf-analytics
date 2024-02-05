#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
    bpf_printk("PASS");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
