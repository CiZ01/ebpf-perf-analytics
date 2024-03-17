#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>

#include <linux/ip.h>

__u64 bpf_mykperf_read_rdpmc__cycles(void) __ksym;
__u64 bpf_mykperf_read_rdpmc__instructions(void) __ksym;

SEC("xdp")
int xdp_sum_func(struct xdp_md *ctx)
{
    __u64 ret;
    ret = bpf_mykperf_read_rdpmc__cycles();

    ret = bpf_mykperf_read_rdpmc__cycles() - ret;
    bpf_printk("value: %llu", ret);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
