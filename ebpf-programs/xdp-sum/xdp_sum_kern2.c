#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

__u64 mykperf_read_rdpmc__cycles(void) __ksym;

SEC("xdp")
int xdp_sum_func(struct xdp_md *ctx)
{
    __u64 ret;
    ret = mykperf_read_rdpmc__cycles();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = data + sizeof(*eth);
        if (iph + 1 > data_end)
            return XDP_PASS;
        iph->check = 0;
        iph->check = bpf_csum_diff(0, 0, iph, sizeof(*iph), 0);
    }
    ret = mykperf_read_rdpmc__cycles() - ret;
    if (ret < 0)
    {
        bpf_printk("Error: %d", ret);
        return XDP_PASS;
    }
    bpf_printk("Sum: %d", ret);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
