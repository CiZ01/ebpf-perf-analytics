#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <bpf/bpf_tracing.h>
#include "mykperf_module.h"

#define MAX_ICMP_SIZE 1480

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

BPF_MYKPERF_INIT_TRACE();

static __always_inline __u16 icmp_cksum(struct icmphdr *icmph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)icmph;

    for (int i = 0; i < MAX_ICMP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
            break;
        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    return ~csum;
}

SEC("xdp")
int xdp_cksm_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE(main, 0);
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);
    struct icmphdr *icmph = data + sizeof(*eth) + sizeof(*iph);

    if ((void *)(icmph + 1) > data_end)
    {
        BPF_MYKPERF_END_TRACE(main, 0);
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_ICMP)
    {
        volatile __u16 csum;
        // 1
        csum = icmp_cksum(icmph, data_end);
        // 2
        csum = icmp_cksum(icmph, data_end);
        // 3
        csum = icmp_cksum(icmph, data_end);
        // 1
        csum = icmp_cksum(icmph, data_end);
        /* csum = icmp_cksum(icmph, data_end);
         // 3
         csum = icmp_cksum(icmph, data_end);
         // 1
         csum = icmp_cksum(icmph, data_end);
         // 2
         csum = icmp_cksum(icmph, data_end); */
    }

    BPF_MYKPERF_END_TRACE(main, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
