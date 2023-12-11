#define BPF_LICENSE GPL

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include "parser_helpers.h"

static inline __u16 csum_fold_helper(__u64 csum)
{
    bpf_trace_printk("1. %x", csum);
    csum = (csum >> 16) + (csum & 0xffff);
    bpf_trace_printk("2. %x", csum);
    csum += (csum >> 16);
    bpf_trace_printk("3. %x", csum);

    bpf_trace_printk("4. %x", ~csum);
    return ~csum;
}

static inline __u16 check_icmp_cksum(void *data, void *data_end)
{
    struct icmp6hdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (icmp + 1 > data_end)
        return -1;

    //__u16 old_csum = icmp->checksum;
    __u16 new_csum;

    new_icmp.icmp6_cksum = 0;
    __u32 csum = 0;
    csum = bpf_csum_diff((__be32 *)icmp, sizeof(*icmp), (__be32 *)&new_icmp, sizeof(new_icmp), 0);
    new_csum = csum_fold_helper(csum);
    new_icmp.icmp6_cksum = new_csum;

    *icmp = new_icmp;
    return new_csum;
}

int xdp_cksum_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
    {
        return XDP_PASS;
    }
    bpf_trace_printk("daio");

    __u16 h_proto = eth->h_proto;

    __u8 ip_proto;
    switch (bpf_htons(h_proto))
    {
    case ETH_P_IP:
        ip_proto = parse_ipv4(eth, data_end);

        break;
    case ETH_P_IPV6:
        ip_proto = parse_ipv6(eth, data_end);
        break;
    default:
        return XDP_PASS;
    }

    switch (ip_proto)
    {
    case IPPROTO_ICMP: {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end)
            return XDP_PASS;

        __u16 cksum = get_icmp_cksum(data, data_end);
        __u16 new_csum = check_icmp_cksum(data, data_end);
        bpf_trace_printk("OLD: %x | NEW: %x", bpf_ntohs(cksum), bpf_ntohs(new_csum));
        break;
    }
    case IPPROTO_ICMPV6: {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if (ip6h + 1 > data_end)
        {
            return XDP_PASS;
        }
        __sum16 cksum = get_icmpv6_cksum(data, data_end);
        bpf_trace_printk("ICMPv6 cksum: %x", bpf_ntohs(cksum));
        break;
    }
    case IPPROTO_UDP: {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end)
        {
            return XDP_PASS;
        }
        __sum16 cksum = get_cksum_udp(data, data_end);
        bpf_trace_printk("UDP cksum: %x", bpf_ntohs(cksum));
        break;
    }
    default:
        return XDP_PASS;
    }

    return XDP_PASS;
}