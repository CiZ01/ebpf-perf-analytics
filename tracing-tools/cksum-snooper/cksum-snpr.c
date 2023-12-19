#define BPF_LICENSE GPL

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include "parser_helpers.h"

static inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return (__u16)~csum;
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
        struct icmphdr *icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (icmph + 1 > data_end)
            return XDP_PASS;

        __u16 old_csum = icmph->checksum;

        icmph->checksum = 0;
        __u16 new_csum = icmp_cksum(icmph, data_end);

        if (new_csum != old_csum)
        {
            // Handle incorrect checksum
            bpf_trace_printk("Incorrect checksum: %x -- correct: %x", bpf_ntohs(old_csum), bpf_ntohs(new_csum));
        }

        /*
            after the checksum is calculated, the verifier complains about a possible
            out-of-bounds access to the data_end pointer.
            We need to reassign data_end and data.
        */
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;

        icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (icmph + 1 > data_end)
            return XDP_PASS;
        icmph->checksum = old_csum;
        break;
    }
    case IPPROTO_ICMPV6: {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if (ip6h + 1 > data_end)
        {
            return XDP_PASS;
        }

        struct icmp6hdr *icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (icmp6h + 1 > data_end)
        {
            return XDP_PASS;
        }

        __u16 old_cksum = icmp6h->icmp6_cksum;
        __u16 new_cksum;
        icmp6h->icmp6_cksum = 0;
        new_cksum = icmp6_cksum(ip6h, icmp6h, data_end);
        icmp6h->icmp6_cksum = old_cksum;

        if (new_cksum != old_cksum)
        {
            // Handle incorrect checksum
            bpf_trace_printk("Incorrect checksum: %x -- correct: %x", bpf_ntohs(old_cksum), bpf_ntohs(new_cksum));
        }

        /*
            after the checksum is calculated, the verifier complains about a possible
            out-of-bounds access to the data_end pointer.
            We need to reassign data_end and data.
        */
        void *data_end = (void *)(long)ctx->data_end;  
        void *data = (void *)(long)ctx->data;

        icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (icmp6h + 1 > data_end)
        {
            return XDP_PASS;
        }

        icmp6h->icmp6_cksum = old_cksum;
        break;
    }
    case IPPROTO_UDP: {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end)
        {
            return XDP_PASS;
        }

        struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udph + 1 > data_end)
        {
            return XDP_PASS;
        }
        __u16 old_cksum = udph->check;

        udph->check = 0;
        __u16 new_cksum = udp_cksum(iph, udph, data_end);
        udph->check = old_cksum;
        if (new_cksum != old_cksum)
        {
            // Handle incorrect checksum
            bpf_trace_printk("Incorrect checksum: %x -- correct: %x", old_cksum, new_cksum);
        }
        break;
    }
    default:
        return XDP_PASS;
    }

    return XDP_PASS;
}