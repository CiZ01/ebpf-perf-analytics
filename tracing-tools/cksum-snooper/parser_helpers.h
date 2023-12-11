#ifndef __PARSER_HELPERS_H
#define __PARSER_HELPERS_H
#endif

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#define MAX_UDP_SIZE 1480
#define MAX_ICMP_SIZE 1480

/****************************************************************/
/*                          PARSERS                             */
static inline __u8 parse_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
    {
        return -1;
    }
    return iph->protocol;
}

static inline __u8 parse_ipv6(void *data, void *data_end)
{
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if (ip6h + 1 > data_end)
    {
        return -1;
    }
    return ip6h->nexthdr;
}

/****************************************************************/
static inline __u16 get_cksum_icmp(void *data, void *data_end)
{
    struct icmphdr *icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (icmph + 1 > data_end)
    {
        return -1;
    }
    return (__u16)icmph->checksum;
}

static inline __u16 get_cksum_icmp6(void *data, void *data_end)
{
    struct icmp6hdr *icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (icmp6h + 1 > data_end)
    {
        return -1;
    }
    return (__u16)icmp6h->icmp6_cksum;
}

static inline __sum16 get_cksum_udp(void *data, void *data_end)
{
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (udph + 1 > data_end)
    {
        return -1;
    }
    return udph->check;
}

static inline __sum16 get_cksum_ip(struct iphdr *iph, void *data_end)
{
    if (iph + 1 > data_end)
    {
        return -1;
    }
    return iph->check;
}

static inline __u16 check_cksum_icmp(void *data, void *data_end)
{
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (icmp + 1 > data_end)
        return -1;

    struct icmphdr tmp_icmp = *icmp;

    __u32 csum = 0;
    __u16 new_csum;

    tmp_icmp.checksum = 0;
    csum = bpf_csum_diff(0, 0, (__be32 *)&tmp_icmp, sizeof(tmp_icmp), 0);
    if (csum == 0)
        return 0;

    // new_csum = csum_fold_helper(csum);

    return new_csum;
}

/*****************************************************************/
/*                          CHECKSUM                             */

static inline __u16 icmp_cksum(struct icmphdr *icmph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 volatile *buf = (void *)icmph;

    for (int i = 0; i < MAX_ICMP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
            break;
        csum_buffer += *buf;
        buf++;
    }

    if ((void *)(buf + 1) <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    return (__u16)~csum;
}

static inline __u16 udp_cksum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 volatile *buf = (void *)udph;

    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)(buf + 1) <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    return ~csum;
}

static inline __u32 sum16(__u16 *addr, __u8 len)
{
    __u32 sum = 0;

    for (int i = 0; i < len; i++)
        sum += *addr++;

    return sum;
}

static inline __u16 icmp6_cksum(struct ipv6hdr *ip6h, struct icmp6hdr *icmp6h, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 volatile *buf = (void *)icmp6h;

    // Compute checksum on ipv6 header, the icmp6 checksum include a ipv6 pseudo header
    csum_buffer += sum16((__u16 *)&ip6h->saddr, sizeof(ip6h->saddr) >> 1);
    csum_buffer += sum16((__u16 *)&ip6h->daddr, sizeof(ip6h->daddr) >> 1);
    csum_buffer += bpf_htons((__u16)ip6h->nexthdr);
    csum_buffer += ip6h->payload_len;

    // not needed, it seems that broke the checksum
    // it is already included in the icmp6 header
    // csum_buffer += icmp6h->icmp6_type;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_ICMP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)(buf + 1) <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    return ~csum;
}