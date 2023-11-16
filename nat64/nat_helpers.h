#include <linux/bpf.h>

#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

// translate prefix
#define TRANSLATE_PREFIX 0x0064FF9B // 64:ff9b::/96

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifdef AF_INET
#define AF_INTET 1
#endif

static __always_inline int is_6to4(struct ipv6hdr *ip6h)
{
    if (bpf_htonl(ip6h->daddr.s6_addr32[0]) == TRANSLATE_PREFIX)
    {
        return 0;
    }
    return -1;
}

static __always_inline void set_4f6(struct iphdr *iph, struct ipv6hdr *ip6h, __u32 new_ip4)
{
    iph->saddr = bpf_htonl((__be32)new_ip4);
    iph->daddr = ip6h->daddr.s6_addr32[3];

    iph->protocol = ip6h->nexthdr;
    iph->ttl = ip6h->hop_limit;
    iph->tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(iph));
}

static __always_inline int write_icmp(struct icmphdr *icmp, struct icmp6hdr *icmp6)
{
    __u32 mtu, ptr;
    // 	/* These translations are defined in RFC6145 section 5.2 */
    // bpf_trace_printk("inside write icmp with type: %d ,request is %d", icmp6->icmp6_type, ICMPV6_ECHO_REQUEST);
    switch (icmp6->icmp6_type)
    {
    case ICMPV6_ECHO_REQUEST:
        icmp->type = ICMP_ECHO;
        // icmp->type = 0;
        // bpf_trace_printk("changed type from %d to %d",icmp6->icmp6_type,icmp->type);
        break;
    case ICMPV6_ECHO_REPLY:
        icmp->type = ICMP_ECHOREPLY;
        break;
    case ICMPV6_DEST_UNREACH:
        icmp->type = ICMP_DEST_UNREACH;
        switch (icmp6->icmp6_code)
        {
        case ICMPV6_NOROUTE:
        case ICMPV6_NOT_NEIGHBOUR:
        case ICMPV6_ADDR_UNREACH:
            icmp->code = ICMP_HOST_UNREACH;
            break;
        case ICMPV6_ADM_PROHIBITED:
            icmp->code = ICMP_HOST_ANO;
            break;
        case ICMPV6_PORT_UNREACH:
            icmp->code = ICMP_PORT_UNREACH;
            break;
        default:
            return -1;
        }
        break;
    case ICMPV6_PKT_TOOBIG:
        icmp->type = ICMP_DEST_UNREACH;
        icmp->code = ICMP_FRAG_NEEDED;

        mtu = bpf_htonl(icmp6->icmp6_mtu) - 20;
        if (mtu > 0xffff)
            return -1;
        icmp->un.frag.mtu = bpf_htons(mtu);
        break;
    case ICMPV6_TIME_EXCEED:
        icmp->type = ICMP_TIME_EXCEEDED;
        break;
    case ICMPV6_PARAMPROB:
        switch (icmp6->icmp6_code)
        {
        case 0:
            icmp->type = ICMP_PARAMETERPROB;
            icmp->code = 0;
            break;
        case 1:
            icmp->type = ICMP_DEST_UNREACH;
            icmp->code = ICMP_PROT_UNREACH;
            ptr = bpf_ntohl(icmp6->icmp6_pointer);
            /* Figure 6 in RFC6145 - using if statements b/c of
             * range at the bottom
             */
            if (ptr == 0 || ptr == 1)
                icmp->un.reserved[0] = ptr;
            else if (ptr == 4 || ptr == 5)
                icmp->un.reserved[0] = 2;
            else if (ptr == 6)
                icmp->un.reserved[0] = 9;
            else if (ptr == 7)
                icmp->un.reserved[0] = 8;
            else if (ptr >= 8 && ptr <= 23)
                icmp->un.reserved[0] = 12;
            else if (ptr >= 24 && ptr <= 39)
                icmp->un.reserved[0] = 16;
            else
                return -1;
            break;
        default:
            return -1;
        }
        break;
    default:
        return -1;
    }
    icmp->un.echo.id = icmp6->icmp6_dataun.u_echo.identifier;
    icmp->un.echo.sequence = icmp6->icmp6_dataun.u_echo.sequence;
    return 0;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);

    sum += (sum >> 16);

    return ~sum;
}

static __always_inline int ipv6_addr_equal(struct in6_addr *a, struct in6_addr *b)
{
    if (a->s6_addr32[0] == b->s6_addr32[0] &&
        a->s6_addr32[1] == b->s6_addr32[1] &&
        a->s6_addr32[2] == b->s6_addr32[2] &&
        a->s6_addr32[3] == b->s6_addr32[3])
        return 1;
    return 0;
}
