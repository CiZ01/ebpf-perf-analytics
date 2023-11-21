#include <linux/bpf.h>

#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

// translate prefix
#define TRANSLATE_PREFIX 0x0064FF9B // 64:ff9b::/96
#define IPV4_PREFIX 0xc0a80900      // 192.168.9.0

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifdef AF_INET
#define AF_INTET 1
#endif

#ifdef AF_INET6
#define AF_INTET6 6
#endif

struct icmpv6_pseudo
{
    struct in6_addr saddr;
    struct in6_addr daddr;
    __u32 len;
    __u8 padding[3];
    __u8 nh;
} __attribute__((packed));

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
    iph->tos = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
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

static __always_inline int write_icmp6(struct icmphdr *icmp, struct icmp6hdr *icmp6)
{
    __u32 mtu;
    // 	/* These translations are defined in RFC6145 section 5.2 */
    // bpf_printk("inside write icmp with type: %d ,request is %d",icmp6->icmp6_type, ICMPV6_ECHO_REQUEST);
    switch (icmp->type)
    {
    case ICMP_ECHO:
        icmp6->icmp6_type = ICMPV6_ECHO_REQUEST;
        break;
    case ICMP_ECHOREPLY:
        icmp6->icmp6_type = ICMPV6_ECHO_REPLY;
        break;
    case ICMP_DEST_UNREACH:
        icmp6->icmp6_type = ICMPV6_DEST_UNREACH;
        switch (icmp->code)
        {
        case ICMP_NET_UNREACH:
        case ICMP_HOST_UNREACH:
        case ICMP_SR_FAILED:
        case ICMP_NET_UNKNOWN:
        case ICMP_HOST_UNKNOWN:
        case ICMP_HOST_ISOLATED:
        case ICMP_NET_UNR_TOS:
        case ICMP_HOST_UNR_TOS:
            icmp6->icmp6_code = ICMPV6_NOROUTE;
            break;
        case ICMP_PROT_UNREACH:
            icmp6->icmp6_type = ICMPV6_PARAMPROB;
            icmp6->icmp6_code = ICMPV6_UNK_NEXTHDR;
            icmp6->icmp6_pointer = bpf_htonl(offsetof(struct ipv6hdr, nexthdr));
        case ICMP_PORT_UNREACH:
            icmp6->icmp6_code = ICMPV6_PORT_UNREACH;
            break;
        case ICMP_FRAG_NEEDED:
            icmp6->icmp6_type = ICMPV6_PKT_TOOBIG;
            icmp6->icmp6_code = 0;
            mtu = bpf_ntohs(icmp->un.frag.mtu) + 20;
            /* RFC6145 section 6, "second approach" - should not be
             * necessary, but might as well do this
             */
            if (mtu < 1280)
                mtu = 1280;
            icmp6->icmp6_mtu = bpf_htonl(mtu);
        case ICMP_NET_ANO:
        case ICMP_HOST_ANO:
        case ICMP_PKT_FILTERED:
        case ICMP_PREC_CUTOFF:
            icmp6->icmp6_code = ICMPV6_ADM_PROHIBITED;
        default:
            return -1;
        }
        break;
    case ICMP_PARAMETERPROB:
        if (icmp->code == 1)
            return -1;
        icmp6->icmp6_type = ICMPV6_PARAMPROB;
        icmp6->icmp6_code = ICMPV6_HDR_FIELD;
        /* The pointer field not defined in the Linux header. This
         * translation is from Figure 3 of RFC6145.
         */
        switch (icmp->un.reserved[0])
        {
        case 0: /* version/IHL */
            icmp6->icmp6_pointer = 0;
            break;
        case 1: /* Type of Service */
            icmp6->icmp6_pointer = bpf_htonl(1);
            break;
        case 2: /* Total length */
        case 3:
            icmp6->icmp6_pointer = bpf_htonl(4);
            break;
        case 8: /* Time to Live */
            icmp6->icmp6_pointer = bpf_htonl(7);
            break;
        case 9: /* Protocol */
            icmp6->icmp6_pointer = bpf_htonl(6);
            break;
        case 12: /* Source address */
        case 13:
        case 14:
        case 15:
            icmp6->icmp6_pointer = bpf_htonl(8);
            break;
        case 16: /* Destination address */
        case 17:
        case 18:
        case 19:
            icmp6->icmp6_pointer = bpf_htonl(24);
            break;
        default:
            return -1;
        }
    default:
        return -1;
    }
    icmp6->icmp6_dataun.u_echo.identifier = icmp->un.echo.id;
    icmp6->icmp6_dataun.u_echo.sequence = icmp->un.echo.sequence;
    return 0;
}

// from 6 to 4
static inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// function from https://github.com/xdp-project/bpf-examples/blob/master/nat64-bpf/nat64_kern.c
static __always_inline void update_icmp_checksum(struct xdp_md *ctx, struct ipv6hdr *ip6h, void *icmp_before,
                                                 void *icmp_after, __u8 add)
{
    void *data = (void *)(unsigned long long)ctx->data;
    struct icmpv6_pseudo ph = {
        .nh = IPPROTO_ICMPV6, .saddr = ip6h->saddr, .daddr = ip6h->daddr, .len = ip6h->payload_len};
    __u16 h_before, h_after, offset;
    __u32 csum, u_before, u_after;

    /* Do checksum update in two passes: first compute the incremental
     * checksum update of the ICMPv6 pseudo header, update the checksum
     * using bpf_l4_csum_replace(), and then do a separate update for the
     * ICMP type and code (which is two consecutive bytes, so cast them to
     * u16). The bpf_csum_diff() helper can be used to compute the
     * incremental update of the full block, whereas the
     * bpf_l4_csum_replace() helper can do the two-byte diff and update by
     * itself.
     */
    csum = bpf_csum_diff((__be32 *)&ph, add ? 0 : sizeof(ph), (__be32 *)&ph, add ? sizeof(ph) : 0, 0);

    offset = ((void *)icmp_after - data) + 2;
    /* first two bytes of ICMP header, type and code */
    h_before = *(__u16 *)icmp_before;
    h_after = *(__u16 *)icmp_after;

    /* last four bytes of ICMP header, the data union */
    u_before = *(__u32 *)(icmp_before + 4);
    u_after = *(__u32 *)(icmp_after + 4);

    bpf_l4_csum_replace(ctx, offset, 0, csum, BPF_F_PSEUDO_HDR);
    bpf_l4_csum_replace(ctx, offset, h_before, h_after, 2);

    if (u_before != u_after)
        bpf_l4_csum_replace(ctx, offset, u_before, u_after, 4);
}

// from 4 to 6
static __always_inline __u16 calculate_icmp_checksum(__u16 *icmph, __u16 *ph)
{

    __u16 ret = 0;
    __u32 sum = 0;
    for (int i = 0; i < 40; i++)
    {
        sum += *ph++;
    }

    for (int i = 0; i < 4; i++)
    {
        sum += *icmph++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret = ~sum;
    return (ret);
}

static __always_inline int ipv6_addr_equal(struct in6_addr *a, struct in6_addr *b)
{
    if (a->s6_addr32[0] == b->s6_addr32[0] && a->s6_addr32[1] == b->s6_addr32[1] &&
        a->s6_addr32[2] == b->s6_addr32[2] && a->s6_addr32[3] == b->s6_addr32[3])
        return 1;
    return 0;
}
