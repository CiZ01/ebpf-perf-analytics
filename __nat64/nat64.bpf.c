#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifdef AF_INET
#define AF_INTET 1
#endif

// router ip address
#define TRANSLATE_PREFIX 0x0064FF9B // 64:ff9b::/96

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

    // suddivido il csum a 32 bit in due parti di 16 bit
    // la prima parte la ottengo facendo lo shift a destra e la seconda parte facendo l'and
    // con una stringa di 16 bit tutti settati a 1 scritta in hex
    sum = (csum >> 16) + (csum & 0xffff);

    // nel caso superi 0xffff ci sarà del riporto che aggiungo qua
    sum += (sum >> 16);

    // inverte la stringa di bit prima di ritornarla
    return ~sum;
}

// natting table for translating IPv6 to IPv4
BPF_HASH(natting_table, u32, u32, 1024);

BPF_HASH(router_ip4, u32, u32, 32);

// nel caso del 6 va cambiato il tipo
// BPF_HASH(router_ip6, __u32, __be32, 32);

int xdp_6to4_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    const __u32 my_ifindex = ctx->ingress_ifindex;

    struct bpf_fib_lookup fib_params = {0};
    int rc;

    __u32 dst_v4;
    struct iphdr dst_hdr = {
        .version = 4,
        .ihl = 5,
        .frag_off = bpf_htons(1 << 14),
    };

    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    bpf_trace_printk("before dmac: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_trace_printk("before smac: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
            return XDP_DROP;

        // check if destination is in the NAT64 prefix
        if (bpf_htonl(ip6h->daddr.s6_addr32[0]) == TRANSLATE_PREFIX)
        {

            __u32 *router_ip = router_ip4.lookup(&my_ifindex);
            if (router_ip)
            {
                // bpf_trace_printk("router ip address %x", *router_ip);
            }
            else
            {
                bpf_trace_printk("[ERR]: router ip address not found");
                return XDP_DROP;
            }
            dst_v4 = ip6h->daddr.s6_addr32[3];
            dst_hdr.saddr = bpf_htonl((__be32)*router_ip);
            dst_hdr.daddr = dst_v4;

            dst_hdr.protocol = ip6h->nexthdr;
            dst_hdr.ttl = ip6h->hop_limit;
            dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

            if (ip6h->nexthdr == IPPROTO_ICMPV6)
            {
                struct icmp6hdr *icmp6 = data + sizeof(*eth) + sizeof(*ip6h);
                if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*icmp6) > data_end)
                    return XDP_DROP;

                struct icmphdr icmp;
                struct icmphdr *new_icmp;

                if (write_icmp(&icmp, icmp6) == -1)
                {
                    bpf_trace_printk("cant write icmp");
                    return XDP_DROP;
                }

                if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp6) - (int)sizeof(icmp)))
                    return XDP_DROP;

                // rifaccio i controlli
                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                // mi preparo il puntatore al icmp
                new_icmp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
                if (new_icmp + 1 > data_end)
                    return XDP_DROP;

                // e lo faccio puntare al pacchetto icmp settato prima
                *new_icmp = icmp;

                // quando in csum_diff il valore from_size == 0 e il valore to_size > 0
                // può essere utilizzata la funzione per aggiungere nuovi dati
                new_icmp->checksum =
                    csum_fold_helper(bpf_csum_diff((__be32 *)new_icmp, 0, (__be32 *)new_icmp, sizeof(new_icmp), 0));

                dst_hdr.protocol = IPPROTO_ICMP;
            } // ICMPv6
            dst_hdr.check =
                csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr) - (int)sizeof(struct iphdr)))
                return XDP_DROP;

            // devo ricalcolare data
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
4
            eth = (void *)(long)ctx->data;
            if (eth + 1 > data_end)
                return XDP_DROP;

            eth->h_proto = bpf_htons(ETH_P_IP);

            // preparo il nuovo pacchetto ipv4 da inviare
            struct iphdr *iph;
            iph = (void *)(data + sizeof(*eth));

            if (iph + 1 > data_end)
            {
                bpf_trace_printk("iph out of boundary");
                return XDP_DROP;
            }

            *iph = dst_hdr;

            // preparo i parametri per la ricerca all'interno della fib
            fib_params.family = AF_INET;
            fib_params.ipv4_dst = dst_v4;
            fib_params.ifindex = my_ifindex;
        } // NAT64 prefix check
        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
        switch (rc)
        {
        case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
            bpf_trace_printk("ifindex redirect %d", fib_params.ifindex);
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

            // DEBUG
            bpf_trace_printk("after dmac: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            bpf_trace_printk("after smac: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            bpf_trace_printk("ip destination: %d.%d.%d", fib_params.ipv4_dst >> 8 & 0xFF,
                             fib_params.ipv4_dst >> 16 & 0xFF, fib_params.ipv4_dst >> 24 & 0xFF);
            int action;
            action = bpf_redirect(fib_params.ifindex, 0);
            bpf_trace_printk("action %d", action);
            return action;
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
        case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
        case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
            bpf_trace_printk("route not found, check if routing suite is working properly");
        case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
        case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
            bpf_trace_printk("neigh entry missing");
        case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
            return XDP_PASS;
        }

    } // IPv6

    return XDP_PASS;
} // xdp_6to4_func

int xdp_4to6_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    const __u32 my_ifindex = ctx->ingress_ifindex;

    struct bpf_fib_lookup fib_params = {0};
    int rc;

    // PENSO NON SERVA PER L'IDEA MIA
    struct in6_addr v6_prefix;
    v6_prefix.s6_addr[1] = 0x64;
    v6_prefix.s6_addr[2] = 0xff;
    v6_prefix.s6_addr[3] = 0x9b;

    struct ipv6hdr dst_hdr = {.version = 6, .saddr = v6_prefix, .daddr = v6_prefix};

    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    bpf_trace_printk("before dmac: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_trace_printk("before smac: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return XDP_DROP;

        // check if destination is in the NAT64 prefix
        if (bpf_htonl(iph->daddr.s6_addr32[0]) == TRANSLATE_PREFIX)
        {

            __u32 *router_ip = router_ip4.lookup(&my_ifindex);
            if (router_ip)
            {
                // bpf_trace_printk("router ip address %x", *router_ip);
            }
            else
            {
                bpf_trace_printk("[ERR]: router ip address not found");
                return XDP_DROP;
            }
            dst_v4 = ip6h->daddr.s6_addr32[3];
            dst_hdr.saddr = bpf_htonl((__be32)*router_ip);
            dst_hdr.daddr = dst_v4;

            dst_hdr.protocol = ip6h->nexthdr;
            dst_hdr.ttl = ip6h->hop_limit;
            dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

            if (ip6h->nexthdr == IPPROTO_ICMPV6)
            {
                struct icmp6hdr *icmp6 = data + sizeof(*eth) + sizeof(*ip6h);
                if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*icmp6) > data_end)
                    return XDP_DROP;

                struct icmphdr icmp;
                struct icmphdr *new_icmp;

                if (write_icmp(&icmp, icmp6) == -1)
                {
                    bpf_trace_printk("cant write icmp");
                    return XDP_DROP;
                }

                if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp6) - (int)sizeof(icmp)))
                    return XDP_DROP;

                // rifaccio i controlli
                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                // mi preparo il puntatore al icmp
                new_icmp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
                if (new_icmp + 1 > data_end)
                    return XDP_DROP;

                // e lo faccio puntare al pacchetto icmp settato prima
                *new_icmp = icmp;

                // quando in csum_diff il valore from_size == 0 e il valore to_size > 0
                // può essere utilizzata la funzione per aggiungere nuovi dati
                new_icmp->checksum =
                    csum_fold_helper(bpf_csum_diff((__be32 *)new_icmp, 0, (__be32 *)new_icmp, sizeof(new_icmp), 0));

                dst_hdr.protocol = IPPROTO_ICMP;
            } // ICMPv6
            dst_hdr.check =
                csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr) - (int)sizeof(struct iphdr)))
                return XDP_DROP;

            // devo ricalcolare data
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;

            eth = (void *)(long)ctx->data;
            if (eth + 1 > data_end)
                return XDP_DROP;

            eth->h_proto = bpf_htons(ETH_P_IP);

            // preparo il nuovo pacchetto ipv4 da inviare
            struct iphdr *iph;
            iph = (void *)(data + sizeof(*eth));

            if (iph + 1 > data_end)
            {
                bpf_trace_printk("iph out of boundary");
                return XDP_DROP;
            }

            *iph = dst_hdr;

            // preparo i parametri per la ricerca all'interno della fib
            fib_params.family = AF_INET;
                            dst = dst_v4;
            fib_params.ifindex = my_ifindex;
        } // NAT64 prefix check
        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
        switch (rc)
        {
        case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
            bpf_trace_printk("ifindex redirect %d", fib_params.ifindex);
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

            // DEBUG
            bpf_trace_printk("after dmac: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            bpf_trace_printk("after smac: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            bpf_trace_printk("ip destination: %d.%d.%d", fib_params.ipv4_dst >> 8 & 0xFF,
                             fib_params.ipv4_dst >> 16 & 0xFF, fib_params.ipv4_dst >> 24 & 0xFF);
            int action;
            action = bpf_redirect(fib_params.ifindex, 0);
            bpf_trace_printk("action %d", action);
            return action;
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
        case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
        case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
            bpf_trace_printk("route not found, check if routing suite is working properly");
        case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
        case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
            bpf_trace_printk("neigh entry missing");
        case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
            return XDP_PASS;
        }

    } // IPv6

    return XDP_PASS;
} // xdp_4to6_func

int xdp_pass_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}
