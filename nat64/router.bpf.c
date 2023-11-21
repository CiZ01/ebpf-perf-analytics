#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include "nat64/nat_helpers.h"

#define IP_BOUNDARY_START 0xc0a80901 // 192.168.9.1
#define IP_BOUNDARY_END 0xc0a809fe   // 192.168.9.254

// nattinh table
BPF_HASH(natting_table, u32, struct in6_addr, 256);

/*
    reset the ip passed as parameter in the natting_table
*/
static inline int free_ip(__u32 ip)
{
    struct in6_addr *value;
    value = natting_table.lookup(&ip);
    if (value != NULL)
    {
        if (ipv6_addr_equal(value, NULL) == 0)
        {
            natting_table.update(&ip, NULL);
            return 0;
        }
        return -1;
    }
    return -1;
}

/*
    search inside the natting_table if the ip is already assigned
    if value == NULL the ip is free
    else the ip is already assigned

    After the search if the ip is free, the function assign the ipv6_addr to the ip

    this function is needed because call map.lookup()
    inside a for involve in a error by the verifier
*/
static inline int find_free_ip(__u32 ip, struct in6_addr *ipv6_addr)
{
    __u32 *value;
    value = natting_table.lookup(&ip);
    if (value != NULL)
    {
        if (*value == NULL)
        {
            natting_table.update(&ip, ipv6_addr);
            bpf_trace_printk("free ip: %pI6", ipv6_addr);
            return 0;
        }
    }
    return -1;
}

/*
    search inside the natting_table the ipv6_addr associated to the ipv4
    if the ipv4 is not found return 0
    else return 1 and set the ipv6_addr
*/
static inline int search_ipv4_from_ipv6(__u32 ip, struct in6_addr *ipv6_addr)
{
    struct in6_addr *value;
    value = natting_table.lookup(&ip);
    if (value != NULL)
    {
        if (ipv6_addr_equal(value, ipv6_addr) == 1)
        {
            return 0;
        }
    }
    return -1;
}

/*
    search inside the natting_table the ipv6_addr associated to the ipv4
    if the ipv4 is not found return 0
    else return 1 and set the ipv6_addr
*/
static inline int search_ipv6_from_ipv4(__u32 ip, struct in6_addr *ipv6_addr)
{
    struct in6_addr *value;

    value = natting_table.lookup(&ip);
    if (value != NULL)
    {
        // if finded ipv6 is different zero, the function return 0 (true)
        if (value != 0)
        {
            *ipv6_addr = *value;
            return 0;
        }
    }
    return -1;
}

int xdp_router_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct bpf_fib_lookup fib_params = {0};

    struct ethhdr eth_cpy;
    struct ethhdr *eth = data;
    struct iphdr *iph = {0};

    // ip protocol just for debugging
    __u8 ip_protocol = 0;

    __u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {

        memcpy(&eth_cpy, eth, sizeof(eth_cpy));

        struct ipv6hdr *ip6h = data + nh_off;
        if (ip6h + 1 > data_end)
            return XDP_DROP;

        // bpf_trace_printk("%pI6c", &ip6h->saddr);
        if (is_6to4(ip6h) == -1)
        {
            // forse ci sta un jump a una parte per il forward
            // bpf_trace_printk("it is not a 6to4 packet");
            return XDP_PASS;
        }

        // it must be defined here equal zero because the verifier
        __u32 assigned_ipv4 = 0;

        struct iphdr dst_hdr = {
            .version = 4,
            .ihl = 5,
            .frag_off = bpf_htons(1 << 14),
        };

        // search inside the natting_table the ipv6_addr associated to the ipv4
        for (__u32 ip = IP_BOUNDARY_START; ip <= IP_BOUNDARY_END; ip++)
        {
            int res = search_ipv4_from_ipv6(ip, &ip6h->saddr);
            if (res == 0)
            {
                assigned_ipv4 = ip;
                // bpf_trace_printk("ip:%pI4", &ip);
                break;
            }
        }

        // if the ipv4 is not found, search a free ipv4
        if (assigned_ipv4 == 0)
        {
            // searching a free ipv4
            for (__u32 ip = IP_BOUNDARY_START; ip <= IP_BOUNDARY_END; ip++)
            {
                int res = find_free_ip(ip, &ip6h->saddr);
                if (res == 0)
                {
                    assigned_ipv4 = ip;
                    break;
                }
            }
        }

        // if the ipv4 is not found, drop the packet
        if (assigned_ipv4 == 0)
        {
            bpf_trace_printk("no free ipv4");
            return XDP_DROP;
        }

        /*         if (ip6h->nexthdr == 0x3b)
                {
                    bpf_trace_printk("no next header");
                }
                else if (ip6h->nexthdr == 0x3a)
                {
                    bpf_trace_printk("icmp6 header");
                }
                else
                {
                    bpf_trace_printk("errore strano");
                    return XDP_DROP;
                } */

        // set the ipv4 header
        // set_4f6(&dst_hdr, ip6h, assigned_ipv4);

        dst_hdr.saddr = bpf_htonl((__be32)assigned_ipv4);
        dst_hdr.daddr = ip6h->daddr.s6_addr32[3];

        dst_hdr.protocol = ip6h->nexthdr;
        dst_hdr.ttl = ip6h->hop_limit;
        dst_hdr.tos = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

        // check if the packet is a icmpv6
        if (dst_hdr.protocol == IPPROTO_ICMPV6)
        {
            struct icmp6hdr *icmp6h = (void *)ip6h + sizeof(*ip6h);
            if (icmp6h + 1 > data_end)
                return XDP_DROP;

            // bpf_trace_printk("[IPV6]: icmp type -> %d", icmp6h->icmp6_type);

            // ready to parse the icmpv6 header in icmp
            struct icmphdr tmp_icmp;
            struct icmphdr *icmp;

            if (write_icmp(&tmp_icmp, icmp6h) == -1)
            {
                bpf_trace_printk("[ERR]: error during icpmv6 parse in icmp");
                return XDP_DROP;
            }

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp6h) - (int)sizeof(tmp_icmp)))
                return XDP_DROP;

            // after the adjust head I have to reassign the pointers
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            icmp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
            if (icmp + 1 > data_end)
                return XDP_DROP;

            // bpf_trace_printk("inside write icmp with type: %d ,request is %d", icmp->type, ICMPV6_ECHO_REQUEST);
            *icmp = tmp_icmp;

            // set the checksum
            icmp->checksum = 0x0000;
            icmp->checksum =
                csum_fold_helper(bpf_csum_diff((__be32 *)icmp, 0, (__be32 *)icmp, sizeof(struct icmphdr), 0));
            dst_hdr.protocol = IPPROTO_ICMP;

            // DEBUG
            ip_protocol = dst_hdr.protocol;
            bpf_trace_printk("checksum: %x", icmp->checksum);
        } // icmpv6

        dst_hdr.check = csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr) - (int)sizeof(struct iphdr)))
            return XDP_DROP;

        // after the adjust head I have to reassign the pointers
        eth = (void *)(long)ctx->data;
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        if (eth + 1 > data_end)
            return XDP_DROP;

        memcpy(eth, &eth_cpy, sizeof(*eth));
        eth->h_proto = bpf_htons(ETH_P_IP);

        // preparo il nuovo pacchetto ipv4 da inviare
        iph = (void *)(data + sizeof(*eth));

        if (iph + 1 > data_end)
        {
            bpf_trace_printk("iph out of boundary");
            return XDP_DROP;
        }

        *iph = dst_hdr;

        // start the forwarding

        // setting the fib_params
        fib_params.family = AF_INET;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;

    } // ipv6
    else
    {
        bpf_trace_printk("è arrivato un ipv4 random, lo passo");
        return XDP_DROP;
    }
    // forwarding
    int rc;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

        // DEBUG
        // bpf_trace_printk("PROTOCOL: %u", ip_protocol);
        // bpf_trace_printk("after dmac: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        // bpf_trace_printk("after smac: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        // bpf_trace_printk("SRC: %pI4 DST: %pI4", &iph->saddr, &iph->daddr);
        bpf_trace_printk("ifindex: %d", fib_params.ifindex);
        int action;
        action = bpf_redirect(fib_params.ifindex, 0);
        bpf_trace_printk("action %d", action);
        return action;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
        bpf_trace_printk("dest not allowed");
        return XDP_PASS;
    case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
        bpf_trace_printk("route not found, check if routing suite is working properly");
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
        bpf_trace_printk("neigh entry missing");
    case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
        return XDP_PASS;
    }

    return XDP_PASS;
}

int xdp_router_4_func(struct xdp_md *ctx)
{
    // bpf_trace_printk("ciaone!!!");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    int iphdr_len;
    struct ethhdr eth_cpy;
    __u16 h_proto;
    __u64 nh_off;
    int rc;
    struct bpf_fib_lookup fib_params = {0};
    struct in6_addr *fib_dst = (struct in6_addr *)fib_params.ipv6_dst;
    struct ipv6hdr dst_hdr = {.version = 6, .saddr = 0, .daddr = 0};

    int action;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
    {
        return XDP_DROP;
    }

    h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP))
    {

        __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
        iph = data + nh_off;

        if (iph + 1 > data_end)
        {
            return XDP_DROP;
        }

        /*
            I check if the packet is intended for an ipv6
            to do this I use the ipv4 prefix chosen for translation,
            shift 8 bits to the right to consider only the subnet, and
            discard the last 255 values.
            I do the same with the packet ip address but I do the shift
            to the left because has a different endian format.
        */
        if (bpf_htonl(iph->daddr << 8) != (IPV4_PREFIX >> 8))
        {
            bpf_trace_printk("not for me");
            return XDP_PASS;
        }

        // bpf_trace_printk("src address of received packet %pI4", &iph->saddr);
        iphdr_len = iph->ihl * 4;

        if (iphdr_len != sizeof(struct iphdr) || (iph->frag_off & ~bpf_htons(1 << 14)))
        {
            /*  bpf_trace_printk("v4: pkt src/dst %pI4/ %pI4 has IP options or is fragmented, dropping\n", &iph->daddr,
                        &iph->saddr); */
            return XDP_DROP;
        }

        // find the ipv6 address associated to the ipv4 dest address
        int res = search_ipv6_from_ipv4(bpf_htonl(iph->daddr), &dst_hdr.daddr);
        if (res == -1)
        {
            bpf_trace_printk("ipv6 address not found");
            return XDP_DROP;
        }

        // setting the source address
        dst_hdr.saddr.in6_u.u6_addr32[0] = bpf_htonl(TRANSLATE_PREFIX);
        dst_hdr.saddr.in6_u.u6_addr32[3] = iph->saddr;

        dst_hdr.nexthdr = iph->protocol;
        dst_hdr.hop_limit = iph->ttl;
        dst_hdr.priority = (iph->tos & 0x70) >> 4;
        dst_hdr.flow_lbl[0] = iph->tos << 4;
        dst_hdr.payload_len = bpf_htons(bpf_ntohs(iph->tot_len) - iphdr_len);
        if (dst_hdr.nexthdr == IPPROTO_ICMP)
        {
            struct icmphdr *icmp = (void *)iph + sizeof(*iph);
            if (icmp + 1 > data_end)
                return XDP_DROP;
            struct icmp6hdr icmp6;
            struct icmp6hdr *new_icmp6;

            // bpf_trace_printk("[IPV4]: icmp type -> %d", icmp->type);

            if (write_icmp6(icmp, &icmp6) == -1)
            {
                bpf_trace_printk("cant write icmp");
                return XDP_DROP;
            }

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp) - (int)sizeof(icmp6)))
                return XDP_DROP;
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            new_icmp6 = (void *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

            if (new_icmp6 + 1 > data_end)
            {
                bpf_trace_printk("new icmp");
                return XDP_DROP;
            }

            *new_icmp6 = icmp6;

            struct icmpv6_pseudo ph = {
                .nh = IPPROTO_ICMPV6, .saddr = dst_hdr.saddr, .daddr = dst_hdr.daddr, .len = dst_hdr.payload_len};
            // new_icmp6->icmp6_cksum = calculate_icmp_checksum((__u16 *)new_icmp6, (__u16 *)&ph);

            new_icmp6->icmp6_cksum = 0x0000;
            new_icmp6->icmp6_cksum =
                csum_fold_helper(bpf_csum_diff((__be32 *)new_icmp6, 0, (__be32 *)new_icmp6, sizeof(new_icmp6), 0));
            bpf_trace_printk("checksum in icmp %x", bpf_htonl(new_icmp6->icmp6_cksum));
            dst_hdr.nexthdr = IPPROTO_ICMPV6;
        }

        // bpf_printk("ipv6 destination in hdr %d", &dst_hdr.saddr);
        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr) - (int)sizeof(struct ipv6hdr)))
            return XDP_DROP;

        eth = (void *)(long)ctx->data;
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        if (eth + 1 > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
        eth->h_proto = bpf_htons(ETH_P_IPV6);
        ip6h = (void *)(data + sizeof(*eth));

        if (ip6h + 1 > data_end)
        {
            return XDP_DROP;
        }

        // non so se serve
        ip6h->saddr.s6_addr32[0] = 0;
        ip6h->saddr.s6_addr32[1] = 0;
        ip6h->saddr.s6_addr32[2] = 0;
        ip6h->saddr.s6_addr32[3] = 0;
        ip6h->daddr.s6_addr32[0] = 0;
        ip6h->daddr.s6_addr32[1] = 0;
        ip6h->daddr.s6_addr32[2] = 0;
        ip6h->daddr.s6_addr32[3] = 0;

        *ip6h = dst_hdr;
        ip6h->saddr = dst_hdr.saddr;

        fib_params.family = AF_INET6;
        *fib_dst = dst_hdr.daddr;
        // bpf_printk("ipv6 destination %pI6",fib_dst);
        // bpf_printk("ipv6 destination in hdr %pI6",&ip6h->saddr);
        fib_params.ifindex = ctx->ingress_ifindex;
        bpf_trace_printk("[IPV4]: SRC: %pI6", &ip6h->saddr);
        bpf_trace_printk("[IPV4]: DST: %pI6", &ip6h->daddr);

        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        switch (rc)
        {
        case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
            bpf_trace_printk("ifindex redirect %d", fib_params.ifindex);
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            // action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);

            action = bpf_redirect(fib_params.ifindex, 0);
            bpf_trace_printk("action %d", action);
            return action;
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
    }
    return XDP_PASS;
}

int xdp_pass_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}