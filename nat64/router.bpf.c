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
static inline void find_free_ip(__u32 ip, __u32 *assigned_ipv4, struct in6_addr ipv6_addr)
{
    __u32 *value;
    value = natting_table.lookup(&ip);
    if (value != NULL)
    {
        if (*value == NULL)
        {
            *assigned_ipv4 = ip;
            natting_table.update(&ip, &ipv6_addr);
            return;
        }
    }
    return;
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
        if (ipv6_addr_equal(value, NULL) == 0)
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

    struct ethhdr *eth = data;

    __u32 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = data + nh_off;
        if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
            return XDP_DROP;

        if (is_6to4(ip6h) == -1)
        {
            // forse ci sta un jump a una parte per il forward
            return XDP_PASS;
        }

        // it must be defined here equal zero because the verifier
        __u32 assigned_ipv4 = 0;

        struct iphdr dst_hdr = {
            .version = 4,
            .ihl = 5,
            .frag_off = bpf_htons(1 << 14),
        };

        for (__u32 ip = IP_BOUNDARY_START; ip <= IP_BOUNDARY_END; ip++)
        {
            find_free_ip(ip, &assigned_ipv4, ip6h->saddr);
            if (assigned_ipv4 != 0)
            {
                break;
            }
        }

        // set the ipv4 header
        set_4f6(&dst_hdr, ip6h, assigned_ipv4);

        // check if the packet is a icmpv6
        if (ip6h->nexthdr == IPPROTO_ICMPV6)
        {
            struct icmp6hdr *icmp6h = data + nh_off + sizeof(*ip6h);
            if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*icmp6h) > data_end)
                return XDP_DROP;

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

            icmp = (void *)(data + nh_off + sizeof(*ip6h));
            if (icmp + 1 > data_end)
                return XDP_DROP;

            *icmp = tmp_icmp;

            // set the checksum
            icmp->checksum = csum_fold_helper(bpf_csum_diff((__be32 *)icmp, 0, (__be32 *)icmp, sizeof(icmp), 0));

            dst_hdr.protocol = IPPROTO_ICMP;
        } // icmpv6

        dst_hdr.check = csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr) - (int)sizeof(struct iphdr)))
            return XDP_DROP;

        // after the adjust head I have to reassign the pointers
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

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

        // start the forwarding

        // setting the fib_params
        fib_params.family = AF_INET;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;

    } // ipv6

    // forwarding
    int rc;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

        // DEBUG
        bpf_trace_printk("lookup successful");
        int action;
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

    return XDP_PASS;
}