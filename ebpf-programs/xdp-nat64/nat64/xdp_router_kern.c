#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "nat_helpers.h"

#define IP_BOUNDARY_START 0xc0a80901 // 192.168.9.1
#define IP_BOUNDARY_END 0xc0a809fe   // 192.168.9.254

#ifdef DEBUG
#define bpf_trace_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_trace_printk(fmt, ...)                                                                                     \
    {                                                                                                                  \
    }
#endif

struct ipv6_addr32
{
    __be32 addr[4];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ipv6_addr32);
    __uint(max_entries, 256);
} natting_table_4to6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_addr32);
    __type(value, __u32);
    __uint(max_entries, 256);
} natting_table_6to4 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} ip4_cnt SEC(".maps");

static inline int free_ip_4to6(__u32 ip)
{
    struct ipv6_addr32 *value;
    value = bpf_map_lookup_elem(&natting_table_4to6, &ip);
    if (value != NULL)
    {
        if (ipv6_addr_equal(value->addr, NULL) == 0)
        {
            bpf_map_update_elem(&natting_table_4to6, &ip, NULL, BPF_ANY);
            return 0;
        }
        return -1;
    }
    return -1;
}

static inline int assign_ipv4_to_ipv6(__be32 ipv6_addr[4], __u32 *ip)
{
    int zero = 0;
    __u32 *last_ip = bpf_map_lookup_elem(&ip4_cnt, &zero);
    if (last_ip)
    {
        if (*last_ip + 1 < IP_BOUNDARY_END)
        {
            struct ipv6_addr32 addr32;
            bpf_probe_read_kernel(&addr32.addr, sizeof(addr32.addr), ipv6_addr);

            // update the natting table
            bpf_map_update_elem(&natting_table_6to4, &addr32, last_ip, BPF_ANY);
            bpf_map_update_elem(&natting_table_4to6, last_ip, &addr32, BPF_ANY);

            // update the counter
            bpf_map_update_elem(&ip4_cnt, &zero, last_ip, BPF_ANY);

            // set the ipv4 address
            *ip = *last_ip;
            return 0;
        }
    }
    return -1;
}

static inline int find_free_ip_6to4(struct ipv6_addr32 *ipv6_addr, __u32 ip)
{
    __u32 *value;
    value = bpf_map_lookup_elem(&natting_table_6to4, &ip);
    if (value)
    {
        if (*value)
        {
            bpf_map_update_elem(&natting_table_6to4, &ip, ipv6_addr, BPF_ANY);
            return 0;
        }
    }
    return -1;
}

static inline int search_ipv4_from_ipv6(struct ipv6_addr32 *ipv6_addr, __u32 ip)
{
    struct ipv6_addr32 *value;
    value = bpf_map_lookup_elem(&natting_table_6to4, &ip);
    if (value)
    {
        if (ipv6_addr_equal(value->addr, ipv6_addr->addr) == 1)
        {
            return 0;
        }
    }
    return -1;
}

static inline int search_ipv6_from_ipv4(__u32 ip, __be32 *ipv6_addr)
{
    struct ipv6_addr32 *value;

    value = bpf_map_lookup_elem(&natting_table_4to6, &ip);
    if (value)
    {
        // if found ipv6 is not zero, the function returns 0
        if (value != 0)
        {
            return bpf_probe_read_kernel(ipv6_addr, sizeof(value->addr), value->addr);
        }
    }
    return -1;
}

SEC("xdp_router_6to4")
int xdp_router_6to4_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 rc;
    int ret;

    struct bpf_fib_lookup fib_params = {0};

    struct ethhdr eth_cpy;
    struct ethhdr *eth = data;
    struct iphdr *iph = {0};
    __u8 action;

    __u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {

        memcpy(&eth_cpy, eth, sizeof(eth_cpy));

        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if (ip6h + 1 > data_end)
            return XDP_DROP;

        if (bpf_htonl(ip6h->daddr.s6_addr32[0]) != TRANSLATE_PREFIX)
        {
            // if the packet is not a 6to4, forward it
            fib_params.family = AF_INET6;
            *(struct in6_addr *)fib_params.ipv6_dst = ip6h->daddr;
            fib_params.ifindex = ctx->ingress_ifindex;

            bpf_trace_printk("entro qa");

            goto forward;
        }

        // it must be defined here equal zero because the verifier
        __u32 *assigned_ipv4 = 0;

        struct iphdr dst_hdr = {
            .version = 4,
            .ihl = 5,
            .frag_off = bpf_htons(1 << 14),
        };

        struct ipv6_addr32 ipv6_addr_key;

        // Copy values from src_array to dest_array
        memcpy(ipv6_addr_key.addr, ip6h->daddr.in6_u.u6_addr32, sizeof(ip6h->daddr.in6_u.u6_addr32));

        // find the ipv4 address associated to the ipv6 dest address
        assigned_ipv4 = bpf_map_lookup_elem(&natting_table_6to4, &ipv6_addr_key);
        // if the ipv4 is not found, search a free ipv4 to assign
        if (assigned_ipv4)
        {
            ret = assign_ipv4_to_ipv6(ip6h->daddr.in6_u.u6_addr32, assigned_ipv4);
            if (ret == -1)
            {
                bpf_trace_printk("[ERR]: error during ipv4 assign");
                return XDP_DROP;
            }
        }

        // if the ipv4 is not found, drop the packet
        if (assigned_ipv4 == 0)
        {
            bpf_trace_printk("[WARN]: no free ipv4");
            return XDP_DROP;
        }

        bpf_trace_printk("[IPV6]: %pI4", &assigned_ipv4);

        // set the ipv4 header
        dst_hdr.saddr = bpf_htonl((__be32)*assigned_ipv4);
        dst_hdr.daddr = ip6h->daddr.s6_addr32[3];
        dst_hdr.protocol = ip6h->nexthdr;
        dst_hdr.ttl = ip6h->hop_limit;
        dst_hdr.tos = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

        // check if the packet is an icmpv6
        if (dst_hdr.protocol == IPPROTO_ICMPV6)
        {
            struct icmp6hdr *icmp6h = (void *)ip6h + sizeof(*ip6h);
            if (icmp6h + 1 > data_end)
                return XDP_DROP;

            // ready to parse the icmpv6 header into icmp
            struct icmphdr tmp_icmp;
            struct icmphdr *icmp;

            if (write_icmp(&tmp_icmp, icmp6h) == -1)
            {
                bpf_trace_printk("[ERR]: error during icmpv6 parse into icmp");
                return XDP_DROP;
            }

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp6h) - (int)sizeof(tmp_icmp)))
                return XDP_DROP;

            // after the adjust head, reassign the pointers
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            icmp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
            if (icmp + 1 > data_end)
                return XDP_DROP;

            *icmp = tmp_icmp;

            // set the checksum
            icmp->checksum = 0;
            //__u16 new_cksum = icmp_cksum(icmp, (void *)data_end);
            __u16 new_cksum =
                csum_fold_helper(bpf_csum_diff((__be32 *)icmp, 0, (__be32 *)icmp, sizeof(struct icmphdr), 0));
            // bpf_trace_printk("[IPV6]: checksum: %x", bpf_htons(new_cksum));

            /*
            after the checksum is calculated, the verifier complains about a possible
            out-of-bounds access to the data_end pointer.
            We need to reassign data_end and data.
            */
            void *data_end = (void *)(long)ctx->data_end;
            void *data = (void *)(long)ctx->data;

            icmp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if (icmp + 1 > data_end)
                return XDP_PASS;
            icmp->checksum = new_cksum;

            dst_hdr.protocol = IPPROTO_ICMP;
        } // icmpv6

        if (dst_hdr.protocol == IPPROTO_UDP)
        {
            struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if (udph + 1 > data_end)
                return XDP_PASS;

            udph->check = 0;
            __u16 new_cksum = udp_cksum(&dst_hdr, udph, data_end);
            udph->check = new_cksum;
        } // udp

        if (dst_hdr.protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if (tcph + 1 > data_end)
                return XDP_PASS;

            tcph->check = 0;
            __u16 new_cksum = tcp_cksum(&dst_hdr, tcph, data_end);
            tcph->check = new_cksum;
        } // tcps

        // this work
        dst_hdr.check =
            csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(struct iphdr), 0));

        // bpf_trace_printk("ipv4 checksum diff: %u", dst_hdr.check);
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
            return XDP_DROP;
        }

        *iph = dst_hdr;
        // start forwarding

        // setting the fib_params
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ipv4_src = iph->saddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.sport = 0;
        fib_params.dport = 0;

    } // ipv6
    else
    {
        return XDP_PASS;
    }

forward:

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

        action = bpf_redirect(fib_params.ifindex, 0);
        bpf_trace_printk("[IPV6]: ACTION: %d", action);
        return action;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */

        return XDP_PASS;
    case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
        // bpf_trace_printk("route not found, check if routing suite is working properly");
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
        // bpf_trace_printk("neigh entry missing");
    case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";