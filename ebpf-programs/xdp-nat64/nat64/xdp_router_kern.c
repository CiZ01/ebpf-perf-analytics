#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <sys/resource.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "../../../tracing-tools/xdp-introspection/kperf_/mykperf_module.h"
#include "nat_helpers.h"

#define IP_BOUNDARY_START 0xc0a80901 // 192.168.9.1
#define IP_BOUNDARY_END 0xc0a809fe   // 192.168.9.254

__u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

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

} nat_4to6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_addr32);
    __type(value, __u32);
    __uint(max_entries, 256);
} nat_6to4 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} ip4_cnt SEC(".maps");

BPF_MYKPERF_INIT_TRACE();

static inline int free_ip_4to6(__u32 ip)
{
    struct ipv6_addr32 *value;
    value = bpf_map_lookup_elem(&nat_4to6, &ip);
    if (value != NULL)
    {
        if (ipv6_addr_equal(value->addr, NULL) == 0)
        {
            bpf_map_update_elem(&nat_4to6, &ip, NULL, BPF_ANY);
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
            bpf_map_update_elem(&nat_6to4, &addr32, last_ip, BPF_ANY);
            bpf_map_update_elem(&nat_4to6, last_ip, &addr32, BPF_ANY);

            // update the counter
            __u32 next_ip = *last_ip + 1;
            bpf_map_update_elem(&ip4_cnt, &zero, &next_ip, BPF_ANY);

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
    value = bpf_map_lookup_elem(&nat_6to4, &ip);
    if (value)
    {
        if (*value)
        {
            bpf_map_update_elem(&nat_6to4, &ip, ipv6_addr, BPF_ANY);
            return 0;
        }
    }
    return -1;
}

static inline int search_ipv4_from_ipv6(struct ipv6_addr32 *ipv6_addr, __u32 ip)
{
    struct ipv6_addr32 *value;
    value = bpf_map_lookup_elem(&nat_6to4, &ip);
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
    bpf_printk("[IPV4]: %pI4", &ip);

    value = bpf_map_lookup_elem(&nat_4to6, &ip);
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

            bpf_printk("entro qa");
            goto forward;
        }

        // it must be defined here equal zero because the verifier
        __u32 assigned_ipv4 = 0; // Change the type from pointer to value

        struct iphdr dst_hdr = {
            .version = 4,
            .ihl = 5,
            .frag_off = bpf_htons(1 << 14),
        };

        struct ipv6_addr32 ipv6_addr_key;

        // Copy values from src_array to dest_array
        memcpy(ipv6_addr_key.addr, ip6h->saddr.in6_u.u6_addr32, sizeof(ip6h->saddr.in6_u.u6_addr32));

        // find the ipv4 address associated to the ipv6 dest address
        __u32 *assigned_ipv4_ptr = bpf_map_lookup_elem(&nat_6to4, &ipv6_addr_key); // Change the variable name

        // if the ipv4 is not found, search a free ipv4 to assign
        if (assigned_ipv4_ptr == NULL)
        {
            ret = assign_ipv4_to_ipv6(ip6h->saddr.in6_u.u6_addr32, &assigned_ipv4); // Pass the address of assigned_ipv4
            if (ret == -1)
            {
                bpf_printk("[ERR]: error during ipv4 assign");
                return XDP_DROP;
            }

            // if the ipv4 is not found, drop the packet
            if (!assigned_ipv4)
            {
                bpf_printk("[WARN]: no free ipv4");
                return XDP_DROP;
            }
        }

        bpf_probe_read_kernel(&assigned_ipv4, sizeof(assigned_ipv4), assigned_ipv4_ptr); // Change the variable name

        // set the ipv4 header
        dst_hdr.saddr = bpf_htonl(assigned_ipv4); // Use the assigned_ipv4 value directly
        bpf_printk("[IPV6]: %pI4", &dst_hdr.saddr);
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
            struct icmphdr tmp_icmp = {0};
            struct icmphdr *icmp;

            if (write_icmp(&tmp_icmp, icmp6h) == -1)
            {
                bpf_printk("[ERR]: error during icmpv6 parse into icmp");
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
            __u16 new_cksum = icmp_cksum(icmp, (void *)data_end);
            //__u16 new_cksum = csum_fold_helper(bpf_csum_diff(0, 0, (__be32 *)icmp, sizeof(struct icmphdr), 0));
            bpf_printk("[IPV6]: checksum: %x", bpf_htons(new_cksum));

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

        // bpf_printk("ipv4 checksum diff: %u", dst_hdr.check);
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
        bpf_printk("[IPV6]: ACTION: %d", action);
        return action;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
        bpf_printk("[IPV6]: ERROR: %d", rc);
        return XDP_PASS;
    case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
        // bpf_printk("route not found, check if routing suite is working properly");
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
        // bpf_printk("neigh entry missing");
    case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
        bpf_printk("[IPV6]: ERROR: %d", rc);
        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp_router_4to6")
int xdp_router_4to6_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE(0);
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    int iphdr_len;
    struct ethhdr eth_cpy;
    __u16 h_proto;
    __u64 nh_off;
    __u16 rc;
    struct bpf_fib_lookup fib_params = {0};
    struct in6_addr *fib_dst = (struct in6_addr *)fib_params.ipv6_dst;
    struct ipv6hdr dst_hdr = {.version = 6, .saddr = 0, .daddr = 0};

    __u8 action;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {

        memcpy(&eth_cpy, eth, sizeof(eth_cpy));
        iph = data + sizeof(struct ethhdr);

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
            fib_params.family = AF_INET;
            fib_params.ipv4_dst = iph->daddr;
            fib_params.ifindex = ctx->ingress_ifindex;
            fib_params.sport = 0;
            fib_params.dport = 0;

            goto forward;
        }

        iphdr_len = iph->ihl * 4;

        if (iphdr_len != sizeof(struct iphdr) || (iph->frag_off & ~bpf_htons(1 << 14)))
            return XDP_DROP;

        // find the ipv6 address associated to the ipv4 dest address
        int res = search_ipv6_from_ipv4(bpf_htonl(iph->daddr), (__be32 *)&dst_hdr.daddr.in6_u.u6_addr32);
        if (res == -1)
        {
            bpf_printk("[ERR]: IPV6 address not found, packet droped!");
            return XDP_DROP;
        }

        // setting the source address
        dst_hdr.saddr.in6_u.u6_addr32[0] = bpf_htonl(TRANSLATE_PREFIX);
        dst_hdr.saddr.in6_u.u6_addr32[3] = iph->saddr;

        /*         bpf_printk("[IPV4]: IPV6 ASSIGNED: %pI6", &dst_hdr.saddr.s6_addr32);
                bpf_printk("[IPV4]: IPV6 DEST: %pI6", &dst_hdr.daddr.s6_addr32);
         */
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

            struct icmp6hdr icmp6 = {0};
            struct icmp6hdr *new_icmp6;

            if (write_icmp6(icmp, &icmp6) == -1)
            {
                bpf_printk("[ERR]: cant write icmp");
                return XDP_DROP;
            }

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(*icmp) - (int)sizeof(icmp6)))
                return XDP_DROP;

            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            new_icmp6 = (void *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            if (new_icmp6 + 1 > data_end)
                return XDP_DROP;

            *new_icmp6 = icmp6;

            // TODO REFORMAT THIS PART
            struct icmpv6_pseudo ph = {
                .nh = IPPROTO_ICMPV6, .saddr = dst_hdr.saddr, .daddr = dst_hdr.daddr, .len = dst_hdr.payload_len};

            new_icmp6->icmp6_cksum = 0;
            //__u16 new_cksum = calculate_icmp_checksum((__u16 *)new_icmp6, (__u16 *)&ph);
            __u16 new_cksum = icmpv6_cksum(&ph, new_icmp6, data_end);
            //__u16 new_cksum = csum_fold_helper(bpf_csum_diff((__be32 *)new_icmp6, 0, (__be32 *)new_icmp6,
            // sizeof(*new_icmp6), 0));

            /*
                after the checksum is calculated, the verifier complains about a possible
                out-of-bounds access to the data_end pointer.
                We need to reassign data_end and data.
            */
            void *data_end = (void *)(long)ctx->data_end;
            void *data = (void *)(long)ctx->data;

            new_icmp6 = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (new_icmp6 + 1 > data_end)
                return XDP_PASS;

            new_icmp6->icmp6_cksum = new_cksum;

            dst_hdr.nexthdr = IPPROTO_ICMPV6;
        } // icmp

        if (dst_hdr.nexthdr == IPPROTO_UDP)
        {
            struct udphdr *udp6h = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udp6h + 1 > data_end)
                return XDP_PASS;

            udp6h->check = 0;

            // udp checksum is the same, but change the pseudo header
            __u16 new_cksum = udp6_cksum(&dst_hdr, udp6h, data_end);
            udp6h->check = new_cksum;
        } // udp

        if (dst_hdr.nexthdr == IPPROTO_TCP)
        {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcph + 1 > data_end)
                return XDP_PASS;

            tcph->check = 0;
            __u16 new_cksum = tcp6_cksum(&dst_hdr, tcph, data_end);
            tcph->check = new_cksum;
        } // tcps

        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr) - (int)sizeof(struct ipv6hdr)))
            return XDP_DROP;

        eth = (void *)(long)ctx->data;
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        if (eth + 1 > data_end)
            return XDP_DROP;

        memcpy(eth, &eth_cpy, sizeof(*eth));
        eth->h_proto = bpf_htons(ETH_P_IPV6);
        ip6h = (void *)(data + sizeof(*eth));

        if (ip6h + 1 > data_end)
        {
            return XDP_DROP;
        }

        *ip6h = dst_hdr;
        ip6h->saddr = dst_hdr.saddr;

        fib_params.family = AF_INET6;
        *fib_dst = dst_hdr.daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
    } // ipv4
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

        BPF_MYKPERF_END_TRACE(0);
        return action;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
        bpf_printk("[IPV4]: ERROR: %d", rc);
        return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
        // bpf_printk("route not found, check if routing suite is working properly");
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
        // bpf_printk("neigh entry missing");
    case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
        bpf_printk("[IPV4]: ERROR: %d", rc);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
