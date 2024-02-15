#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>

// fold checksum
static __always_inline __u16 fold_csum(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum += csum >> 16;
    return ~csum;
}

#define TRACE 1
#ifdef TRACE
#define START_TRACE()                                                                                                  \
    struct perf_trace_event __event = {};                                                                              \
    __event.timestamp = bpf_ktime_get_ns();                                                                            \
    __event.bytes = 0;                                                                                                 \
    __event.processing_time_ns = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} output_map SEC(".maps");

struct perf_trace_event
{
    __u64 timestamp;
    __u32 processing_time_ns;
    __u32 bytes;
};

#define TYPE_ENTER 1
#define TYPE_DROP 2
#define TYPE_PASS 3

#define END_TRACE()                                                                                                    \
    __event.bytes = (__u32)(data_end - data);                                                                          \
    __event.processing_time_ns = bpf_ktime_get_ns() - __event.timestamp;                                               \
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &__event, sizeof(__event));                             \
    bpf_printk("processing time: %d\n", __event.processing_time_ns);
#else
#define START_TRACE()
#define END_TRACE()
#endif

int xdp_change_id(struct xdp_md *ctx)
{
    START_TRACE();
    int action = XDP_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return XDP_DROP;

    // change id icmp packet to 1234
    bpf_printk("proto: %x", bpf_ntohs(eth->h_proto));
    bpf_printk("dest: %pM", eth->h_dest);
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        // bpf_printk("xdp_change_id: %d\n", action);
        struct iphdr *iph = data + sizeof(*eth);
        if (iph + 1 > data_end)
        {
            action = XDP_DROP;
            goto out;
        }
        if (iph->protocol == IPPROTO_ICMP)
        {
            struct icmphdr *icmph = data + sizeof(*eth) + sizeof(*iph);
            if (icmph + 1 > data_end)
            {
                action = XDP_DROP;
                goto out;
            }
            // icmph->un.echo.id = bpf_htons(1234);
            //  icmph->checksum = 0;
            __u32 checksum = fold_csum(bpf_csum_diff((__be32 *)icmph, sizeof(struct icmphdr), 0, 0, 0));
            bpf_printk("Done");
        }
    }
    else
    {
        action = XDP_DROP;
    }

out:

    END_TRACE();
    bpf_printk("action: %d", action);
    return action;
}

SEC("xdp")
int xdp_cid_func(struct xdp_md *ctx)
{
    return xdp_change_id(ctx);
}

char _license[] SEC("license") = "GPL";
