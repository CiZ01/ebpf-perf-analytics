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
    csum = (csum & 0xfff) + (csum >> 16);
    csum += csum >> 16;
    return ~csum;
}

#define MAX_ICMP_SIZE 1480

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

static __always_inline __u16 icmp_cksum(struct icmphdr *icmph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)icmph;

    for (int i = 0; i < MAX_ICMP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
            break;
        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    return ~csum;
}

int xdp_change_id(struct xdp_md *ctx)
{
    START_TRACE();
    int action = XDP_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 checksum = 0;
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return XDP_DROP;

    // change id icmp packet to 1234
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
            // (__be32*)icmph->un.echo.id = bpf_htons(1234);
            //  (__be32*)icmph->checksum = 0;

            // 1.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 2.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 3.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 4.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 5.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 6.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 7.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 8.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 1.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 2.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 3.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 4.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 5.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 6.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 7.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            // 8.
            checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

            /*             checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 2.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 3.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 4.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 5.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 6.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 7.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));

                        // 8.
                        checksum = fold_csum(bpf_csum_diff(0, 0, (__be32 *)icmph, sizeof(icmph), 0));
             */
            bpf_printk("DOne");
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
