#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#define MAX_ICMP_SIZE 1480

#ifdef TRACE
__u64 bpf_mykperf_read_rdpmc__cycles(void) __ksym;
__u64 bpf_mykperf_read_rdpmc__instructions(void) __ksym;
__u64 bpf_mykperf_read_rdpmc(__u8 counter_k) __ksym;

struct perf_event
{
    __u64 value;
};

// perf output
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} output SEC(".maps");
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

SEC("xdp")
int xdp_cksm_func(struct xdp_md *ctx)
{
#ifdef TRACE
    __u64 start, end;
    struct perf_event event = {0};

    // it work only with 0, it's perf that choose the counter
    start = bpf_mykperf_read_rdpmc(0);
#endif
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);
    struct icmphdr *icmph = data + sizeof(*eth) + sizeof(*iph);

    if ((void *)(icmph + 1) > data_end)
    {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_ICMP)
    {
        volatile __u16 csum;
        // 1
        csum = icmp_cksum(icmph, data_end);
        // 2
        /*csum = icmp_cksum(icmph, data_end);
        // 3
        csum = icmp_cksum(icmph, data_end);
        // 1
        csum = icmp_cksum(icmph, data_end);
        // 2
        csum = icmp_cksum(icmph, data_end);
        // 3
        csum = icmp_cksum(icmph, data_end);
        // 1
        csum = icmp_cksum(icmph, data_end);
        // 2
        csum = icmp_cksum(icmph, data_end);*/
    }

#ifdef TRACE
    end = bpf_mykperf_read_rdpmc(0) - start;
    event.value = end;
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &event, sizeof(event));
#endif
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
