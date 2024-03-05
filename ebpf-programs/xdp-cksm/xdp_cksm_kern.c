#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <bpf/bpf_tracing.h>

#define MAX_ICMP_SIZE 1480

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#ifdef TRACE
__u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

struct event_value
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

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} ring_output SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_output SEC(".maps");

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
    __u32 low = 0;
    __u32 high = 0;
    __u32 low2 = 0;
    __u32 high2 = 0;
    __u64 start, end, start2, end2;
    //__u8 sampled = 0;

    // sampling
    // if (UNLIKELY((bpf_get_prandom_u32() & 0x07)))
    //{
    // sampled = 1;
    // it work only with 0, it's perf that choose the counter
    start = bpf_mykperf_read_rdpmc(0);
    start2 = bpf_mykperf_read_rdpmc(1);
    //}

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
        csum = icmp_cksum(icmph, data_end);
        // 3
        csum = icmp_cksum(icmph, data_end);
        // 1
        csum = icmp_cksum(icmph, data_end);

        // 2
        /* csum = icmp_cksum(icmph, data_end);
         // 3
         csum = icmp_cksum(icmph, data_end);
         // 1
         csum = icmp_cksum(icmph, data_end);
         // 2
         csum = icmp_cksum(icmph, data_end); */
    }

#ifdef TRACE
    // if (UNLIKELY(sampled))
    //{
    end = bpf_mykperf_read_rdpmc(0) - start;
    end2 = bpf_mykperf_read_rdpmc(1) - start2;
    bpf_printk("end: %llu, end2: %llu\n", end, end2);

    struct event_value event = {0};
    event.value = end;
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &event, sizeof(event));
    // bpf_ringbuf_output(&ring_output, &end, sizeof(__u64), BPF_RB_FORCE_WAKEUP);
    /* __u32 key = 0;
    __u64 *value;
    value = bpf_map_lookup_elem(&percpu_output, &key);
    if (value){
        *value = end;
    } */
    //}
#endif
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
