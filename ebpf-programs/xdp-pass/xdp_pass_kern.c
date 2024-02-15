#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifdef TRACE
#define START_TRACE()                                                                                                  \
    struct perf_trace_event __event = {};                                                                              \
    __event.timestamp = bpf_ktime_get_ns();                                                                            \
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
    __event.processing_time_ns = bpf_ktime_get_ns() - __event.timestamp;                                               \
    bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &__event, sizeof(__event));                             \
    bpf_printk("processing time: %d\n", __event.processing_time_ns);
#else
#define START_TRACE()
#define END_TRACE()
#endif

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
    START_TRACE();
    bpf_printk("PASS");
    END_TRACE();
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
