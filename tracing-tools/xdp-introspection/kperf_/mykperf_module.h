#ifndef MYKEPERF_MODULE_H
#define MYKEPERF_MODULE_H

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define RAND_FN bpf_get_prandom_u32()

struct record
{
    __u64 value;
    char name[16];
    __u8 type_counter;
};

#ifdef TRACE
#define BPF_MYKPERF_INIT_TRACE()                                                                                       \
    __u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;                                                                 \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                                                            \
        __uint(max_entries, 256 * 1024);                                                                               \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } ring_output SEC(".maps");

#define BPF_MYKPERF_START_TRACE(sec_name, counter)                                                                     \
    sec_name = bpf_ringbuf_reserve(&ring_output, sizeof(struct record), 0);                                            \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf_read_rdpmc(counter);                                                             \
        memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                                     \
        sec_name->type_counter = counter;                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        bpf_printk("Failed to reserve ring buffer\n");                                                                 \
    }

#define BPF_MYKPERF_END_TRACE(sec_name, counter)                                                                       \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf_read_rdpmc(counter) - sec_name->value;                                           \
        bpf_ringbuf_submit(sec_name, 0);                                                                               \
    }

// should not work
#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)                                                               \
    sec_name = bpf_mykperf_read_rdpmc(counter) - sec_name->value;                                                      \
    bpf_ringbuf_output(&ring_output, &sec_name, sizeof(sec_name), BPF_RB_FORCE_WAKEUP);                                \
    bpf_printk("[PERF] %s: %lld\n", #sec_name, sec_name->value);

// ----------------------------- SAMPLED TRACE -----------------------------
#define BPF_MYKPERF_START_TRACE_SAMPLED(sec_name, counter, sample_rate)                                                \
    struct record *sec_name = {0};                                                                                     \
    if (UNLIKELY(RAND_FN & sample_rate))                                                                               \
    {                                                                                                                  \
        BPF_MYKPERF_START_TRACE(sec_name, counter)                                                                     \
    }

// ----------------------------- --- -----------------------------

#else
#define BPF_MYKPERF_INIT_TRACE()
#define BPF_MYKPERF_START_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)
#define BPF_MYKPERF_START_TRACE_SAMPLED(sec_name, counter, sample_rate)
#define BPF_MYKPERF_END_TRACE_SAMPLED(sec_name, counter)
#endif

#endif // MYKEPERF_MODULE_H