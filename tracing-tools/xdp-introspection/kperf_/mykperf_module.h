#ifndef MYKEPERF_MODULE_H
#define MYKEPERF_MODULE_H

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define RAND_FN bpf_get_prandom_u32()
#define MAX_ENTRIES_PERCPU_ARRAY 64 << 10

struct record
{
    __u64 value;
    char name[15];
    __u8 type_counter;
} __attribute__((aligned(32)));

#ifdef TRACE

#define BPF_MYKPERF_INIT_TRACE(max_events_before_wakeup)                                                               \
    __u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;                                                                 \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                                                            \
        __uint(max_entries, 256 * 1024);                                                                               \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } ring_output SEC(".maps");                                                                                        \
                                                                                                                       \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                                              \
        __type(key, __u32);                                                                                            \
        __type(value, struct record);                                                                                  \
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                 \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } percpu_output SEC(".maps");                                                                                      \
                                                                                                                       \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                                              \
        __type(key, __u32);                                                                                            \
        __type(value, __u32);                                                                                          \
        __uint(max_entries, 2);                                                                                        \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } pos SEC(".maps");                                                                                                \
                                                                                                                       \
    const volatile long wakeup_data_size = max_events_before_wakeup;                                                   \
    static __always_inline long get_flags()                                                                            \
    {                                                                                                                  \
        if (!wakeup_data_size)                                                                                         \
            return 0;                                                                                                  \
        long sz;                                                                                                       \
        sz = bpf_ringbuf_query(&ring_output, BPF_RB_AVAIL_DATA);                                                       \
        return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;                                        \
    }

// remove definition of sec_name to use sampled version
#define BPF_MYKPERF_START_TRACE(sec_name, counter)                                                                     \
    struct record *sec_name = {0};                                                                                     \
    sec_name = bpf_ringbuf_reserve(&ring_output, sizeof(struct record), 0);                                            \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                                     \
        sec_name->type_counter = counter;                                                                              \
        sec_name->value = bpf_mykperf_read_rdpmc(counter);                                                             \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        bpf_printk("Failed to reserve ring buffer\n");                                                                 \
    }

#define BPF_MYKPERF_END_TRACE(sec_name, counter)                                                                       \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf_read_rdpmc(counter) - sec_name->value;                                           \
        bpf_ringbuf_submit(sec_name, get_flags());                                                                     \
    }

#define BPF_MYKPERF_DISCARD_TRACE(sec_name, counter)                                                                   \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = 0;                                                                                           \
        bpf_ringbuf_submit(sec_name, get_flags());                                                                     \
    }

// should not work
#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)                                                               \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf_read_rdpmc(counter) - sec_name->value;                                           \
        bpf_printk("[PERF] %s: %lld\n", #sec_name, sec_name->value);                                                   \
        bpf_ringbuf_submit(sec_name, get_flags());                                                                     \
    }

#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name, counter)                                                               \
    struct record *sec_name = {0};                                                                                     \
    __u32 key = 0;                                                                                                     \
    __u32 *pos_key = bpf_map_lookup_elem(&pos, &key);                                                                  \
    if (pos_key)                                                                                                       \
    {                                                                                                                  \
        sec_name = bpf_map_lookup_elem(&percpu_output, pos_key);                                                       \
        if (sec_name)                                                                                                  \
        {                                                                                                              \
            __sync_fetch_and_add(&sec_name->value, bpf_mykperf_read_rdpmc(counter));                                   \
        }                                                                                                              \
    }

#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name, counter)                                                                 \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        __sync_fetch_and_add(&sec_name->value, (bpf_mykperf_read_rdpmc(counter) - sec_name->value));                   \
        if ((*pos_key + 1) % MAX_ENTRIES_PERCPU_ARRAY)                                                                 \
        {                                                                                                              \
            __sync_fetch_and_add(pos_key, 1);                                                                          \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            __sync_fetch_and_add(pos_key, -(*pos_key));                                                                \
        }                                                                                                              \
        bpf_printk("[PERF] %s: %lld\n", #sec_name, sec_name->value);                                                   \
    }

// ----------------------------- SAMPLED TRACE -----------------------------
#define BPF_MYKPERF_START_TRACE_SAMPLED(sec_name, counter, sample_rate)                                                \
    struct record *sec_name = {0};                                                                                     \
    if (UNLIKELY(RAND_FN & sample_rate))                                                                               \
    {                                                                                                                  \
        BPF_MYKPERF_START_TRACE(sec_name, counter)                                                                     \
    }

// ----------------------------- --- -----------------------------

#else
#define BPF_MYKPERF_INIT_TRACE(max_events_before_wakeup)
#define BPF_MYKPERF_START_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)
#define BPF_MYKPERF_START_TRACE_SAMPLED(sec_name, counter, sample_rate)
#define BPF_MYKPERF_DISCARD_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE_SAMPLED(sec_name, counter)
#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name, counter)
#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name, counter)
#endif

#endif // MYKEPERF_MODULE_H
