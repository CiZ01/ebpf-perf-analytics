#ifndef MYKEPERF_MODULE_H
#define MYKEPERF_MODULE_H

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))

struct record
{
    char name[16];
    __u64 value;
    __u8 type_counter;
};

#ifdef TRACE
#define BPF_MYKPERF_INIT_TRACE()                                                                                       \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                                                            \
        __uint(max_entries, 4096);                                                                                     \
    } ring_output SEC(".maps");

#define BPF_MYKPERF_START_TRACE(sec_name, counter)                                                                     \
    struct record sec_name = {0};                                                                                      \
    memcpy(sec_name.name, #sec_name, sizeof(sec_name.name));                                                           \
    sec_name.value = bpf_mykperf_read_rdpmc(counter);

#define BPF_MYKPERF_END_TRACE(sec_name, counter)                                                                       \
    sec_name.value = bpf_mykperf_read_rdpmc(counter) - sec_name.value;                                                 \
    sec_name.type_counter = counter;                                                                                   \
    bpf_ringbuf_output(&ring_output, &sec_name, sizeof(sec_name), BPF_RB_FORCE_WAKEUP);

#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)                                                               \
    sec_name.value = bpf_mykperf_read_rdpmc(counter) - #sec_name.value;                                                \
    sec_name.type_counter = counter;                                                                                   \
    bpf_ringbuf_output(&ring_output, &sec_name, sizeof(sec_name), BPF_RB_FORCE_WAKEUP);                                \
    bpf_printk("[PERF] %s: %lld\n", #sec_name, sec_name->value);

#else
#define BPF_MYKPERF_INIT_TRACE()
#define BPF_MYKPERF_START_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE(sec_name, counter)
#define BPF_MYKPERF_END_TRACE_VERBOSE(sec_name, counter)
#endif

#endif // MYKEPERF_MODULE_H