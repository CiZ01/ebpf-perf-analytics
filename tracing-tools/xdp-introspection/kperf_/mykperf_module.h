#ifndef MYKEPERF_MODULE_H
#define MYKEPERF_MODULE_H

#define BPF_MYKPERF_INIT_TRACE() \
struct { \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, 4096); \
} ring_output SEC(".maps"); 

#define BPF_MYKPERF_START_TRACE(counter) \
    __u32 low, high; \
    __u64 start, end; \
    start = bpf_mykperf_read_rdpmc(counter, low, high);


#define BPF_MYKPERF_END_TRACE(counter) \
    end = bpf_mykperf_read_rdpmc(counter, low, high); \
    bpf_ringbuf_output(&ring_output, &end, sizeof(__u64), BPF_RB_FORCE_WAKEUP);



#endif // MYKEPERF_MODULE_H