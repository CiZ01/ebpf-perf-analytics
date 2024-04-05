#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "mykperf_module.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct record);
    __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} percpu_output SEC(".maps");
__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

BPF_MYKPERF_INIT_TRACE(0);

SEC("xdp") int xdp_pass_func(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE(main, 0);

    __u64 start = bpf_mykperf_read_rdpmc(0);

    if (start)
    {
        struct record *sec_name = {0};
        __u32 key = 0;

        sec_name = bpf_map_lookup_elem(&percpu_output, &key);
        if (sec_name)
        {
            sec_name->value += bpf_mykperf_read_rdpmc(0) - start;
            memcpy(sec_name->name, "test", sizeof(sec_name->name));
            sec_name->type_counter += 1;
        }
    }

    BPF_MYKPERF_END_TRACE(main, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
