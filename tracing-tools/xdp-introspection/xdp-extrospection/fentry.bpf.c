// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2020 Facebook
// https://github.com/torvalds/linux/blob/603c04e27c3e9891ce7afa5cd6b496bfacff4206/tools/perf/util/bpf_skel/bpf_prog_profiler.bpf.c#L77

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("fentry", "update");

/* readings at fentry */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_perf_event_value));
    __uint(max_entries, 1);
} fentry_readings SEC(".maps");

/* map of perf event fds, num_cpu * num_metric entries */
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

/* accumulated readings */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_perf_event_value));
    __uint(max_entries, 1);
} accum_readings SEC(".maps");

/* sample counts, one per cpu --- from bpftool */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} counts SEC(".maps");

const volatile __u32 num_cpu = 1;
const volatile __u32 num_metric = 1;

SEC("fentry/*")
int BPF_PROG(fentry_XXX)
{
    BPF_MYKPERF_START_TRACE_ARRAY(fentry);
    __u32 key = bpf_get_smp_processor_id();
    struct bpf_perf_event_value *ptr;
    __u32 zero = 0;
    long err;

    /* look up before reading, to reduce error */
    ptr = bpf_map_lookup_elem(&fentry_readings, &zero);
    if (!ptr)
        return 0;

    err = bpf_perf_event_read_value(&events, key, ptr, sizeof(*ptr));
    if (err)
        return 0;
    BPF_MYKPERF_END_TRACE_ARRAY(fentry);
    return 0;
}

static inline void fexit_update_maps(struct bpf_perf_event_value *after)
{
    struct bpf_perf_event_value *before, diff;
    __u32 zero = 0;

    before = bpf_map_lookup_elem(&fentry_readings, &zero);
    /* only account samples with a valid fentry_reading */
    if (before && before->counter)
    {
        struct bpf_perf_event_value *accum;

        diff.counter = after->counter - before->counter;
        diff.enabled = after->enabled - before->enabled;
        diff.running = after->running - before->running;

        accum = bpf_map_lookup_elem(&accum_readings, &zero);
        if (accum)
        {
            accum->counter += diff.counter;
            accum->enabled += diff.enabled;
            accum->running += diff.running;
        }
    }
}

SEC("fexit/XXX")
int BPF_PROG(fexit_XXX)
{

    struct bpf_perf_event_value reading;
    __u32 cpu = bpf_get_smp_processor_id();
    int err;
    __u32 zero = 0;
    // from bpftool
    __u64 *count;

    err = bpf_perf_event_read_value(&events, cpu, &reading, sizeof(reading));
    if (err)
        return 0;

    // bpf_printk("costo 2 read event: %lld\n", end - start);

    // from bpftool
    BPF_MYKPERF_START_TRACE_ARRAY(update);
    count = bpf_map_lookup_elem(&counts, &zero);
    if (count)
    {
        *count += 1;
        fexit_update_maps(&reading);
    }
    BPF_MYKPERF_END_TRACE_ARRAY(update);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";