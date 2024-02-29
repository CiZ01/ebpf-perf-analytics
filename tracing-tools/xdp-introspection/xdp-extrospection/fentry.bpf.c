// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2020 Facebook
// https://github.com/torvalds/linux/blob/603c04e27c3e9891ce7afa5cd6b496bfacff4206/tools/perf/util/bpf_skel/bpf_prog_profiler.bpf.c#L77

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// my kernel function prototype
__u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

struct my_value_perf
{
    __u64 value;
};

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

/* readings at fentry my value */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct my_value_perf));
    __uint(max_entries, 1);
} my_value_fentry_readings SEC(".maps");

/* accumulated readings */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_perf_event_value));
    __uint(max_entries, 1);
} accum_readings SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct my_value_perf));
    __uint(max_entries, 1);
} my_accum_readings SEC(".maps");

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

    // my code
    struct my_value_perf *ptr_my_value;
    // faccio la stessa cosa
    // in pratica recupero il puntatore alla struttura dalla mappa, così
    // non la devo ricaricaricare quando modifico il valore
    ptr_my_value = bpf_map_lookup_elem(&my_value_fentry_readings, &zero);
    if (!ptr_my_value)
        return 0;
    // my code
    ptr_my_value->value = bpf_mykperf_read_rdpmc(0);

    return 0;
}

static inline void fexit_update_maps(struct bpf_perf_event_value *after, struct my_value_perf *my_after)
{
    struct bpf_perf_event_value *before, diff;
    __u32 zero = 0;

    // my code
    struct my_value_perf *my_before, my_diff;

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

    // my code
    my_before = bpf_map_lookup_elem(&my_value_fentry_readings, &zero);
    if (my_before)
    {
        struct my_value_perf *my_accum;

        my_diff.value = my_after->value - my_before->value;

        my_accum = bpf_map_lookup_elem(&my_accum_readings, &zero);
        if (my_accum)
        {
            my_accum->value += my_diff.value;
        }
    }
    // se salva il puntatore nella mappa non c'è bisogno di aggiornala
    // penso, non so se è vero
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
    // my code
    struct my_value_perf my_reading;
    /* read all events before updating the maps, to reduce error */
    err = bpf_perf_event_read_value(&events, cpu, &reading, sizeof(reading));
    if (err)
        return 0;
    // my code
    my_reading.value = bpf_mykperf_read_rdpmc(0);

    // from bpftool
    count = bpf_map_lookup_elem(&counts, &zero);
    if (count)
    {
        *count += 1;
        fexit_update_maps(&reading, &my_reading);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";