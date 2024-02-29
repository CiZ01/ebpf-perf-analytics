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

// events
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
    __u32 zero = 0;
    long err;

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

static inline void fexit_update_maps(struct my_value_perf *my_after)
{
    __u32 zero = 0;

    // my code
    struct my_value_perf *my_before, my_diff;
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

    int err;
    __u32 zero = 0;
    // from bpftool
    __u64 *count;
    // my code
    struct my_value_perf my_reading;

    // my code
    my_reading.value = bpf_mykperf_read_rdpmc(0);

    // from bpftool
    count = bpf_map_lookup_elem(&counts, &zero);
    if (count)
    {
        *count += 1;
        fexit_update_maps(&my_reading);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";