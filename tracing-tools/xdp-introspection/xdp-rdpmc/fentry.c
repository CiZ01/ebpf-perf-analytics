// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>

#include <linux/perf_event.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/skel_internal.h>

#include "fentry_skel.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BPF_METADATA_PREFIX "bpf_metadata_"
#define BPF_METADATA_PREFIX_LEN (sizeof(BPF_METADATA_PREFIX) - 1)
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#ifndef __same_type
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int : (-!!(e)); })))

struct my_value_perf
{
    __u64 value;
};

static inline __u64 ptr_to_u64(const void *ptr)
{
    return (__u64)(unsigned long)ptr;
}

struct profile_metric
{
    const char *name;
    struct bpf_perf_event_value val;
    struct perf_event_attr attr;
    bool selected;
    __u64 my_value;

    /* calculate ratios like instructions per cycle */
    const int ratio_metric; /* 0 for N/A, 1 for index 0 (cycles) */
    const char *ratio_desc;
    const float ratio_mul;
} metrics[] = {{
                   .name = "cycles",
                   .attr =
                       {
                           .type = PERF_TYPE_HARDWARE,
                           .config = PERF_COUNT_HW_CPU_CYCLES,
                           .exclude_user = 1,
                       },
               },
               {
                   .name = "instructions",
                   .attr =
                       {
                           .type = PERF_TYPE_HARDWARE,
                           .config = PERF_COUNT_HW_INSTRUCTIONS,
                           .exclude_user = 1,
                       },
                   .ratio_metric = 1,
                   .ratio_desc = "insns per cycle",
                   .ratio_mul = 1.0,
               },
               {
                   .name = "l1d_loads",
                   .attr =
                       {
                           .type = PERF_TYPE_HW_CACHE,
                           .config = PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                                     (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
                           .exclude_user = 1,
                       },
               },
               {
                   .name = "llc_misses",
                   .attr = {.type = PERF_TYPE_HW_CACHE,
                            .config = PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                                      (PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                            .exclude_user = 1},
                   .ratio_metric = 2,
                   .ratio_desc = "LLC misses per million insns",
                   .ratio_mul = 1e6,
               },
               {
                   .name = "itlb_misses",
                   .attr = {.type = PERF_TYPE_HW_CACHE,
                            .config = PERF_COUNT_HW_CACHE_ITLB | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                                      (PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                            .exclude_user = 1},
                   .ratio_metric = 2,
                   .ratio_desc = "itlb misses per million insns",
                   .ratio_mul = 1e6,
               },
               {
                   .name = "dtlb_misses",
                   .attr = {.type = PERF_TYPE_HW_CACHE,
                            .config = PERF_COUNT_HW_CACHE_DTLB | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                                      (PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                            .exclude_user = 1},
                   .ratio_metric = 2,
                   .ratio_desc = "dtlb misses per million insns",
                   .ratio_mul = 1e6,
               },
               {
                   .name = "L1-dcache-load-misses",
                   .attr = {.type = PERF_TYPE_HW_CACHE,
                            .config = PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                                      (PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                            .exclude_user = 1},
               }};

static __u64 profile_total_count;

#define MAX_NUM_PROFILE_METRICS 4

// not used

static void profile_read_values(struct fentry_bpf *obj)
{
    __u32 m, cpu, num_cpu = obj->rodata->num_cpu;
    int count_map_fd, my_reading_map_fd;
    __u64 counts[num_cpu];
    __u32 key = 0;
    int err;

    //// forse potrebbe dare errore perché supera i 15 caratteri
    my_reading_map_fd = bpf_map__fd(obj->maps.my_accum_readings);

    count_map_fd = bpf_map__fd(obj->maps.counts);
    if (count_map_fd < 0 || my_reading_map_fd < 0)
    {
        fprintf(stderr, "failed to get fd for map");
        return;
    }

    err = bpf_map_lookup_elem(count_map_fd, &key, counts);
    if (err)
    {
        fprintf(stderr, "failed to read count_map: %s", strerror(errno));
        return;
    }

    profile_total_count = 0;
    for (cpu = 0; cpu < num_cpu; cpu++)
        profile_total_count += counts[cpu];

    for (m = 0; m < ARRAY_SIZE(metrics); m++)
    {
        struct my_value_perf my_values[num_cpu];

        if (!metrics[m].selected)
            continue;

        err = bpf_map_lookup_elem(my_reading_map_fd, &key, my_values);
        if (err)
        {
            fprintf(stderr, "failed to read my_reading_map: %s", strerror(errno));
            return;
        }

        for (cpu = 0; cpu < num_cpu; cpu++)
        {
            // my code
            metrics[m].my_value += my_values[cpu].value;
        }
        key++;
    }
}

static void profile_print_readings_plain(void)
{
    __u32 m;

    printf("\n%18llu %-20s\n", profile_total_count, "run_cnt");
    for (m = 0; m < ARRAY_SIZE(metrics); m++)
    {
        int r;

        if (!metrics[m].selected)
            continue;

        // questa è quella che mi interessa
        printf("%18llu %-20s", metrics[m].my_value, "my_value");
        printf("\n");
    }
}

static void profile_print_readings(void)
{
    /*     if (json_output)
            profile_print_readings_json();
        else */
    profile_print_readings_plain();
}

static char *profile_target_name(int tgt_fd)
{
    struct bpf_func_info func_info;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    const struct btf_type *t;
    __u32 func_info_rec_size;
    struct btf *btf = NULL;
    char *name = NULL;
    int err;

    err = bpf_prog_get_info_by_fd(tgt_fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "failed to get info for prog FD %d", tgt_fd);
        goto out;
    }

    if (info.btf_id == 0)
    {
        fprintf(stderr, "prog FD %d doesn't have valid btf", tgt_fd);
        goto out;
    }

    func_info_rec_size = info.func_info_rec_size;
    if (info.nr_func_info == 0)
    {
        fprintf(stderr, "found 0 func_info for prog FD %d", tgt_fd);
        goto out;
    }

    memset(&info, 0, sizeof(info));
    info.nr_func_info = 1;
    info.func_info_rec_size = func_info_rec_size;
    info.func_info = ptr_to_u64(&func_info);

    err = bpf_prog_get_info_by_fd(tgt_fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "failed to get func_info for prog FD %d", tgt_fd);
        goto out;
    }

    btf = btf__load_from_kernel_by_id(info.btf_id);
    if (!btf)
    {
        fprintf(stderr, "failed to load btf for prog FD %d", tgt_fd);
        goto out;
    }

    t = btf__type_by_id(btf, func_info.type_id);
    if (!t)
    {
        fprintf(stderr, "btf %d doesn't have type %d", info.btf_id, func_info.type_id);
        goto out;
    }
    name = strdup(btf__name_by_offset(btf, t->name_off));
out:
    btf__free(btf);
    return name;
}

static struct fentry_bpf *profile_obj;
static int profile_tgt_fd = -1;
static char *profile_tgt_name;
static int *profile_perf_events;
static int profile_perf_event_cnt;

static void profile_close_perf_events(struct fentry_bpf *obj)
{
    int i;

    for (i = profile_perf_event_cnt - 1; i >= 0; i--)
        close(profile_perf_events[i]);

    free(profile_perf_events);
    profile_perf_event_cnt = 0;
}

static int profile_open_perf_event(int mid, int cpu, int map_fd)
{
    int pmu_fd;

    pmu_fd = syscall(__NR_perf_event_open, &metrics[mid].attr, -1 /*pid*/, cpu, -1 /*group_fd*/, 0);
    if (pmu_fd < 0)
    {
        if (errno == ENODEV)
        {
            // fprintf(stdout, "cpu %d may be offline, skip %s profiling.", cpu, metrics[mid].name);
            profile_perf_event_cnt++;
            return 0;
        }
        return -1;
    }

    if (bpf_map_update_elem(map_fd, &profile_perf_event_cnt, &pmu_fd, BPF_ANY) ||
        ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
    {
        close(pmu_fd);
        return -1;
    }

    profile_perf_events[profile_perf_event_cnt++] = pmu_fd;
    return 0;
}

static int profile_open_perf_events(struct fentry_bpf *obj)
{
    unsigned int cpu, m;
    int map_fd;

    profile_perf_events = calloc(obj->rodata->num_cpu * obj->rodata->num_metric, sizeof(int));
    if (!profile_perf_events)
    {
        fprintf(stderr, "failed to allocate memory for perf_event array: %s\n", strerror(errno));
        return -1;
    }
    map_fd = bpf_map__fd(obj->maps.events);
    if (map_fd < 0)
    {
        fprintf(stderr, "failed to get fd for events map\n");
        return -1;
    }

    // sennò per ogni cpu scriveva troppe robe
    fprintf(stdout, "cpu not avaible message has been disabled\n");
    for (m = 0; m < ARRAY_SIZE(metrics); m++)
    {
        if (!metrics[m].selected)
            continue;
        for (cpu = 0; cpu < obj->rodata->num_cpu; cpu++)
        {
            if (profile_open_perf_event(m, cpu, map_fd))
            {
                fprintf(stderr, "failed to create event %s on cpu %d\n", metrics[m].name, cpu);
                return -1;
            }
        }
    }
    return 0;
}

static void profile_print_and_cleanup(void)
{
    profile_close_perf_events(profile_obj);
    profile_read_values(profile_obj);
    profile_print_readings();

    fentry_bpf__detach(profile_obj);
    fentry_bpf__destroy(profile_obj);

    close(profile_tgt_fd);
    free(profile_tgt_name);
}

static void int_exit(int signo)
{
    profile_print_and_cleanup();
    exit(0);
}

int main(int argc, char **argv)
{
    int num_metric, num_cpu, err = -1;
    struct bpf_program *prog;
    char *endptr;
    int bpf_prog_id = -1;

    int selected_metric = 0;

    /* we at least need two args for the prog and one metric */
    /*     if (!REQ_ARGS(3))
            return -EINVAL; */

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, ":i:m:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            bpf_prog_id = strtol(optarg, &endptr, 10);
            break;
        case 'm':
            selected_metric = strtol(optarg, &endptr, 10);
            if (selected_metric < 0 || selected_metric >= ARRAY_SIZE(metrics))
            {
                fprintf(stderr, "Invalid metric index %d\n", selected_metric);
                return -1;
            }
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an operand\n", optopt);
            return -1;
        case '?':
            fprintf(stderr, "Unrecognized option: -%c\n", optopt);
            return -1;
        }
    }

    // seleziono la metric
    metrics[selected_metric].selected = true;

    /* parse target fd */
    profile_tgt_fd = bpf_prog_get_fd_by_id(bpf_prog_id);
    if (profile_tgt_fd < 0)
    {
        fprintf(stderr, "failed to parse fd \n");
        return -1;
    }

    num_metric = 1;

    num_cpu = libbpf_num_possible_cpus();
    if (num_cpu <= 0)
    {
        fprintf(stderr, "failed to identify number of CPUs \n");
        goto out;
    }

    profile_obj = fentry_bpf__open();
    if (!profile_obj)
    {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        goto out;
    }

    profile_obj->rodata->num_cpu = num_cpu;
    profile_obj->rodata->num_metric = num_metric;

    // questo mi serve per tenere traccia degli eventi scelti

    bpf_map__set_max_entries(profile_obj->maps.events, num_metric * num_cpu);
    bpf_map__set_max_entries(profile_obj->maps.counts, 1);

    // my code, my maps
    bpf_map__set_max_entries(profile_obj->maps.my_value_fentry_readings, num_metric);
    bpf_map__set_max_entries(profile_obj->maps.my_accum_readings, num_metric);

    /* change target name */
    profile_tgt_name = profile_target_name(profile_tgt_fd);
    if (!profile_tgt_name)
        goto out;

    bpf_object__for_each_program(prog, profile_obj->obj)
    {
        err = bpf_program__set_attach_target(prog, profile_tgt_fd, profile_tgt_name);
        if (err)
        {
            fprintf(stderr, "failed to set attach target\n");
            goto out;
        }
    }

    // set_max_rlimit();
    err = fentry_bpf__load(profile_obj);
    if (err)
    {
        fprintf(stderr, "failed to load profile_obj\n");
        goto out;
    }

    err = profile_open_perf_events(profile_obj);
    if (err)
        goto out;

    err = fentry_bpf__attach(profile_obj);
    if (err)
    {
        fprintf(stderr, "failed to attach profile_obj\n");
        goto out;
    }
    signal(SIGINT, int_exit);

    // sleep(duration);
    printf("Start profiling\n");
    while (1)
    {
        sleep(1);
    }

    profile_print_and_cleanup();
    return 0;

out:
    profile_close_perf_events(profile_obj);
    if (profile_obj)
        fentry_bpf__destroy(profile_obj);
    close(profile_tgt_fd);
    free(profile_tgt_name);
    return err;
}
