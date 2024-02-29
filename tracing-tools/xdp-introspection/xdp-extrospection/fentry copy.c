// fentry userspace code
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <linux/btf.h>

#include <linux/perf_event.h>

#include <linux/ptrace.h>
#include <signal.h>

#include "fentry_skel.h"

static inline __u64 ptr_to_u64(const void *ptr)
{
    return (__u64)(unsigned long)ptr;
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
}
metrics[] = {{.name = "cycles",
              .attr =
                  {
                      .type = PERF_TYPE_HARDWARE,
                      .config = PERF_COUNT_HW_CPU_CYCLES,
                      .exclude_user = 1,
                  },

              static int profiler_open_perf_event(int mid, int cpu, int map_fd){int pmu_fd;

pmu_fd = syscall(__NR_perf_event_open, &metrics[mid].attr, -1 /*pid*/, cpu, -1 /*group_fd*/, 0);
if (pmu_fd < 0)
{
    if (errno == ENODEV)
    {
        p_info("cpu %d may be offline, skip %s profiling.", cpu, metrics[mid].name);
        profile_perf_event_cnt++;
        return 0;
    }
    return -1;
}

if (bpf_map_update_elem(map_fd, &profile_perf_event_cnt, &pmu_fd, BPF_ANY) || ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
{
    close(pmu_fd);
    return -1;
}

profile_perf_events[profile_perf_event_cnt++] = pmu_fd;
return 0;
}
static void profile_close_perf_events(struct profiler_bpf *obj)
{
    int i;

    for (i = profile_perf_event_cnt - 1; i >= 0; i--)
        close(profile_perf_events[i]);

    free(profile_perf_events);
    profile_perf_event_cnt = 0;
}

static void int_exit(int signo)
{
    profile_print_and_cleanup();
    exit(0);
}

static void profile_read_values(struct fentry_bpf *obj)
{
    __u32 m, cpu, num_cpu = obj->rodata->num_cpu;
    int reading_map_fd, count_map_fd;
    __u64 counts[num_cpu];
    __u32 key = 0;
    int err;

    reading_map_fd = bpf_map__fd(obj->maps.accum_readings);
    count_map_fd = bpf_map__fd(obj->maps.counts);
    if (reading_map_fd < 0 || count_map_fd < 0)
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
        struct bpf_perf_event_value values[num_cpu];

        if (!metrics[m].selected)
            continue;

        err = bpf_map_lookup_elem(reading_map_fd, &key, values);
        if (err)
        {
            fprintf(stderr, "failed to read reading_map: %s", strerror(errno));
            return;
        }
        for (cpu = 0; cpu < num_cpu; cpu++)
        {
            metrics[m].val.counter += values[cpu].counter;
            metrics[m].val.enabled += values[cpu].enabled;
            metrics[m].val.running += values[cpu].running;
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
        struct bpf_perf_event_value *val = &metrics[m].val;
        int r;

        if (!metrics[m].selected)
            continue;
        printf("%18llu %-20s", val->counter, metrics[m].name);

        r = metrics[m].ratio_metric - 1;
        if (r >= 0 && metrics[r].selected && metrics[r].val.counter > 0)
        {
            printf("# %8.2f %-30s", val->counter * metrics[m].ratio_mul / metrics[r].val.counter,
                   metrics[m].ratio_desc);
        }
        else
        {
            printf("%-41s", "");
        }

        if (val->enabled > val->running)
            printf("(%4.2f%%)", val->running * 100.0 / val->enabled);
        printf("\n");
    }
}

static void profile_print_and_cleanup(void)
{
    profile_close_perf_events(profile_obj);
    profile_read_values(profile_obj);
    profile_print_readings();
    fentry_bpf__destroy(profile_obj);

    close(profile_tgt_fd);
    free(profile_tgt_name);
}

// must be shared
int profile_tgt_fd;
struct fentry_bpf *profile_obj;
char *profile_tgt_name;
static int profile_perf_event_cnt;
static int *profile_perf_events;
static __u64 profile_total_count;

int main(int argc, char **argv)
{
    struct bpf_program *prog;
    char *endptr;

    int bpf_prog_id, num_cpu, err;

    /* we at least need two args for the prog and one metric */
    /*     if (!REQ_ARGS(3))
            return -EINVAL; */
    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, ":i:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            bpf_prog_id = strtol(optarg, &endptr, 10);
            break;
        }
    }

    /* parse target fd */
    profile_tgt_fd = bpf_prog_get_fd_by_id(bpf_prog_id);

    num_cpu = libbpf_num_possible_cpus();
    if (num_cpu <= 0)
    {
        fprintf(stderr, "failed to identify number of CPUs");
        goto out;
    }

    profile_obj = fentry_bpf__open();
    if (!profile_obj)
    {
        fprintf(stderr, "failed to open and/or load BPF object");
        goto out;
    }

    // così evito di cambiare troppe cose
    int num_metric = 1;

    profile_obj->rodata->num_cpu = num_cpu;
    profile_obj->rodata->num_metric = num_metric;

    /* adjust map sizes */
    bpf_map__set_max_entries(profile_obj->maps.events, num_metric * num_cpu);
    bpf_map__set_max_entries(profile_obj->maps.fentry_readings, num_metric);
    bpf_map__set_max_entries(profile_obj->maps.accum_readings, num_metric);
    bpf_map__set_max_entries(profile_obj->maps.counts, 1);
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
        fprintf(stderr, "failed to load profile_obj");
        goto out;
    }

    err = profile_open_perf_events(profile_obj);
    if (err)
        goto out;

    err = fentry_bpf__attach(profile_obj);
    if (err)
    {
        fprintf(stderr, "failed to attach profile_obj");
        goto out;
    }
    signal(SIGINT, int_exit);

    // invece di fare sleep, faccio un ciclo infinito
    // sleep(duration);

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
