#ifndef __INXPECT_H__
#define __INXPECT_H__

#include "mykperf_module.h"
#include "mykperf_helpers.h"

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
#define MAX_PSECTIONS 8
#define PINNED_PATH "/sys/fs/bpf/"
#define RECORD_MAP_NAME "percpu_output"

#define MAX_PROG_FULL_NAME 15

struct event
{
    const char *name;
    const __u64 code;
    int cpu; // now, work with just one cpu
    int reg_h;
    __u8 enabled;
} metrics[] = {
    {.name = "instructions", .code = 0x00c0},
    {.name = "cycles", .code = 0x003c},
    {.name = "cache-misses", .code = 0x2e41},
    {.name = "llc-misses", .code = 0x01b7},
    // questi dopo vanno settati
    {"branch_misses", 0x30c},
    {"bus_cycles", 0x30b},
    {"stalled_cycles_frontend", 0x30d},
    {"stalled_cycles_backend", 0x30e},
    {"ref_cpu_cycles", 0x30f},
    {"cpu_clock", 0x309},
    {"task_clock", 0x30a},
    {"page_faults", 0x30b},
    {"context_switches", 0x30c},
    {"cpu_migrations", 0x30d},
    {"page_faults_min", 0x30e},
    {"page_faults_maj", 0x30f},
};

struct psection_t
{
    struct record_array record;
    struct event *metric;
};

static struct event *event__get_by_name(const char *name)
{
    for (int i = 0; i < ARRAY_SIZE(metrics); i++)
    {
        if (strcmp(metrics[i].name, name) == 0)
        {
            return &metrics[i];
        }
    }
    return NULL;
}

static int event__enable(struct event *event, int cpu)
{
    int err = enable_event(event->code, &event->reg_h, cpu);
    if (err)
    {
        return -1;
    }
    fprintf(stdout, "[%s]:   %s: %x\n", DEBUG, event->name, event->reg_h);
    event->cpu = cpu;
    event->enabled = 1;
    return 0;
}

static int event__disable(struct event *event, int cpu)
{
    int err = disable_event(event->code, event->reg_h, cpu);
    if (err)
    {
        return -1;
    }
    event->enabled = 0;
    return 0;
}

static int event__name_isvalid(char *name)
{
    for (int i = 0; i < ARRAY_SIZE(metrics); i++)
    {
        if (strcmp(metrics[i].name, name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

#endif // __INXPECT_H__