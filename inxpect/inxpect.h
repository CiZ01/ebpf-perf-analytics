#ifndef __INXPECT_H__
#define __INXPECT_H__

#include "mykperf_module.h"
#include "mykperf_helpers.h"

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

// #define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
//  this is needed because of the way the metrics are defined
// ARRAY SIZE not work with extern
#define METRICS_NR 5 

#define MAX_METRICS 8
#define MAX_PSECTIONS 8
#define PINNED_PATH "/sys/fs/bpf/"
#define RECORD_MAP_NAME "percpu_output"

#define MAX_PROG_FULL_NAME 15

extern int percpu_output_fd;

struct event
{
    const char *name;
    const __u64 code;
    int cpu; // now, work with just one cpu
    int reg_h;
    __u8 enabled;
};

extern struct event metrics[];
extern int prog_fd; // just for inxpect server

struct psection_t
{
    struct record_array *record;
    struct event *metric;
};

// ---- EVENT ----------
static struct event *event__get_by_name(const char *name)
{
    for (int i = 0; i < METRICS_NR; i++)
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
    for (int i = 0; i < METRICS_NR; i++)
    {
        if (strcmp(metrics[i].name, name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// -------------------------------------

// ---------------- PSECTIONS ----------

extern struct psection_t psections[];

static int psection__get_index_by_name(const char *name)
{
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (!psections[i].record)
        {
            break;
        }
        if (strcmp(psections[i].record->name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}

static struct psection_t *psection__get_by_name(const char *name)
{
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (strcmp(psections[i].record->name, name) == 0)
        {
            return &psections[i];
        }
    }
    return NULL;
}

static int __update_record_on_map(int map_fd, struct record_array *record, int cpu)
{
    int key = psection__get_index_by_name(record->name);
    if (key < 0)
        return -1;

    int err = 0;
    struct record_array *percpu_data = calloc(libbpf_num_possible_cpus(), sizeof(struct record_array));
    err = bpf_map_lookup_elem(map_fd, &key, percpu_data);
    if (err)
    {
        free(percpu_data);
        return -1;
    }

    percpu_data[cpu] = *record;
    err = bpf_map_update_elem(map_fd, &key, percpu_data, BPF_ANY);
    free(percpu_data);
    if (err)
    {
        return -1;
    }
    return 0;
}

static int psection__change_event(struct psection_t *psection, const char *event_name)
{
    struct event *event = event__get_by_name(event_name);
    if (!event)
    {
        return -1;
    }
    if (!event->enabled)
    {
        int err = event__enable(event, psection->metric->cpu);
        if (err)
        {
            return -1;
        }
    }

    struct record_array tmp_record = *psection->record;

    // update values
    tmp_record.counter = event->reg_h;
    tmp_record.value = 0;
    tmp_record.run_cnt = 0;

    if (__update_record_on_map(percpu_output_fd, &tmp_record, psection->metric->cpu))
    {
        return -1;
    }

    // if all goes well, I update in userspace
    psection->metric = event;

    fprintf(stdout, "[%s]:  %s: %x\n", DEBUG, event->name, event->reg_h);
    memcpy(psection->record, &tmp_record, sizeof(struct record_array));
    return 0;
}

static int psection__event_disable(struct psection_t *psection)
{
    if (!psection->metric)
    {
        return 0;
    }

    if (psection->metric->enabled == 1)
    {
        int err = event__disable(psection->metric, psection->metric->cpu);
        if (err)
        {
            return -1;
        }
        psection->metric = NULL;
    }
    psection->metric->enabled--;
    psection->metric = NULL;
    psection->metric = NULL;
    return 0;
}

static int psection__set_event(struct psection_t *psection, struct event *event)
{
    if (psection->metric)
    {
        psection__event_disable(psection);
    }

    if (!event->enabled)
    {
        int err = event__enable(event, event->cpu);
        if (err)
        {
            return -1;
        }
    }
    else
    {
        event->enabled++; // count how much psections are using this event
    }
    psection->metric = event;
    return 0;
}

// get all psection in json
static void psection__get_all(char *json)
{
    json[0] = '[';
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (psections[i].record)
        {
            strcat(json, psections[i].record->name);
            strcat(json, ",");
        }
    }
    json[strlen(json) - 1] = ']';
}

// ----------- SAMPLE RATE -----------------
static int sample_rate__set(int prog_fd, int sample_rate)
{
    int fd = -1;
    int zero = 0;
    fd = get_bss_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bss bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during setting sample rate\n", ERR);
        return -1;
    }

    bss_data.__sample_rate = sample_rate;

    err = bpf_map_update_elem(fd, &zero, &bss_data, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[%s]: during setting sample rate\n", ERR);
        return -1;
    }

    close(fd);
    return 0;
}

// -------------------------------------------------

// ------------------- DATA -----------------------
static int percput_output__clean_and_init(int map_fd, int cpu)
{
    int err;
    /*    unsigned int count = MAX_PSECTIONS;
       int *keys = malloc(MAX_PSECTIONS * sizeof(int));
       // clean the map
       int err = bpf_map_delete_batch(percpu_output_fd, keys, &count, NULL);
       if (err)
       {
           fprintf(stderr, "[%s]: during cleaning map: %s\n", ERR, strerror(errno));
           fprintf(stderr, "[%s]: %d\n", DEBUG, count);
           free(keys);
           return -1;
       }
       free(keys);
    */

    // init the map
    int nr_cpus = libbpf_num_possible_cpus();
    struct record_array *percpu_values = calloc(nr_cpus, sizeof(struct record_array));

    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        percpu_values[cpu] = *psections[i_sec].record;

        err = bpf_map_update_elem(map_fd, &i_sec, percpu_values, BPF_ANY);
        if (err)
        {
            fprintf(stderr, "[%s]: during updating map\n", ERR);
            free(percpu_values);
            return -1;
        }
    }
    free(percpu_values);

    return 0;
}

static struct record_array *stats__get_by_psection_name(char *name)
{
    struct psection_t *psection = psection__get_by_name(name);
    if (!psection)
    {
        return NULL;
    }
    return psection->record;
}
#endif // __INXPECT_H__