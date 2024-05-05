#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>

// xdp prog management
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// if_nametoindex
#include <net/if.h>

// my modules
#include "inxpect.h"

// --- GLOBALS ---
char prog_name[MAX_PROG_FULL_NAME];
struct psection_t psections[MAX_PSECTIONS];

// percpu map
int percpu_output_fd = -1;
struct record_array percpu_data[MAX_ENTRIES_PERCPU_ARRAY];

// events
char *arg__event = NULL;
int nr_selected_events = 0;
int running_cpu = 0;

// from bpftool
static int prog_fd_by_nametag(char nametag[MAX_PROG_FULL_NAME])
{
    unsigned int id = 0;
    int err;
    int fd = -1;

    while (true)
    {
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);

        err = bpf_prog_get_next_id(id, &id);
        if (err)
        {
            if (errno != ENOENT)
            {
                fprintf(stderr, "[%s]: can't get next prog id: %s", ERR, strerror(errno));
            }
            return -1;
        }

        fd = bpf_prog_get_fd_by_id(id);
        if (fd < 0)
        {
            fprintf(stderr, "[%s]: can't get prog fd (%u): %s", ERR, id, strerror(errno));
            return -1;
        }

        err = bpf_prog_get_info_by_fd(fd, &info, &len);
        if (err)
        {
            fprintf(stderr, "[%s]: can't get prog info by fd (%u): %s", ERR, id, strerror(errno));
            return -1;
        }

        if (strncmp(nametag, info.name, sizeof(info.name)) == 0)
        {
            break;
        }
    }

    return fd;
}

static int psections__get_list(char psections_name_list[MAX_PSECTIONS][MAX_PROG_FULL_NAME])
{
    int fd = -1;
    int zero = 0;
    fd = get_rodata_map_fd();
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct rodata bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during profiler section name retrieve\n", ERR);
        return -1;
    }

    memcpy(psections_name_list, bss_data.sections, sizeof(bss_data.sections));

    close(fd);
    return 0;
}

static int percpu_output__get_fd()
{
    char filename_map[256];
    int err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, RECORD_MAP_NAME);
    if (err < 0)
    {
        fprintf(stderr, "[%s]: creating filename for pinned path: %s\n", ERR, strerror(errno));
        return -1;
    }

    // retrieve map fd from pinned path
    int map_fd = bpf_obj_get(filename_map);
    if (map_fd < 0)
    {
        fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own '%s' map", ERR, filename_map,
                prog_name, RECORD_MAP_NAME);
        return -1;
    }

    return map_fd;
}

static int percput_output__clean_and_init()
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
        if (strlen(psections[i_sec].record.name) == 0)
        {
            break;
        }

        percpu_values[running_cpu] = psections[i_sec].record;

        err = bpf_map_update_elem(percpu_output_fd, &i_sec, percpu_values, BPF_ANY);
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

static int handle_event(struct record_array percpu_data[MAX_ENTRIES_PERCPU_ARRAY])
{
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // FORMAT OUTPUT
    char *fmt = "%s     %s: %llu    (%s)  %.2f/pkt - %u run_cnt\n";

    // accumulate for each cpu
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (strlen(psections[i_sec].record.name) == 0)
            break;
        // TODO: this should be work for moore cpu, currently is useless beacouse we work wit just one cpu
        for (int cpu = 0; cpu < libbpf_num_possible_cpus(); cpu++)
        {
            if (percpu_data[cpu].name[0] == 0)
                continue;

            if (strcmp(percpu_data[cpu].name, psections[i_sec].record.name) == 0)
            {
                psections[i_sec].record.value += percpu_data[cpu].value;
                psections[i_sec].record.run_cnt += percpu_data[cpu].run_cnt;
            }
        }
        fprintf(stdout, fmt, ts, psections[i_sec].metric->name, psections[i_sec].record.value,
                psections[i_sec].record.name, (float)psections[i_sec].record.value / psections[i_sec].record.run_cnt,
                psections[i_sec].record.run_cnt);
    }

    return 0;
}

static void poll_stats(__u32 timeout_s)
{
    int err;

    while (1)
    {
        // read percpu array
        for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            err = bpf_map_lookup_elem(percpu_output_fd, &key, percpu_data);
            if (err)
            {
                continue;
            }
            handle_event(percpu_data);
        }
        sleep(timeout_s);
    }
}

static void exit_cleanup(int signo)
{
    // TODO: disable event
    int err;
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (strlen(psections[i_sec].record.name) == 0)
        {
            break;
        }

        if (psections[i_sec].metric->enabled)
        {
            err = event__disable(psections[i_sec].metric, running_cpu);
            if (err)
            {
                fprintf(stderr, "[%s]: during disabling event %s\n", ERR, psections[i_sec].metric->name);
            }
        }
    }

    if (arg__event)
        free(arg__event);

    fprintf(stdout, "[%s]: exiting\n", DEBUG);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int err, opt;
    // retrieve opt
    while ((opt = getopt(argc, argv, ":n:e:C:")) != -1)
    {
        switch (opt)
        {
        case 'n':
            if (strlen(optarg) > MAX_PROG_FULL_NAME)
            {
                fprintf(stderr, "%s: program name too long, should be no longer then %d characters\n", ERR,
                        MAX_PROG_FULL_NAME);
                exit_cleanup(0);
            }
            strcpy(prog_name, optarg);
            break;
        case 'e':
            arg__event = malloc(strlen(optarg) + 1);
            strcpy(arg__event, optarg);
            break;
        case 'C':
            running_cpu = atoi(optarg);
            break;
        case '?':
            fprintf(stderr, "%s: invalid option\n", ERR);
            exit_cleanup(0);
            break;
        }
    }

    // TODO: check any error
    if (strlen(prog_name) == 0)
    {
        fprintf(stderr, "[%s]: program name is required\n", ERR);
        exit_cleanup(0);
    }

    if (arg__event == NULL)
    {
        fprintf(stderr, "[%s]: event name is required\n", ERR);
        exit_cleanup(0);
    }

    if (!event__name_isvalid(arg__event))
    {
        fprintf(stderr, "[%s]: event name %s is not valid\n", ERR, arg__event);
        exit_cleanup(0);
    }

    // retrieve `prog_name` file descriptor by name
    int prog_fd = prog_fd_by_nametag(prog_name);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: can't get prog fd by name: %s\n", ERR, strerror(errno));
        exit_cleanup(0);
    }

    // at this point the we are sure that the program is loaded

    // retrieve the psection from xdp program
    char psections_name_list[MAX_PSECTIONS][MAX_PROG_FULL_NAME];
    err = psections__get_list(psections_name_list);
    if (err)
    {
        fprintf(stderr, "[%s]: during psections list retrieve\n", ERR);
        exit_cleanup(0);
    }

    // now we set the name and the choosen event (if provided) to the psections
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (strlen(psections_name_list[i_sec]) == 0)
        {
            break;
        }

        struct event *metric = event__get_by_name(arg__event);
        if (!metric) // TODO: this check should be done at the beginning
        {
            fprintf(stderr, "[%s]: event %s not found\n", ERR, arg__event);
            exit_cleanup(0);
        }

        strcpy(psections[i_sec].record.name, psections_name_list[i_sec]);

        // enable the event
        err = event__enable(metric, running_cpu);
        if (err)
        {
            fprintf(stderr, "[%s]: during enabling event %s\n", ERR, arg__event);
            exit_cleanup(0);
        }

        // set to the psection the related event
        psections[i_sec].metric = metric;

        // set the event to the record array
        psections[i_sec].record.counter = psections[i_sec].metric->reg_h;
        // TODO: currently reg_h is the counter, so we can use it. But I want to store the index register, so in future
        // this should be reg_h - MAX REGISETR
    }

    // retrieve percpu_output fd
    percpu_output_fd = percpu_output__get_fd();
    if (percpu_output_fd < 0)
    {
        exit_cleanup(0);
    }

    // set signal handler
    signal(SIGINT, exit_cleanup);
    signal(SIGTERM, exit_cleanup);

    err = percput_output__clean_and_init();
    if (err)
        exit_cleanup(0);

    // polling stats
    poll_stats(1);
    exit_cleanup(0);
    return 0;
}