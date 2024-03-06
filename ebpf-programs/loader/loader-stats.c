#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

// xdp prog management
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// if_nametoindex
#include <net/if.h>

// perf event
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#include "mykperf_module.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
// metrics definition
struct profile_metric
{
    const char *name;
    // unused
    // struct bpf_perf_event_value val;
    unsigned long long acc;
    struct perf_event_attr attr;
    bool selected;

    /* calculate ratios like instructions per cycle */
    const int ratio_metric; /* 0 for N/A, 1 for index 0 (cycles) */
    const char *ratio_desc;
    const float ratio_mul;
} metrics[] = {
    {
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
};
int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int verbose;
int perf_fd;
char filename[256];
char *progsec = "xdp";
char *ifname;
int prog_id;
int n_cpus;
int *perf_event_fds;

struct profile_metric selected_metrics[MAX_METRICS];
int selected_metrics_cnt;

// TODO - acc fn
int accumulate;
// how much run to wait before printing accumulated stats
// int acc_period;
// int run_cnt; not work, I don't know how to count runs

void usage(void)
{
    printf("Usage: loader-stats [OPTS]\n");
    printf("OPTS:\n");
    printf("  -i <ifname>      : interface name\n");
    printf("  -f <filename>    : bpf object file\n");
    printf("  -m <mode>        : xdp mode (skb, native)\n");
    printf("  -e <metrics>     : comma separated list of metrics to profile\n");
    printf("  -P <progsec>     : program section\n");
    printf("  -v               : verbose\n");
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int start_perf(int n_cpus)
{
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        for (int cpu = 0; cpu < n_cpus; cpu++)
        {
            perf_fd = perf_event_open(&selected_metrics[i].attr, -1, cpu, -1, 0);
            if (perf_fd < 0)
            {
                if (errno == ENODEV)
                {
                    if (verbose)
                    {
                        fprintf(stderr, "[ERR]: cpu: %d may be offline\n", cpu);
                    }
                    continue;
                }
            }

            // enable perf event
            if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0))
            {
                fprintf(stderr, "[ERR]: ioctl failed - cpu: %d metric: %s\n", cpu, selected_metrics[i].name);
                return -1;
            }
            perf_event_fds[cpu + i] = perf_fd;
        }
    }
    return 0;
}

static void int_exit(int sig)
{
    for (int i = 0; i < (selected_metrics_cnt * n_cpus); i++)
    {
        if (perf_event_fds[i] > 0)
            close(perf_event_fds[i]);
    }
    free(perf_event_fds);

    // print accumulated stats
    if (accumulate)
    {
        // set locale to print numbers with dot as thousands separator
        setlocale(LC_NUMERIC, "");
        fprintf(stdout, "Accumulated stats:\n");
        for (int i = 0; i < selected_metrics_cnt; i++)
        {
            fprintf(stdout, "       %s: %'llu\n", selected_metrics[i].name, selected_metrics[i].acc);
        }
    }

    fprintf(stdout, "[INFO]: Detaching program...\n");

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        printf("[ERR]: getting ifindex during detaching\n");
        exit(1);
    }

    // get in current prog id the xdp program attached to the interface
    // until we find a way to manage multiple prog id this is not working
    /*     if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id))
        {
            printf("[ERR]: bpf_xdp_query_id failed\n");
            exit(1);
        } */

    if (bpf_xdp_detach(ifindex, xdp_flags, NULL))
    {
        printf("[ERR]: bpf_xdp_detach failed\n");
        exit(1);
    }
    fprintf(stdout, "[INFO]: Done \n");
    exit(0);
}

// accumulate stats
int accumulate_stats(void *data)
{
    struct record *sample = data;
    // for now we accumulate value in metric struct and print it every acc_period
    // as we say before, the order of the metrics is important
    selected_metrics[sample->type_counter].acc += sample->value;
    return 0;
}

static int attach_prog(struct bpf_program *prog)
{
    int ifindex;
    // struct bpf_prog_info info = {};
    //__u32 info_len = sizeof(info);
    int prog_fd;

    if (strcmp(progsec, bpf_program__section_name(prog)) != 0)
    {
        return 0;
    }

    // get prog fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[ERR]: retrieving prog fd\n");
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "[ERR]: getting ifindex - ifname: %s \n", ifname);
        return 1;
    }

    // attach prog
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0)
    {
        fprintf(stderr, "[ERR]: attaching program - ifname: %s \n", ifname);
        return 1;
    }

    // TODO - find a way to manage multiple prog id
    /*     // get prog id
        err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
        if (err)
        {
            printf("[ERR]: can't get prog info - %s\n", strerror(errno));
            return 1;
        }
        prog_id = info.id; */
    return 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    if (accumulate)
    {
        accumulate_stats(data);
        return 0;
    }
    struct record *sample = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    // print metric name work beacouse of the order of the metrics
    // I think that the counter associated to the metric follow the order of how they are activated
    fprintf(stdout, "%-8s    %s: %llu   ( %s ) \n", ts, selected_metrics[sample->type_counter].name, sample->value,
            sample->name);
    return 0;
}

static void poll_stats(unsigned int map_fd)
{
    int err;
    struct ring_buffer *rb;
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    err = libbpf_get_error(rb);
    if (err)
    {
        rb = NULL;
        fprintf(stderr, "[ERR]: failed to open ring buffer: %d\n", err);
        int_exit(0);
    }

    while (ring_buffer__poll(rb, 100) >= 0)
    {
    }
}

int main(int arg, char **argv)
{
    int rb_map_fd = -1;
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err, opt;

    // set shared var
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;

    // retrieve opt
    while ((opt = getopt(arg, argv, ":m:P:f:i:e:a:h")) != -1)
    {
        switch (opt)
        {
        // choosen xdp mode
        case 'm':
            if (strcmp(optarg, "skb") == 0)
            {
                xdp_flags |= XDP_FLAGS_SKB_MODE;
            }
            else if (strcmp(optarg, "native") == 0)
            {
                xdp_flags |= XDP_FLAGS_DRV_MODE;
            }
            else
            {
                fprintf(stderr, "Invalid xdp mode\n");
                return 1;
            }
            break;
        case 'e':
            // parse metrics
            char *token = strtok(optarg, ",");
            while (token != NULL)
            {
                for (int i = 0; i < ARRAY_SIZE(metrics); i++)
                {
                    if (strcmp(token, metrics[i].name) == 0)
                    {
                        metrics[i].selected = true;
                        __mempcpy(&selected_metrics[selected_metrics_cnt], &metrics[i], sizeof(struct profile_metric));
                        selected_metrics_cnt++;
                    }
                }
                token = strtok(NULL, ",");
            }
            break;
        case 'P':
            progsec = optarg;
            break;
        case 'f':
            strcpy(filename, optarg);
            break;
        case 'i':
            ifname = optarg;
            break;
        case 'a':
            accumulate = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, "Invalid option\n");
            usage();
            return 1;
        }
    }

    // check mandatory opt
    if (strlen(filename) == 0 || strlen(ifname) == 0)
    {
        usage();
        return 1;
    }

    // if almost one metric is selected, allocate perf_event_fds
    if (selected_metrics_cnt > 0)
    {
        perf_event_fds = malloc((selected_metrics_cnt * n_cpus) * sizeof(int));
    }

    // get obj
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
        return 1;

    // set prog type
    bpf_object__for_each_program(prog, obj)
    {
        err = bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
        if (err)
        {
            fprintf(stderr, "[ERR]: setting program type\n");
            return 1;
        }
    }

    // load obj
    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "[ERR]: loading object\n");
        return 1;
    }

    // set trap for ctrl+c
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    fprintf(stdout, "[INFO]: Loaded object...\n");

    // get ring buffer if verbose
    if (selected_metrics_cnt > 0)
    {
        rb_map_fd = bpf_object__find_map_fd_by_name(obj, "ring_output");
        if (rb_map_fd < 0)
        {
            fprintf(stderr, "[ERR]: finding map\n");
            return 1;
        }
    }

    // start perf before loading prog
    err = start_perf(n_cpus); // perf fd will be freed during int_exit
    if (err)
    {
        int_exit(0);
        return 1;
    }

    // do attach
    int i_prog = 0;
    bpf_object__for_each_program(prog, obj)
    {
        err = attach_prog(prog);
        if (err)
        {
            int_exit(0);
            return 1;
        }
        i_prog++;
    }

    fprintf(stdout, "[INFO]: Running...\nPress Ctrl+C to stop\n");
    if (selected_metrics_cnt > 0 && rb_map_fd > 0)
    {
        // start perf before polling
        fflush(stdout);
        poll_stats(rb_map_fd);
    }
    else
    {
        printf("[INFO]: Stats not enabled\n");
        pause();
    }

    return 0;
}