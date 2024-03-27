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

// profiler
#include "profiler/profiler.skel.h"
#include "mykperf_module.h"

// plot
#include "gnuplot/gplot.h"

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
#define MAX_MEASUREMENT 16
#define PINNED_PATH "/sys/fs/bpf/"

struct section_stats
{
    __u64 acc_value;
    char name[16];
    __u64 run_cnt; // if the sections are sampled, we can count the runs

    // I don't need type counter attribute, this struct is used inside `profile_metric`
};

// metrics definition
struct profile_metric
{
    const char *name;
    // unused
    // struct bpf_perf_event_value val;
    struct section_stats *acc_persection;
    struct perf_event_attr attr;
    bool selected;

    /* calculate ratios like instructions per cycle */
    const int ratio_metric; /* 0 for N/A, 1 for index 0 (cycles) */
    const char *ratio_desc;
    const float ratio_mul;
} metrics[] = {
    {
        // cycles
        .name = "cycles",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_CPU_CYCLES,
                .exclude_user = 1,
            },
    },
    {
        // instructions
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
        // branch misses
        .name = "branch-misses",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_BRANCH_MISSES,
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "branch-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // cache misses
        .name = "cache-misses",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_CACHE_MISSES,
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "cache-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // L1-dcache-load-misses
        .name = "L1-dcache-load-misses",
        .attr =
            {
                .type = PERF_TYPE_HW_CACHE,
                .config = (PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                           (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)),
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "L1-dcache-load-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // LLC-load-misses
        .name = "LLC-load-misses",
        .attr =
            {
                .type = PERF_TYPE_HW_CACHE,
                .config = (PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                           (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)),
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "LLC-load-misses per cycle",
        .ratio_mul = 1.0,
    },
};

struct bpf_object *obj;
int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int verbose;
int perf_fd;
int load;
struct bpf_prog_info info;
__u32 info_len;
int prog_fd;
int prog_id;
char filename[256];
char *prog_name;
char *ifname;
int n_cpus;
int *perf_event_fds;
struct ring_buffer *rb;

// plot
int do_plot;
struct gnuplot_cfg *plot_cfg;

// profiler
static struct profiler *profile_obj;
int enable_run_cnt;
__u64 run_cnt;

// output file
FILE *output_file;
char *output_filename;

// DEBUG
int x;

struct profile_metric selected_metrics[MAX_METRICS];
int selected_metrics_cnt;

// TODO - acc fn
int accumulate;

void usage()
{
    printf("Usage: loader-stats -i <ifname> -f <filename> -m <mode>\n");
    printf("  -f <filename>        : BPF object file to load\n");
    printf("  -n <prog id>         : Program id (only for programs already loaded)\n");
    printf("  -i <ifname>          : Interface name\n");
    printf("  -m <mode>            : xdp mode (skb, native)\n");
    // -P not work properly
    printf("  -P <prog_name>       : Program section name\n");
    printf("  -e <metrics>         : Comma separated list of metrics\n");
    printf("  -a                   : Accumulate stats\n");
    printf("  -c                   : Enable run count\n");
    printf("  -l                   : Load program\n");
    printf("  -o <output_filename> : Output filename\n");
    printf("  -v                   : Verbose\n");
    printf("  -s                   : Supported metrics\n");
    printf("  -h                   : Print this help\n");
}

void supported_metrics()
{
    printf("Supported metrics:\n");
    for (int i = 0; i < ARRAY_SIZE(metrics); i++)
    {
        printf("  %s\n", metrics[i].name);
    }
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
                        fprintf(stderr, "[%s]: cpu: %d may be offline\n", WARN, cpu);
                    }
                    continue;
                }
                else
                {
                    fprintf(stderr, "[%s]: perf_event_open failed - cpu: %d metric: %s\n", ERR, cpu,
                            selected_metrics[i].name);
                }
            }

            // enable perf event
            if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0))
            {
                fprintf(stderr, "[%s]: ioctl failed - cpu: %d metric: %s\n", ERR, cpu, selected_metrics[i].name);
                return -1;
            }
            perf_event_fds[cpu + i] = perf_fd;
        }
    }
    return 0;
}

static void print_accumulated_stats()
{
    float percentage = 0;
    float avg_single_run = 0;

    fprintf(stdout, "\nAccumulated stats\n\n");
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        fprintf(stdout, "%s\n", selected_metrics[i].name);
        for (int s = 0; s < MAX_MEASUREMENT; s++)
        {
            if (strlen(selected_metrics[i].acc_persection[s].name) > 0)
            {

                if (enable_run_cnt)
                {
                    percentage = ((float)selected_metrics[i].acc_persection[s].run_cnt / run_cnt) * 100;
                }
                avg_single_run = (float)selected_metrics[i].acc_persection[s].acc_value /
                                 selected_metrics[i].acc_persection[s].run_cnt;

                fprintf(stdout, "[%s]: %s - %'llu runs\n", DEBUG, selected_metrics[i].acc_persection[s].name,
                        selected_metrics[i].acc_persection[s].run_cnt);
                fprintf(stdout, "    %s: %'llu      (%.2f%%)    avg: %2.f/pkt\n\n",
                        selected_metrics[i].acc_persection[s].name, selected_metrics[i].acc_persection[s].acc_value,
                        percentage, avg_single_run);
            }
            else
            {
                // here we can break the loop if we find a null section,
                // because the next sections will be null too
                break;
            }
        }
    }
}

static void init_exit(int sig)
{
    // consume remaining events
    if (rb)
    {
        int n = ring_buffer__consume(rb);
        if (n < 0)
        {
            fprintf(stderr, "[%s]: failed to consume ring buffer\n", WARN);
        }
        else if (verbose) // if verbose is set, print the number of consumed events
        {
            fprintf(stdout, "[%s]: consumed %d events before exit\n", INFO, n);
        }
        ring_buffer__free(rb);
    }

    for (int i = 0; i < (selected_metrics_cnt * n_cpus); i++)
    {
        if (perf_event_fds[i] > 0)
            close(perf_event_fds[i]);
    }
    free(perf_event_fds);

    // close output file
    if (output_file)
        fclose(output_file);

    // set locale to print numbers with dot as thousands separator
    setlocale(LC_NUMERIC, "");

    if (enable_run_cnt)
    {
        // set locale to print numbers with dot as thousands separator
        // setlocale(LC_NUMERIC, "");

        // retrieve count fd
        int counts_fd = bpf_map__fd(profile_obj->maps.counts);
        if (counts_fd < 0)
        {
            fprintf(stderr, "[%s]: retrieving counts fd, runs was not counted\n", ERR);
            run_cnt = 0;
        }
        else
        {

            // retrieve count value
            __u64 counts[n_cpus];
            __u32 key = 0;
            int err = bpf_map_lookup_elem(counts_fd, &key, counts);
            if (err)
            {
                fprintf(stderr, "[%s]: retrieving run count\n", ERR);
            }

            for (int i = 0; i < n_cpus; i++)
            {
                run_cnt += counts[i];
                if (verbose && counts[i] > 0)
                {
                    fprintf(stdout, "\nCPU[%03d]: %'llu", i, counts[i]);
                }
            }
        }
        fprintf(stdout, "\nTotal run_cnt: %'llu     [N.CPUS: %d]\n", run_cnt, n_cpus);

        profiler__detach(profile_obj);
        profiler__destroy(profile_obj);
    }

    // print accumulated stats
    if (accumulate)
    {
        print_accumulated_stats();
    }

    // after read, free acc_persection
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        free(selected_metrics[i].acc_persection);
    }

    fprintf(stdout, "[%s]: Detaching program...\n", INFO);

    // if the program was loaded by this tool, detach it
    if (load)
    {
        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0)
        {
            fprintf(stderr, "[%s]: getting ifindex during detaching\n", ERR);
        }
        else
        {
            // get in current prog id the xdp program attached to the interface
            // until we find a way to manage multiple prog id this is not working
            /*     if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id))
                {
                    printf("[ERR]: bpf_xdp_query_id failed\n");
                    exit(1);
                } */

            if (bpf_xdp_detach(ifindex, xdp_flags, NULL))
            {
                fprintf(stderr, "%s: bpf_xdp_detach failed\n", ERR);
            }
        }
    }

    // free plot_cfg
    if (do_plot)
    {
        gplot_close();
        free(plot_cfg);
    }
    bpf_object__close(obj);
    fprintf(stdout, "[%s]: Done \n", INFO);
    exit(0);
}

void moving_avg(FILE *file_data)
{
    time_t t;
    time(&t);
    struct tm *tm;
    char ts[32];
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    char value[16];
    char data[64];
    x++;
    // add time to data
    snprintf(data, 64, "%d", x);
    for (int s = 0; s < MAX_MEASUREMENT; s++)
    {
        for (int m = 0; m < selected_metrics_cnt; m++)
        {
            if (strlen(selected_metrics[m].acc_persection[s].name) != 0)
            {
                snprintf(value, sizeof(value), " %.2f",
                         (float)selected_metrics[m].acc_persection[s].acc_value /
                             selected_metrics[m].acc_persection[s].run_cnt);
                strcat(data, value);
            }
            else
            {
                break;
            }
        }
    }
    fprintf(file_data, "%s\n", data);
    fflush(file_data);
    return;
}

// accumulate stats
void accumulate_stats(void *data)
{
    struct record *sample = data;

    if (sample->type_counter >= selected_metrics_cnt)
    {
        return;
    }

    // find section if exists
    for (int s = 0; s < MAX_MEASUREMENT; s++)
    {
        // if the section is null, we can create a new one and stop the loop
        if (strlen(selected_metrics[sample->type_counter].acc_persection[s].name) == 0)
        {
            strcpy(selected_metrics[sample->type_counter].acc_persection[s].name, sample->name);
            selected_metrics[sample->type_counter].acc_persection[s].acc_value = sample->value;
            selected_metrics[sample->type_counter].acc_persection[s].run_cnt = 1;
            return;
        }

        // if the section exists, we can accumulate the value and stop the loop
        if (strcmp(sample->name, selected_metrics[sample->type_counter].acc_persection[s].name) == 0)
        {
            selected_metrics[sample->type_counter].acc_persection[s].acc_value += sample->value;
            selected_metrics[sample->type_counter].acc_persection[s].run_cnt++;
            return;
        }
    }

    return;
}

int attach_profiler(struct bpf_program *prog)
{
    int err;
    // this will be the profiler program
    struct bpf_program *prof_prog;
    if (!prog_name)
    {
        prog_name = (char *)bpf_program__name(prog);
    }

    bpf_object__for_each_program(prof_prog, profile_obj->obj)
    {
        err = bpf_program__set_attach_target(prof_prog, prog_fd, prog_name);
        if (err)
        {
            fprintf(stderr, "[%s]: setting attach target during profiler init\n", ERR);
            return 1;
        }
    }

    // load profiler
    err = profiler__load(profile_obj);
    if (err)
    {
        fprintf(stderr, "[%s]: loading profiler\n", ERR);
        return 1;
    }

    // attach profiler
    err = profiler__attach(profile_obj);
    if (err)
    {
        fprintf(stderr, "[%s]: attaching profiler\n", ERR);
        return 1;
    }

    return 0;
}

static int attach_prog(struct bpf_program *prog)
{
    int ifindex;
    int err;

    if (prog_name && strcmp(prog_name, bpf_program__name(prog)) != 0)
        return 0;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "[%s]: getting ifindex - ifname: %s \n", ERR, ifname);
        return 1;
    }

    // get prog fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: retrieving prog fd\n", ERR);
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0)
    {
        fprintf(stderr, "[%s]: attaching program - ifname: %s \n", ERR, ifname);
        return 1;
    }

    // TODO - find a way to manage multiple prog id
    // get prog id
    err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
    if (err)
    {
        // I'm not sure if strerror manage errno properly
        printf("[%s]: can't get prog info - %s\n", ERR, strerror(errno));
        return 1;
    }

    fprintf(stdout, "[%s]: Attached profiler\n", INFO);

    return 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct record *sample = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (output_file)
    {
        fprintf(output_file, "%s     %s: %llu    (%s)\n", ts, selected_metrics[sample->type_counter].name,
                sample->value, sample->name);
    }

    if (accumulate)
    {
        accumulate_stats(data);
        return 0;
    }

    if (!output_file)
    {

        fprintf(stdout, "%s     %s: %llu    (%s)\n", ts, selected_metrics[sample->type_counter].name, sample->value,
                sample->name);
        fflush(stdout);
    }
    return 0;
}

static void poll_stats(unsigned int map_fd)
{
    int err;

    time_t start_time = time(NULL);
    time_t current_time;

    // start plot process
    if (do_plot)
    {
        pid_t plot_pid = fork();
        if (plot_pid == 0)
        {
            // child process
            gplot_plot_poll();
            exit(0);
        }
        else if (plot_pid < 0)
        {
            fprintf(stderr, "[%s]: forking plot process\n", ERR);
            init_exit(0);
        }
    }

    //// FIX - when a new ring buffer is opened, it receives the data that was not read previous
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    err = libbpf_get_error(rb);
    if (err)
    {
        rb = NULL;
        fprintf(stderr, "[%s]: failed to open ring buffer: %d\n", ERR, err);
        init_exit(0);
    }

    /*
     * we must consume the events received before this tool was started,
     * otherwise some statistics would have wrong values compared with the data calculated by the tool.
     * The statistics involved:
     *   - percentage of samples
     */

    int n = ring_buffer__consume(rb);
    if (n < 0)
    {
        fprintf(stderr, "[%s]: failed to consume ring buffer\n some value could be wrong", WARN);
    }
    else
    {
        if (verbose) // if verbose is set, print the number of consumed events
            fprintf(stdout, "[%s]: consumed %d events before start\n", INFO, n);
    }

    while (ring_buffer__poll(rb, 1000) >= 0)
    {
        if (do_plot)
        {
            current_time = time(NULL);
            if (current_time - start_time > plot_cfg->poll_interval)
            {
                moving_avg(plot_cfg->fp);
                start_time = current_time;
            }
        }
    }

    // this could be an alternative to ring_buffer__poll
    // should improve notification adaptation, but needs to be tested
    // int timeout = 10;
    // while (2)
    //{
    //    ring_buffer__consume(rb);
    //    sleep(timeout);
    //}
}

int main(int arg, char **argv)
{
    int rb_map_fd = -1;
    struct bpf_program *prog;
    int err, opt;

    // set shared var
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;
    load = 0;
    prog_name = NULL;
    info_len = sizeof(info);
    plot_cfg = malloc(sizeof(struct gnuplot_cfg));
    x = 0;

    // retrieve opt
    while ((opt = getopt(arg, argv, ":m:P:f:n:i:e:ao:hsvlcx")) != -1)
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
                        memcpy(&selected_metrics[selected_metrics_cnt], &metrics[i], sizeof(struct profile_metric));
                        selected_metrics_cnt++;
                    }
                }
                token = strtok(NULL, ",");
            }
            break;
        case 'P':
            prog_name = optarg;
            break;
        case 'f':
            strcpy(filename, optarg);
            break;
        case 'n':
            prog_id = atoi(optarg);
            break;
        case 'l':
            load = 1;
            break;
        case 'i':
            ifname = optarg;
            break;
        case 'a':
            accumulate = 1;
            break;
        case 'c':
            enable_run_cnt = 1;
            break;
        case 'o':
            output_filename = optarg;
            break;
        // find a appropriate name for this
        case 'x':
            do_plot = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            return 0;
        case 's':
            supported_metrics();
            return 0;
        default:
            fprintf(stderr, "Invalid option: %c\n", opt);
            usage();
            return 1;
        }
    }

    // check mandatory opt
    if (!strlen(filename) || !strlen(ifname))
    {
        usage();
        return 1;
    }

    // check mutual exclusive opt
    if (load && prog_id)
    {
        fprintf(stderr,
                "[%s]: -n is used to retrieve statistics from an already loaded program, use -l to load a program\n",
                ERR);
        return 1;
    }

    // if at least one metric is selected, allocate perf_event_fds
    if (selected_metrics_cnt > 0)
    {
        perf_event_fds = malloc((selected_metrics_cnt * n_cpus) * sizeof(int));
        for (int m = 0; m < selected_metrics_cnt; m++)
        {
            selected_metrics[m].acc_persection = malloc(MAX_MEASUREMENT * sizeof(struct section_stats));
            if (!selected_metrics[m].acc_persection)
            {
                fprintf(stderr, "[%s]: allocating memory for section stats\n", ERR);
                return 1;
            }
            selected_metrics[m].acc_persection->run_cnt = 0;
            selected_metrics[m].acc_persection->acc_value = 0;
            // define for safety
            selected_metrics[m].acc_persection->name[0] = '\0';
        }
    }

    // if enable_run_cnt is set, enable run count
    // open profile object
    if (enable_run_cnt)
    {
        profile_obj = profiler__open();
        if (!profile_obj)
        {
            fprintf(stderr, "[%s]: opening profile object\n", ERR);
            return 1;
        }
    }

    // get obj
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
        return 1;

    // load obj
    if (load)
    {
        // set prog type
        bpf_object__for_each_program(prog, obj)
        {
            err = bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
            if (err)
            {
                fprintf(stderr, "[%s]: setting program type\n", ERR);
                return 1;
            }
        }

        err = bpf_object__load(obj);
        if (err)
        {
            fprintf(stderr, "[%s]: loading object\n", ERR);
            return 1;
        }
    }

    // set trap for ctrl+c
    signal(SIGINT, init_exit);
    signal(SIGTERM, init_exit);

    fprintf(stdout, "[%s]: Loaded object...\n", INFO);

    // get ring buffer if at least one metric is selected
    if (selected_metrics_cnt > 0)
    {
        if (load)
        {
            rb_map_fd = bpf_object__find_map_fd_by_name(obj, "ring_output");
            if (rb_map_fd < 0)
            {
                fprintf(stderr, "[%s]: finding map\n", ERR);
                return 1;
            }
        }
        else // if not loaded by this tool, retrieve map fd
        {
            char filename_map[256];
            err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, "ring_output");
            if (err < 0)
            {
                fprintf(stderr, "[%s]: creating filename for pinned path\n", ERR);
                return 1;
            }

            // retrieve map fd from pinned path
            rb_map_fd = bpf_obj_get(filename_map);
            if (rb_map_fd < 0)
            {
                fprintf(stderr, "[%s]: getting map fd from pinned path: %s\n", ERR, filename_map);
                return 1;
            }
        }
    }

    // start perf before loading prog
    err = start_perf(n_cpus); // perf fd will be freed during init_exit
    if (err)
    {
        init_exit(0);
        return 1;
    }

    // if user wants plot, do it
    if (do_plot)
    {
        char *plot_filename = "tmp_data.txt";
        char *plot_title = "Metrics";

        // plot config
        memcpy(plot_cfg->filename, plot_filename, strlen(plot_filename));
        memcpy(plot_cfg->title, plot_title, strlen(plot_title));
        plot_cfg->poll_interval = 1;

        time_t t;
        time(&t);

        // plot init
        err = gplot_init(plot_cfg);
        if (err || !plot_cfg->fp)
        {
            fprintf(stderr, "[%s]: initializing plot\n", ERR);
            init_exit(0);
            return 1;
        }

        // see handle_event function for data writing
    }

    // do attach
    int i_prog = 0;
    if (load)
    {

        bpf_object__for_each_program(prog, obj)
        {
            // attach prog to interface and if enable_run_cnt is set, enable run count
            // attaching a fentry program

            // the program will be attached only if load is set

            err = attach_prog(prog);
            if (err)
            {
                init_exit(0);
                return 1;
            }
            if (enable_run_cnt)
            {
                err = attach_profiler(prog);
                if (err)
                {
                    init_exit(0);
                    return 1;
                }
            }
            i_prog++;
        }
    }
    else // if not loaded by this tool, retrieve prog fd
    {
        // retrieve prog fd
        prog_fd = bpf_prog_get_fd_by_id(prog_id);
        if (prog_fd < 0)
        {
            fprintf(stderr, "[%s]: retrieving prog fd for program id: %d\n", ERR, prog_id);
            return 1;
        }

        // get prog name
        // check if id is the same specified by -n
        err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
        if (err)
        {
            fprintf(stderr, "[%s]: getting prog info by fd\n", ERR);
            return 1;
        }

        // set prog name
        if (!prog_name)
        {
            prog_name = info.name;
        }

        if (enable_run_cnt)
        {
            err = attach_profiler(prog);
            if (err)
            {
                init_exit(0);
                return 1;
            }
        }
        fprintf(stdout, "[%s]: Program name: %s\n", DEBUG, info.name);
    }

    fprintf(stdout, "[%s]: Running... \nPress Ctrl+C to stop\n", INFO);
    if (selected_metrics_cnt > 0 && rb_map_fd > 0)
    {
        // TODO - Using file as output instead stdout may not work properly
        // I either fixed the problem or I forgot what it was :)
        if (output_filename)
        {
            output_file = fopen(output_filename, "w");
            if (output_file == NULL)
            {
                fprintf(stderr, "[%s]: opening output file\n", ERR);
                init_exit(0);
                return 1;
            }
        }
        // start perf before polling
        poll_stats(rb_map_fd);
    }
    else
    {
        printf("[%s]: Stats not enabled\n", INFO);
        pause();
    }

    // there is a remote possibility that the poll_stats function will return an error
    // and the programm will end without calling init_exit function
    // so we call it here
    init_exit(0);

    return 0;
}
