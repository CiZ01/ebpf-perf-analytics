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
#include "mykperf_helpers.h"

// plot
#include "gnuplot/gplot.h"

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
#define MAX_MEASUREMENT 8
#define PINNED_PATH "/sys/fs/bpf/"

// metrics definition
struct profile_metric
{
    const char *name;
    const __u64 code;
    int cpu;
    __u8 enabled;
    struct record_array data_section[MAX_MEASUREMENT];
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

#define MAX_PROG_FULL_NAME 15
#define NS_PER_SECOND 1000000000

struct bpf_object *obj;
int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int verbose;
int perf_fd;
int load;
struct bpf_prog_info info;
__u32 info_len;
int prog_fd;
int prog_id;
char func_name[15];
char filename[256];
char *prog_name;
char *ifname;
int n_cpus;
int *perf_event_fds;
struct record_array *data;
int array_map_fd;
int firtst_offline_cpu;

// time variables
struct timespec start_running_time;
struct timespec end_running_time;
struct timespec delta;

int throw_away_events;

// plot
int do_plot;
struct gnuplot_cfg *plot_cfg;
int x_axis;

// profiler
static struct profiler *profile_obj;

// run count
int enable_run_cnt;
__u64 run_cnt;

// output file
FILE *output_file;
char output_filename[256];

// sample rate
__u64 sample_rate;

int running_cpu;

struct profile_metric selected_metrics[MAX_METRICS];
int selected_metrics_cnt;
char section_list[8][15];

// TODO - acc fn
int accumulate;

void usage()
{
    printf("Usage: loader-stats -i <ifname> -f <filename> -m <mode>\n");
    printf("  -f <filename>        : BPF object file to load\n");
    printf("  -n <func name>       : XDP function name (only for programs already loaded)\n");
    printf("  -i <ifname>          : Interface name\n");
    printf("  -m <mode>            : xdp mode (skb, native)\n");
    // -P not work properly
    printf("  -P <prog_name>       : Program section name\n");
    printf("  -e <metrics>         : Comma separated list of metrics\n");
    printf("  -a                   : Accumulate stats\n");
    printf("  -c                   : Enable run count\n");
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

static int get_run_count()
{
    int fd = 0;
    int zero = 0;
    fprintf(stdout, "[%s]: Getting run count\n", INFO);
    fd = get_bss_map_fd();
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bss data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &data);
    if (err)
    {
        fprintf(stderr, "[%s]: during updating sample rate\n", ERR);
        return -1;
    }

    int run_count = data.run_cnt;

    close(fd);
    return run_count;
}

static int start_perf(int n_cpus)
{
    int err;
    __u64 out_reg = 0;
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        err = enable_event(selected_metrics[i].code, &out_reg, selected_metrics[i].cpu);
        if (err)
        {
            fprintf(stderr, "[%s]: during enabling event %s: %s\n", ERR, selected_metrics[i].name, strerror(errno));
            return -1;
        }
        fprintf(stdout, "[%s]:   %s: %llx\n", DEBUG, selected_metrics[i].name, out_reg);
        selected_metrics[i].enabled = 1;
        for (int i = 0; i < MAX_MEASUREMENT; i++)
        {
            if (section_list[i][0] != 0)
            {
                strcpy(selected_metrics[i].data_section[i].name, section_list[i]);
                selected_metrics[i].data_section[i].counter = out_reg;
            }
        }
    }
    return 0;
}

static void end_perf()
{
    int err;
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        if (selected_metrics[i].enabled)
        {
            fprintf(stdout, "[%s]: Disabling event %s\n", INFO, selected_metrics[i].name);
            for (int j = 0; j < MAX_MEASUREMENT; j++)
            {
                if (section_list[i][0] != 0)
                {
                    strcpy(selected_metrics[i].data_section[i].name, section_list[i]);
                    err = disable_event(selected_metrics[i].data_section[j].counter, selected_metrics[i].code,
                                        selected_metrics[i].cpu);
                    if (err < 0)
                    {
                        fprintf(stderr, "[%s]: during disabling event %s: %s\n", ERR, selected_metrics[i].name,
                                strerror(errno));
                    }
                }
            }
            selected_metrics[i].enabled = 0;
        }
    }
    return;
}

static void print_accumulated_stats()
{
    struct record_array sample = {0};
    int err;
    // read percpu array
    for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
        sample.name[0] = 0;
        err = bpf_map_lookup_elem(array_map_fd, &key, data);
        if (err)
        {
            fprintf(stderr, "[%s]: during last bpf_map_lookup_elem: %s\n", ERR, strerror(errno));
            continue;
        }
        // accumulate for each cpu
        for (int cpu = 0; cpu < n_cpus; cpu++)
        {
            if (data[cpu].name[0] != 0)
            {
                sample.value += data[cpu].value;
                sample.run_cnt += data[cpu].run_cnt;
                if (sample.name[0] == 0)
                {
                    strcpy(sample.name, data[cpu].name);
                    sample.counter = data[cpu].counter;
                }
            }
        }

        if (sample.name[0] != 0)
        {
            fprintf(stdout, "    %s: %llu  - %llu run_count \n\n", sample.name, sample.value, sample.run_cnt);
        }
    }
    return;
}

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}

// from bpftool
static int prog_fd_by_nametag(char nametag[15])
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

static int handle_event(struct record_array *data)
{
    struct record_array sample = {0};

    // accumulate for each cpu
    for (int cpu = 0; cpu < firtst_offline_cpu; cpu++)
    {
        if (data[cpu].name[0] != 0)
        {
            sample.value += data[cpu].value;
            sample.run_cnt += data[cpu].run_cnt;
            if (sample.name[0] == 0)
            {
                strcpy(sample.name, data[cpu].name);
                sample.counter = data[cpu].counter;
            }
        }
    }

    if (sample.name[0] == 0)
    {
        return 0;
    }

    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // FORMAT OUTPUT
    char *fmt = "%s     %s: %llu    (%s)  %.2f/pkt - %u run_cnt\n";

    if (output_file != NULL)
    {
        fprintf(output_file, fmt, ts, selected_metrics[sample.counter].name, sample.value, sample.name,
                (float)sample.value / sample.run_cnt, sample.run_cnt);
    }

    if (!output_file)
    {

        fprintf(stdout, fmt, ts, selected_metrics[sample.counter].name, sample.value, sample.name,
                (float)sample.value / sample.run_cnt, sample.run_cnt);
        fflush(stdout);
    }
    return 0;
}

static void init_exit(int sig)
{

    // read end timestamp
    clock_gettime(CLOCK_MONOTONIC, &end_running_time);
    sub_timespec(start_running_time, end_running_time, &delta);

    // consume remaining events
    if (selected_metrics_cnt)
    {
        for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            if (bpf_map_lookup_elem(array_map_fd, &key, data))
                continue;

            handle_event(data);
        }
    }
    free(data);

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
    if (selected_metrics_cnt > 0)
    {
        print_accumulated_stats();
    }

    // print delta time
    fprintf(stdout, "[%s]: Elapsed time: %d.%09ld\n", INFO, (int)delta.tv_sec, delta.tv_nsec);
    // print delta time from loading

    if (info.run_time_ns > 0) // this work only with bpf_stats enabled
        fprintf(stdout, "[%s]: Elapsed time from loading: %d.%09lld\n", INFO, (int)info.run_time_ns / NS_PER_SECOND,
                info.run_time_ns % NS_PER_SECOND);

    if (run_cnt)
        fprintf(stdout, "[%s]: Troughtput: %d.%09lld\n", INFO, (int)(run_cnt / delta.tv_sec), run_cnt / delta.tv_nsec);

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

    if (selected_metrics_cnt)
    {
        end_perf();
    }

    bpf_object__close(obj);
    fprintf(stdout, "[%s]: Done \n", INFO);
    exit(0);
}

/* void moving_avg(FILE *file_data)
{
    time_t t;
    time(&t);
    struct tm *tm;
    char ts[32];
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    char value[16];
    char row[64];
    x_axis++;
    // add time to data
    snprintf(row, 64, "%d", x_axis);
    for (int s = 0; s < MAX_MEASUREMENT; s++)
    {
        for (int m = 0; m < selected_metrics_cnt; m++)
        {
            if (strlen(selected_metrics[m].data_section.name) != 0)
            {
                snprintf(value, sizeof(value), " %.2f",
                         (float)selected_metrics[m].data_section.value / selected_metrics[m].data_section.run_cnt);
                strcat(row, value);
            }
            else
            {
                break;
            }
        }
    }
    fprintf(file_data, "%s\n", row);
    fflush(file_data);
    return;
}
 */
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

static void poll_stats(unsigned int map_fd, __u32 timeout_ns)
{
    int err;

    time_t start_time = time(NULL);
    time_t current_time;

    // start plot process
    if (do_plot)
    {
        pid_t plot_pid = fork();
        if (plot_pid == 0) // CHILD PROCESS
        {
            // set default signal handler, otherwise the plot process calls init_exit
            signal(SIGINT, SIG_DFL);
            gplot_plot_poll();
            exit(0);
        }
        else if (plot_pid < 0)
        {
            fprintf(stderr, "[%s]: forking plot process\n", ERR);
            init_exit(0);
        }
    }

    while (1)
    {
        // read percpu array
        for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            err = bpf_map_lookup_elem(map_fd, &key, data);
            if (err)
            {
                continue;
            }
            handle_event(data);
        }
        if (do_plot)
        {
            current_time = time(NULL);
            if (current_time - start_time > plot_cfg->poll_interval)
            {
                // moving_avg(plot_cfg->fp);
                start_time = current_time;
            }
        }
        sleep(timeout_ns / 1000);
    }
}

static int get_psec_name_list(char section_list_out[8][15])
{
    int fd = 0;
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

    memcpy(section_list_out, bss_data.sections, sizeof(bss_data.sections));

    close(fd);
    return 0;
}

int main(int arg, char **argv)
{
    struct bpf_program *prog;
    int err, opt;

    // set shared var
    ifname = "\0";
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;
    load = 0;
    prog_name = NULL;
    info_len = sizeof(info);
    plot_cfg = malloc(sizeof(struct gnuplot_cfg));
    data = malloc(n_cpus * sizeof(struct record_array));
    array_map_fd = -1;
    firtst_offline_cpu = -1;
    x_axis = 0;
    running_cpu = 0;

    // retrieve opt
    while ((opt = getopt(arg, argv, ":m:P:f:n:i:e:ao:C:r:hsvcx")) != -1)
    {
        switch (opt)
        {
        // choosen xdp mode
        case 'm':
            if (strcmp(optarg, "skb") == 0)
            {
                xdp_flags |= XDP_FLAGS_SKB_MODE;
            }
            else
            {
                xdp_flags |= XDP_FLAGS_DRV_MODE;
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
            load = 1;
            break;
        case 'n':
            strcpy(func_name, optarg);
            break;
        case 'i':
            ifname = optarg;
            break;
        case 'r':
            sample_rate = atoi(optarg);
            break;
        case 'a':
            accumulate = 1;
            break;
        case 'c':
            enable_run_cnt = 1;
            break;
        case 'C':
            running_cpu = atoi(optarg);
            break;
        case 'o':
            memcpy(output_filename, optarg, strlen(optarg));
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

    // set cpu
    if (running_cpu != 0)
    {
        for (int i = 0; i < selected_metrics_cnt; i++)
        {
            selected_metrics[i].cpu = running_cpu;
        }
    }

    // TODO: improve this
    // for loading filename and ifname are mandatory
    // for only stats prog_name is mandatory
    if (strlen(filename) == 0 && strlen(func_name) == 0)
    {
        fprintf(stderr, "[%s]: -f or -n is mandatory\n", ERR);
        return 1;
    }
    // check mutual exclusive opt
    if (strlen(filename) > 0 && strlen(func_name) > 0)
    {
        fprintf(
            stderr,
            "[%s]: -n is used to retrieve statistics from an already loaded program, use -l and -f to load a program\n",
            ERR);
        return 1;
    }

    // check mutual exclusive opt
    if (load && strlen(func_name) > 0)
    {
        fprintf(
            stderr,
            "[%s]: -n is used to retrieve statistics from an already loaded program, use -l and -f to load a program\n",
            ERR);
        return 1;
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

    // load obj
    if (load)
    {
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

    if (selected_metrics_cnt > 0)
    {
        err = get_psec_name_list(section_list);
        if (err)
        {
            fprintf(stderr, "[%s]: getting section name list\n", ERR);
            return 1;
        }

        // enable PMC
        err = start_perf(n_cpus);
        if (err)
        {
            init_exit(0);
            return 1;
        }

        if (load)
        {
            array_map_fd = bpf_object__find_map_fd_by_name(obj, "percpu_output");
            if (array_map_fd < 0)
            {
                fprintf(stderr, "[%s]: finding map\nbe sure %s program own 'percpu_output' map", ERR, filename);
                return 1;
            }
        }
        else // if not loaded by this tool, retrieve map fd
        {
            char filename_map[256];
            err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, "percpu_output");
            if (err < 0)
            {
                fprintf(stderr, "[%s]: creating filename for pinned path: %s\n", ERR, strerror(errno));
                return 1;
            }

            // retrieve map fd from pinned path
            array_map_fd = bpf_obj_get(filename_map);
            if (array_map_fd < 0)
            {
                fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own 'percpu_output' map",
                        ERR, filename_map, func_name);
                return 1;
            }
        }

        /*
         * we must delete the events received before this tool was started,
         * otherwise some statistics would have wrong values compared with the data calculated by the tool.
         * The statistics involved:
         *   - percentage of samples
         */

        // update each element of the map with a zeroed array
        struct record_array *init_values = calloc(n_cpus, sizeof(struct record_array));

        for (__u32 key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            err = bpf_map_update_elem(array_map_fd, &key, init_values, 0);
            if (err)
            {
                fprintf(stderr, "[%s]: deleting map element: %s\n", ERR, strerror(errno));
                return 1;
            }
        }

        for (int i = 0; i < selected_metrics_cnt; i++)
        {
            if (!selected_metrics[i].enabled)
                continue;
            for (int j = 0; j < MAX_MEASUREMENT; j++)
            {
                if (selected_metrics[i].data_section[j].name[0] != 0)
                {
                    // update the init value
                    init_values[running_cpu] = selected_metrics[i].data_section[j];
                    err = bpf_map_update_elem(array_map_fd, &j, init_values, 0);
                    if (err)
                    {
                        fprintf(stderr, "[%s]: during init map element: %s\n", ERR, strerror(errno));
                        return 1;
                    }
                }
                break;
            }
        }
        free(init_values);
    }

    // if user wants plot, do it
    if (do_plot)
    {
        char *plot_filename = "/tmp/loader-stats-plot.data";
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

        fprintf(plot_cfg->fp, "1 1\n2 2\n");
        fflush(plot_cfg->fp);

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
        prog_fd = prog_fd_by_nametag(func_name);
        if (prog_fd < 0)
        {
            fprintf(stderr, "[%s]: during prog fd retreive for program name: %s\n", ERR, func_name);
            return 1;
        }

        // get prog name
        // check if id is the same specified by -n
        err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
        if (err)
        {
            fprintf(stderr, "[%s]: during getting prog info by fd: %d\n", ERR, prog_fd);
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

    // read first timestamp
    clock_gettime(CLOCK_MONOTONIC, &start_running_time);

    fprintf(stdout, "[%s]: Running... \nPress Ctrl+C to stop\n", INFO);
    if (selected_metrics_cnt > 0 && array_map_fd > 0)
    {
        // TODO - Using file as output instead stdout may not work properly
        // I either fixed the problem or I forgot what it was :)
        if (output_filename[0] != '\0')
        {
            output_file = fopen(output_filename, "w");
            if (output_file == NULL)
            {
                fprintf(stderr, "[%s]: during opening output file: %s\n", ERR, output_filename);
                init_exit(0);
                return 1;
            }
        }
        // start perf before polling
        poll_stats(array_map_fd, 1000);
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
