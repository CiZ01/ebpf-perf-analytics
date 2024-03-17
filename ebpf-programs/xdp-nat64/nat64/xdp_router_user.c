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

#include "readconf.h"

#define IP_BOUNDARY_START 0xC0A80901 // 192.168.9.1
#define IP_BOUNDARY_END 0xC0A809FE   // 192.168.9.254

#define XDP_PROGRAM_PATH "xdp_router_kern.o"

#define CONF_PATH "router.conf"

struct cfg configs[2];
int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int verbose;
int perf_fd;

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int start_perf()
{
    struct perf_event_attr attr = {};

    // TODO - map perf event
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.size = sizeof(struct perf_event_attr);
    attr.exclude_user = 1;

    perf_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (perf_fd < 0)
    {
        fprintf(stderr, "[ERR]: perf_event_open failed\n");
        return -1;
    }

    // enable perf event
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0))
    {
        fprintf(stderr, "[ERR]: ioctl failed\n");
        return -1;
    }
    return 0;
}

void usage(void)
{
    printf("Usage: xdp_router_user [-m mode] [-v] [-h]\n");
    printf("  -m mode: xdp mode (skb, native)\n");
    printf("  -v: verbose, print perfomance stat\n");
    printf("  -h: help\n");
}

static void int_exit(int sig)
{
    __u32 curr_prog_id = 0;

    fprintf(stdout, "[INFO]: Detaching program...\n");

    for (int i_cfg = 0; i_cfg < 2; i_cfg++)
    {
        for (int i_if = 0; i_if < configs[i_cfg].num_interfaces; i_if++)
        {
            int ifindex = if_nametoindex(configs[i_cfg].interfaces[i_if]);
            if (ifindex == 0)
            {
                printf("[ERR]: getting ifindex during detaching\n");
                exit(1);
            }

            // get in current prog id the xdp program attached to the interface
            if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id))
            {
                printf("[ERR]: bpf_xdp_query_id failed\n");
                exit(1);
            }

            // check if the current prog id is the same as the one we are trying to remove
            if (bpf_xdp_detach(ifindex, xdp_flags, NULL))
            {
                printf("[ERR]: bpf_xdp_detach failed\n");
                exit(1);
            }
        }
    }
    close(perf_fd);
    fprintf(stdout, "[INFO]: Done \n");
    exit(0);
}

static int attach_prog(struct cfg *cfg, struct bpf_program *prog)
{
    int err;
    int ifindex;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int prog_fd;

    // get prog fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[ERR]: retrieving prog fd\n");
        return 1;
    }

    for (int i = 0; i < cfg->num_interfaces; i++)
    {
        ifindex = if_nametoindex(cfg->interfaces[i]);
        if (ifindex == 0)
        {
            fprintf(stderr, "[ERR]: getting ifindex - ifname: %s \n", cfg->interfaces[i]);
            return 1;
        }

        // attach prog
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0)
        {
            fprintf(stderr, "[ERR]: attaching program - ifname: %s \n", cfg->interfaces[i]);
            return 1;
        }
    }

    // get prog id
    err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
    if (err)
    {
        printf("[ERR]: can't get prog info - %s\n", strerror(errno));
        return 1;
    }
    cfg->prog_id = info.id;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    __u64 *sample = data;

    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%-8s %llu \n", ts, *sample);
    return 0;
}

static void poll_stats(unsigned int map_fd, unsigned int kill_after_s)
{
    int err;
    struct ring_buffer *rb;

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    err = libbpf_get_error(rb);
    if (err)
    {
        rb = NULL;
        fprintf(stderr, "failed to open ring buffer: %d\n", err);
        int_exit(0);
    }

    while (ring_buffer__poll(rb, 1000) >= 0)
    {
        sleep(1);
    }
}

int main(int arg, char **argv)
{
    int map_ip4_cnt_fd, opt;
    int rb_map_fd = -1;
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err;
    int num_configs;

    err = readconfig(CONF_PATH, configs, &num_configs);
    if (err)
    {
        fprintf(stderr, "[ERR]: reading configuration file\n");
        return 1;
    }

    // retrieve opt
    while ((opt = getopt(arg, argv, ":m:vh")) != -1)
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
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, "Usage: %s\n", argv[0]);
            return 1;
        }
    }

    // get obj
    obj = bpf_object__open_file(XDP_PROGRAM_PATH, NULL);
    if (libbpf_get_error(obj))
        return 1;

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

    fprintf(stdout, "[INFO]: Loaded object...\n");

    // retrieve prog later

    // set ipcnt map
    map_ip4_cnt_fd = bpf_object__find_map_fd_by_name(obj, "ip4_cnt");
    if (map_ip4_cnt_fd < 0)
    {
        fprintf(stderr, "[ERR]: finding map\n");
        return 1;
    }

    int key = 0;
    int value = IP_BOUNDARY_START;
    err = bpf_map_update_elem(map_ip4_cnt_fd, &key, &value, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[ERR]: updating map\n");
        return 1;
    }

    // get ring buffer if verbose
    if (verbose)
    {
        rb_map_fd = bpf_object__find_map_fd_by_name(obj, "ring_output");
        if (rb_map_fd < 0)
        {
            fprintf(stderr, "[ERR]: finding map\n");
            return 1;
        }
    }

    // set trap for ctrl+c
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    int i_prog = 0;
    bpf_object__for_each_program(prog, obj)
    {
        err = attach_prog(&configs[i_prog], prog);
        if (err)
        {
            int_exit(0);
            return 1;
        }
        i_prog++;
    }

    fprintf(stdout, "[INFO]: Running... \n Press Ctrl+C to stop\n");
    if (verbose && rb_map_fd > 0)
    {
        // start perf before polling
        err = start_perf(); // perf fd will be freed during int_exit
        if (err)
        {
            int_exit(0);
            return 1;
        }
        poll_stats(rb_map_fd, 0);
    }
    else
    {
        pause();
    }

    return 0;
}