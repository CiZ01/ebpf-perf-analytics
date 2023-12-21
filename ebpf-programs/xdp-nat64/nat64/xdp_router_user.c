/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
                             " - Allows selecting BPF program --progname name to XDP-attach to --dev\n";
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <xdp/libxdp.h>

#include <net/if.h>

#include "common/readconf.h"
#include "common/common_params.h"

#define FILENAME "xdp_router_kern.o"
#define PIN_DIR "/sys/fs/bpf/xdp/router64"
#define PATH_MAX 256

#define IP_BOUNDARY_START 0xC0A80901 // 192.168.9.1
#define IP_BOUNDARY_END 0xC0A809FE   // 192.168.9.254

#define CONF_PATH "router.conf"

static const struct option_wrapper long_options[] = {

    {{"load", no_argument, NULL, 'l'}, "load router", false},

    {{"unload", no_argument, NULL, 'u'}, "detach all router from interfaces", false},

    {{0, 0, NULL, 0}, NULL, false}};

Section sections[2];
int num_sections;
struct xdp_program *prog_6to4;
struct xdp_program *prog_4to6;
char *errmsg[256];

static void detach_programs(int signo)
{
    int curr_ifindex, err;

    // unload 6 to 4
    Section sec = sections[0];
    for (int i = 0; i < sec.num_interfaces; i++)
    {
        curr_ifindex = if_nametoindex(sec.interfaces[i]);
        if (curr_ifindex == 0)
        {
            fprintf(stderr, "ERROR: Failed to get ifindex of interface %s: %s\n", sec.interfaces[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        err = xdp_program__detach(prog_6to4, curr_ifindex, XDP_MODE_SKB, 0);
        if (err)
        {
            fprintf(stderr, "ERROR: Failed to detach program: %s\n", strerror(-err));
            exit(EXIT_FAILURE);
        }

        printf("[INFO]: Detached program %s from interface %s\n", sec.section_name, sec.interfaces[i]);
    }

    xdp_program__close(prog_6to4);

    // unload 4 to 6
    sec = sections[1];
    for (int i = 0; i < sec.num_interfaces; i++)
    {
        curr_ifindex = if_nametoindex(sec.interfaces[i]);
        if (curr_ifindex == 0)
        {
            fprintf(stderr, "ERROR: Failed to get ifindex of interface %s: %s\n", sec.interfaces[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        err = xdp_program__detach(prog_4to6, curr_ifindex, XDP_MODE_SKB, 0);
        if (err)
        {
            fprintf(stderr, "ERROR: Failed to detach program: %s\n", strerror(-err));
            exit(EXIT_FAILURE);
        }

        printf("[INFO]: Detached program %s from interface %s\n", sec.section_name, sec.interfaces[i]);
    }

    xdp_program__close(prog_4to6);

    exit(EXIT_SUCCESS);
}

static void attach_programs()
{
    int curr_ifindex, err;

    // load 6 to 4
    Section sec = sections[0];
    for (int i = 0; i < sec.num_interfaces; i++)
    {
        curr_ifindex = if_nametoindex(sec.interfaces[i]);
        if (curr_ifindex == 0)
        {
            fprintf(stderr, "ERROR: Failed to get ifindex of interface %s: %s\n", sec.interfaces[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        err = xdp_program__attach(prog_6to4, curr_ifindex, XDP_MODE_SKB, 0);
        if (err)
        {
            detach_programs(0);
            fprintf(stderr, "ERROR: Failed to attach program: %s\n", strerror(-err));
            exit(EXIT_FAILURE);
        }

        printf("[INFO]: Attached program %s to interface %s\n", sec.section_name, sec.interfaces[i]);
    }

    // load 4 to 6
    sec = sections[1];
    for (int i = 0; i < sec.num_interfaces; i++)
    {
        curr_ifindex = if_nametoindex(sec.interfaces[i]);
        if (curr_ifindex == 0)
        {
            fprintf(stderr, "ERROR: Failed to get ifindex of interface %s: %s\n", sec.interfaces[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        err = xdp_program__attach(prog_4to6, curr_ifindex, XDP_MODE_SKB, 0);
        if (err)
        {
            detach_programs(0);
            fprintf(stderr, "ERROR: Failed to attach program: %s\n", strerror(-err));
            exit(EXIT_FAILURE);
        }

        printf("[INFO]: Attached program %s to interface %s\n", sec.section_name, sec.interfaces[i]);
    }
}

int main(int argc, char **argv)
{
    // parse command line args
    struct config cfg;
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    // read config file
    int err;
    err = readconf(CONF_PATH, sections, &num_sections);
    if (err < 0)
    {
        fprintf(stderr, "ERROR: Failed to read config file: %s\n", strerror(-err));
        exit(EXIT_FAILURE);
    }

    // load programs
    prog_6to4 = xdp_program__open_file(FILENAME, sections[0].section_name, NULL);
    if (!prog_6to4)
    {
        fprintf(stderr, "ERROR: Failed to open program file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    prog_4to6 = xdp_program__open_file(FILENAME, sections[1].section_name, NULL);
    if (!prog_4to6)
    {
        fprintf(stderr, "ERROR: Failed to open program file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // unload program
    if (cfg.unload)
    {
        detach_programs(0);
    }
    attach_programs();

    // init ipv4_cnt map
    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog_6to4), "ip4_cnt");
    if (map_fd < 0)
    {
        fprintf(stderr, "ERROR: Failed to get map: %lld\n", libxdp_get_error(errno));
        exit(EXIT_FAILURE);
    }

    int key = 0;
    int value = IP_BOUNDARY_START;
    err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (err < 0)
    {
        fprintf(stderr, "ERROR: Failed to update map: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fflush(stdout);
    printf("[INFO]: Running...");

    signal(SIGINT, detach_programs);
    signal(SIGTERM, detach_programs);

    while (1)
    {
        sleep(1);
    }

    return 0;
}