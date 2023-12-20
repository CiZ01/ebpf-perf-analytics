/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
                             " - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const struct option_wrapper long_options[] = {

    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},

    {{"skb-mode", no_argument, NULL, 'S'}, "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'}, "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'}, "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, 'F'}, "Force install, replacing existing program on interface"},

    {{"unload", no_argument, NULL, 'U'}, "Unload XDP program instead of loading"},

    {{"reuse-maps", no_argument, NULL, 'M'}, "Reuse pinned maps"},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1}, "Load program from <file>", "<file>"},

    {{"progname", required_argument, NULL, 2}, "Load program from function <name> in the ELF file", "<name>"},

    {{0, 0, NULL, 0}, NULL, false}};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FILENAME "xdp_router_kern.o"
#define PIN_DIR "/sys/fs/bpf/router64"
#define SECTION1 "xdp_router_6to4"
#define SECTION2 "xdp_router_4to6"
#define MAP1 "nat_6to4"
#define MAP2 "nat_4to6"
#define MAP3 "ip4_cnt"

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg, char *map_name)
{
    char map_filename[PATH_MAX];
    int err, len;

    len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", cfg->pin_dir, cfg->ifname, map_name);
    if (len < 0)
    {
        fprintf(stderr, "ERR: creating map_name\n");
        return EXIT_FAIL_OPTION;
    }

    /* Existing/previous XDP prog might not have cleaned up */
    if (access(map_filename, F_OK) != -1)
    {
        if (verbose)
            printf(" - Unpinning (remove) prev maps in %s/\n", cfg->pin_dir);

        /* Basically calls unlink(3) on map_filename */
        err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
        if (err)
        {
            fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
            return EXIT_FAIL_BPF;
        }
    }
    if (verbose)
        printf(" - Pinning maps in %s/\n", cfg->pin_dir);

    /* This will pin all maps in our bpf_object */
    err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
    if (err)
    {
        fprintf(stderr, "ERR: Pinning maps in %s\n", cfg->pin_dir);
        return EXIT_FAIL_BPF;
    }

    return 0;
}

int main(int argc, char **argv)
{

    char **map_names = {MAP1, MAP2, MAP3};
    char **section_names = {SECTION1, SECTION2};
    char **interfaces_6to4 = {"veth-r-1", "veth-r-2", "veth-r-3"};
    int in_6to4_size = 3;
    char **interfaces_4to6 = {"veth-r-4", "veth-r-5"};
    int in_4to6_size = 2;

    int curr_ifindex;

    int i;
    for (i = 0; i < in_6to4_size; i++)
    {
        curr_ifindex = if_nametoindex(interfaces_6to4[i]);

        struct xdp_program *program;
        int err, len;

        struct config cfg = {
            .filename = FILENAME,
            .pin_dir = PIN_DIR,
            .attach_mode = XDP_MODE_SKB,
            .ifindex = curr_ifindex,
            .do_unload = false,
        };

        program = load_bpf_and_xdp_attach(&cfg);
        if (!program)
            return EXIT_FAIL_BPF;

        if (verbose)
        {
            printf("Success: Loaded BPF-object(%s) and used program(%s)\n", cfg.filename, cfg.progname);
            printf(" - XDP prog attached on device:%s(ifindex:%d)\n", cfg.ifname, cfg.ifindex);
        }
        return EXIT_OK;
    }