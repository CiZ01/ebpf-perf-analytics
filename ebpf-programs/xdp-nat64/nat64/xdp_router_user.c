#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

struct config
{
    char *filename;
    char *section;
    char *interface;
    char *mode;
};

static int parsearg(int argc, char **argv, struct config *cfg)
{
    int c;
    while ((c = getopt(argc, argv, "f:s:i:m:")) != -1)
    {
        switch (c)
        {
        case 'f':
            cfg->filename = optarg;
            break;
        case 's':
            cfg->section = optarg;
            break;
        case 'i':
            cfg->interface = optarg;
            break;
        case 'm':
            cfg->mode = optarg;
            break;
        default:
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Usage: %s -f <filename> -s <section> -i <interface> -m <mode>\n", argv[0]);
        return 1;
    }

    // Allocate memory for struct config
    struct config cfg_data;
    struct config *cfg = &cfg_data;

    // Initialize cfg fields to NULL
    cfg->filename = NULL;
    cfg->section = NULL;
    cfg->interface = NULL;
    cfg->mode = NULL;

    if (parsearg(argc, argv, cfg))
    {
        printf("Invalid argument\n");
        return 1;
    }

    int prog_fd, map_fd, ret, err;
    struct bpf_object *bpf_obj;

    int ifindex = if_nametoindex(cfg->interface);
    if (!ifindex)
    {
        printf("get ifindex from interface name failed\n");
        return 1;
    }

    // Check if filename and section are provided
    if (!cfg->filename || !cfg->section)
    {
        printf("Both filename and section must be provided\n");
        return 1;
    }

    // Open the BPF object
    struct xdp_program *prog = xdp_program__open_file(cfg->filename, cfg->section, NULL);

    if (!prog)
    {
        printf("Failed to open BPF program\n");
        return 1;
    }

    // Attach the BPF program
    err = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);

    if (!err)
        xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);

    // Close the BPF program
    xdp_program__close(prog);

    return 0;
}
