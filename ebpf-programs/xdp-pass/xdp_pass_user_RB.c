clean_ #include<linux / bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "xdp_pass_kern_trace_rb_skel.h"

#include "mykperf_module.h"

    struct record *values;
struct xdp_pass_kern_trace_rb *skel;
int ifindex;

struct ring_buffer *rb;

static void cleanup(int x)
{
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, 0);
    xdp_pass_kern_trace_rb__destroy(skel);

    ring_buffer__free(rb);
    exit(0);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct record *rec = data;

    fprintf(stdout, "Name: %s\n", rec->name);
    fprintf(stdout, "Value: %llu", rec->value);
    fprintf(stdout, "Type: %u", rec->type_counter);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    char ifname[15];
    int err;

    strcpy(ifname, argv[1]);

    ifindex = if_nametoindex(ifname);
    if (!ifindex)
    {
        fprintf(stderr, "Failed to get ifindex\n");
        return 1;
    }

    skel = xdp_pass_kern_trace_rb__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = xdp_pass_kern_trace_rb__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_pass_func),
                         XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    printf("Successfully started BPF program\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb_map), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    int n;
    while (1)
    {
        n = ring_buffer__consume(rb);
        if (n < 0)
        {
            fprintf(stderr, "Failed to consume ring buffer\n");
        }
        sleep(2);
    }

    cleanup(0);
    return 0;
}
