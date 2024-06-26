#include <linux/bpf.h>
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
#include "xdp_pass_kern_trace_skel.h"

#include "mykperf_module.h"

struct record *values;
__u64 *keys;
__u32 batch, count = 32;
struct xdp_pass_kern_trace *skel;
__u32 *cons_key;
__u32 *prod_key;
int ifindex;

static void cleanup(int x)
{
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, 0);
    xdp_pass_kern_trace__destroy(skel);

    free(keys);
    free(values);
    exit(0);
}

static int array_polling(int map_fd, int timeout_ms)
{
    __u32 zero = 0;
    struct record *rec = {0};
    int err;
    for (;;)
    {
        err = bpf_map_lookup_elem(map_fd, &zero, rec);
        if (err)
        {
            fprintf(stderr, "Failed to lookup element: %d\n", err);
            continue;
        }

        if (strlen(rec->name))
        {
            continue;
        }
        fprintf(stdout, "Name: %s\n", rec->name);
        fprintf(stdout, "Value: %llu", rec->value);
        fprintf(stdout, "Type: %u", rec->type_counter);

        usleep(timeout_ms / 1000);
    }
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

    skel = xdp_pass_kern_trace__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = xdp_pass_kern_trace__load(skel);
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

    array_polling(bpf_map__fd(skel->maps.percpu_output), 5000);

    cleanup(0);
    return 0;
}
