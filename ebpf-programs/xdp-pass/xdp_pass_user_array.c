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

static void cleanup(int x)
{
    xdp_pass_kern_trace__detach(skel);
    xdp_pass_kern_trace__destroy(skel);

    free(keys);
    free(values);
    exit(0);
}

static int array_polling(int map_fd, int pos_fd, int timeout_ns)
{
    const __u32 one = 1;
    const __u32 zero = 0;

    int err;
    err = bpf_map_lookup_elem(pos_fd, &one, &cons_key);
    if (err)
    {
        fprintf(stderr, "Failed to lookup cons_key: %d\n", err);
        return 1;
    }

    err = bpf_map_lookup_elem(pos_fd, &zero, &prod_key);
    if (err)
    {
        fprintf(stderr, "Failed to lookup prod_key: %d\n", err);
        return 1;
    }

    // lookup batch
    bool init = false;
    int i, ret;

    for (;;)
    {
        bool exit = false;

       /*  if (abs(cons_key - (prod_key - 1)) < 32)
        {
            continue;
        } */

        ret = bpf_map_lookup_batch(map_fd, init ? &batch : NULL, &batch, keys, values, &count, NULL);
        if (ret < 0 && errno != ENOENT)
            break;
        if (errno == ENOENT)
            exit = true;

        init = true;

        for (i = 0; i < count; i++)
        {
            struct record *arr;

            arr = &values[i];
            fprintf(stdout, "value: %llu\n", arr->value);
            cons_key++;
        }
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

    int ifindex = if_nametoindex(ifname);
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

    keys = calloc(count, sizeof(__u64));
    if (!keys)
    {
        cleanup(0);
        return -ENOMEM;
    }
    values = calloc(count, sizeof(struct record));
    if (!values)
    {
        cleanup(0);
        return -ENOMEM;
    }

    array_polling(bpf_map__fd(skel->maps.percpu_output), bpf_map__fd(skel->maps.pos), 1000);

    cleanup(0);
    return 0;
}
