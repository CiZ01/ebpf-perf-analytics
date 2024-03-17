#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <signal.h>

#include "xdp_sum_kern_skel.h"

struct xdp_sum_kern *skel;

#define MAX_CNT 100

struct bpf_link *xdp_link;
int verbose = 0;
int run_cnt = 0;

void cleanup(int sig)
{
    xdp_sum_kern__detach(skel);
    xdp_sum_kern__destroy(skel);
    bpf_link__destroy(xdp_link);
    printf("Cleaned up and detached BPF program from interface\n");
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname> [ -v | -c <count> ]\n", argv[0]);
        return 1;
    }

    char *ifname = "";
    ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Failed to get ifindex of %s: %s\n", ifname, strerror(errno));
        return 1;
    }
    int err;

    skel = xdp_sum_kern__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    err = setrlimit(RLIMIT_MEMLOCK, &r);
    if (err)
    {
        fprintf(stderr, "Failed to set rlimit: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    err = xdp_sum_kern__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    xdp_link = bpf_program__attach_xdp(skel->progs.xdp_sum_func, ifindex);
    if (libbpf_get_error(xdp_link))
    {
        fprintf(stderr, "Failed to attach BPF program to interface: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    if (verbose)
        printf("Successfully attached BPF program to interface %s\n", ifname);

    signal(SIGINT, cleanup);
    printf("Running...\n");
    while (1)
    {
        sleep(1);
    }

    return err != 0;
}