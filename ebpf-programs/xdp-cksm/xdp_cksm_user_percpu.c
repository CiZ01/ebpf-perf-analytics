#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <signal.h>

// be sure to use xdp_cksm_trace version for this userspace program
#ifdef TRACE
#include "xdp_cksm_kern_trace_skel.h"
struct xdp_cksm_kern_trace *skel;
struct perf_buffer *pb;
#else
#include "xdp_cksm_kern_skel.h"

struct xdp_cksm_kern *skel;
#endif

struct perf_event
{
    __u64 value;
};

struct bpf_link *xdp_link;
int verbose = 0;

void cleanup(int sig)
{
#ifdef TRACE
    perf_buffer__free(pb);
    xdp_cksm_kern_trace__detach(skel);
    xdp_cksm_kern_trace__destroy(skel);
#else
    xdp_cksm_kern__detach(skel);
    xdp_cksm_kern__destroy(skel);
#endif
    bpf_link__destroy(xdp_link);
    printf("Cleaned up and detached BPF program from interface\n");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct perf_event *e = data;
    if (verbose)
    {
        struct tm *tm;
        char ts[32];
        time_t t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-8s %llu \n", ts, e->value);
    }
    else
    {
        // just print the processing time
        fprintf(stdout, "%llu \n", e->value);
        fflush(stdout);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname> [ -v ]\n", argv[0]);
        return 1;
    }

    char *ifname = "";
    int opt;
    while ((opt = getopt(argc, argv, "v:i:")) != -1)
        switch (opt)
        {
        case 'v':
            verbose = 1;
            break;
        case 'i':
            ifname = optarg;
            break;
        case '?':
            fprintf(stderr, "Usage: %s <ifname> [ -v ]\n", argv[0]);
        }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Failed to get ifindex of %s: %s\n", ifname, strerror(errno));
        return 1;
    }
    int err;

#ifdef TRACE
    skel = xdp_cksm_kern_trace__open();
#else
    skel = xdp_cksm_kern__open();
#endif
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

#ifdef TRACE
    err = xdp_cksm_kern_trace__load(skel);
#else
    err = xdp_cksm_kern__load(skel);
#endif
    if (err)
    {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    xdp_link = bpf_program__attach_xdp(skel->progs.xdp_cksm_func, ifindex);
    if (libbpf_get_error(xdp_link))
    {
        fprintf(stderr, "Failed to attach BPF program to interface: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    if (verbose)
        printf("Successfully attached BPF program to interface %s\n", ifname);

    signal(SIGINT, cleanup);
#ifdef TRACE
	__u32 key = 0;
	__u64 values[libbpf_num_possible_cpus()];
	while (bpf_map_lookup_elem(bpf_map__fd(skel->maps.percpu_output), &key, values) == 0)
	{
		for (int i = 0; i < libbpf_num_possible_cpus(); i++)
		{
			if (values[i] != 0)
				printf("%llu\n",values[i]);
		}
	}
#else
    printf("Running...\n");
    while (1)
    {
        sleep(1);
    }
#endif

    return err != 0;
}
