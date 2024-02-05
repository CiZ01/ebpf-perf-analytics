#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <signal.h>

#include "xdp_cid_skel.h"

#define MAX_CNT 100

struct perf_trace_event
{
    __u64 timestamp;
    __u32 processing_time_ns;
    __u32 bytes;
};

struct perf_trace_event_accumulate
{
    __u32 processing_time_ns;
    __u32 bytes;
    __u32 run_cnt;
};

struct xdp_cid_kern *skel;
struct perf_buffer *pb;
struct bpf_link *link;
struct perf_trace_event_accumulate *acc = &((struct perf_trace_event_accumulate){0});

void cleanup(int sig)
{
    if (acc->run_cnt > 0)
    {
        printf("Accumulated processing time: %u ns\n", acc->processing_time_ns);
        printf("Accumulated bytes: %u\n", acc->bytes);
        printf("Accumulated run count: %u\n", acc->run_cnt);

        printf("Average processing time: %u ns\n", acc->processing_time_ns / acc->run_cnt);
        printf("Average bytes: %u\n", acc->bytes / acc->run_cnt);
    }
    perf_buffer__free(pb);
    xdp_cid_kern__destroy(skel);
    xdp_cid_kern__detach(skel);
    bpf_link__destroy(link);
    printf("Cleaned up and detached BPF program from interface\n");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct perf_trace_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%-8s %lld %14u ns %14u bytes\n", ts, e->timestamp, e->processing_time_ns, e->bytes);
}

void handle_event_accumulate(void *ctx, int cpu, void *data, __u32 data_sz)
{

    const struct perf_trace_event *e = data;
    acc->processing_time_ns += e->processing_time_ns;
    acc->bytes += e->bytes;
    acc->run_cnt++;
    printf("Average processing time: %u ns\n", acc->processing_time_ns / acc->run_cnt);
    printf("Average bytes: %u\n\n", acc->bytes / acc->run_cnt);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Failed to get ifindex of %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    int err;

    skel = xdp_cid_kern__open();
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

    err = xdp_cid_kern__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    link = bpf_program__attach_xdp(skel->progs.xdp_cid_func, ifindex);
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "Failed to attach BPF program to interface: %s\n", strerror(errno));
        cleanup(0);
        return 1;
    }

    printf("Successfully attached BPF program to interface %s\n", ifname);

    acc->bytes = 0;
    acc->processing_time_ns = 0;
    acc->run_cnt = 0;

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output_map), 64, handle_event_accumulate, handle_lost_events, NULL,
                          NULL);
    err = libbpf_get_error(pb);
    if (err)
    {
        pb = NULL;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        cleanup(0);
        return 1;
    }

    printf("TIMESTAMP           PKT SIZE            PROCESSING TIME\n");
    while ((err = perf_buffer__poll(pb, 100)) >= 0)
        ;
    printf("Error polling perf buffer: %d\n", err);

    signal(SIGINT, cleanup);
    signal(SIGKILL, cleanup);
    signal(SIGTERM, cleanup);

    return err != 0;
}