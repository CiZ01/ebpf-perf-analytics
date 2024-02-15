#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <errno.h>

#ifdef TRACE
#include "xdp_pass_kern_trace_skel.h"
#else
#include "xdp_pass_kern_skel.h"
#endif

#define SZ_32K 0x00008000

struct xdp_pass_kern *skel;
struct bpf_link *link;

// from bpftool implementation
static int get_run_data(const char *fname, void **data_ptr, unsigned int *size)
{
    size_t block_size = 256;
    size_t buf_size = block_size;
    size_t nb_read = 0;
    void *tmp;
    FILE *f;

    if (!fname)
    {
        *data_ptr = NULL;
        *size = 0;
        return 0;
    }

    if (!strcmp(fname, "-"))
        f = stdin;
    else
        f = fopen(fname, "r");
    if (!f)
    {
        fprintf(stderr, "failed to open %s: %s", fname, strerror(errno));
        return -1;
    }

    *data_ptr = malloc(block_size);
    if (!*data_ptr)
    {
        fprintf(stderr, "failed to allocate memory for data_in/ctx_in: %s", strerror(errno));
        goto err_fclose;
    }

    while ((nb_read += fread(*data_ptr + nb_read, 1, block_size, f)))
    {
        if (feof(f))
            break;
        if (ferror(f))
        {
            fprintf(stderr, "failed to read data_in/ctx_in from %s: %s", fname, strerror(errno));
            goto err_free;
        }
        if (nb_read > buf_size - block_size)
        {
            if (buf_size == UINT32_MAX)
            {
                fprintf(stderr, "data_in/ctx_in is too long (max: %d)", UINT32_MAX);
                goto err_free;
            }
            /* No space for fread()-ing next chunk; realloc() */
            buf_size *= 2;
            tmp = realloc(*data_ptr, buf_size);
            if (!tmp)
            {
                fprintf(stderr, "failed to reallocate data_in/ctx_in: %s", strerror(errno));
                goto err_free;
            }
            *data_ptr = tmp;
        }
    }
    if (f != stdin)
        fclose(f);

    *size = nb_read;
    return 0;

err_free:
    free(*data_ptr);
    *data_ptr = NULL;
err_fclose:
    if (f != stdin)
        fclose(f);
    return -1;
}

int main(int argc, char **argv)
{

    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <ifname> <data_in> <repeats> [-v, -l] \n", argv[0]);
        return 1;
    }

    int verbose = 0;
    int do_load = 0;
    if (argc == 5)
    {
        if (strcmp(argv[4], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[4], "-l") == 0)
        {
            do_load = 1;
        }
    }

    if (argc == 6)
    {
        if (strcmp(argv[5], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[5], "-l") == 0)
        {
            do_load = 1;
        }
    }

    char *ifname = argv[1];
    char *f_data_in = argv[2];
    int repeats = atoi(argv[3]);

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Failed to get ifindex of %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    int err;

#ifdef TRACE
    struct xdp_pass_kern_trace *skel = xdp_pass_kern_trace__open();
#else
    struct xdp_pass_kern *skel = xdp_pass_kern__open();
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
        return 1;
    }

    if (do_load)
    {
#ifdef TRACE
        err = xdp_pass_kern_trace__load(skel);
#else
        err = xdp_pass_kern__load(skel);
#endif
        if (err)
        {
            fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
            return 1;
        }
    }

    int fd = bpf_program__fd(skel->progs.xdp_pass_func);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to get file descriptor for BPF program: %s\n", strerror(errno));
        return 1;
    }

    void *data_in = NULL;
    unsigned int data_size_in = 0;

    if (get_run_data(f_data_in, &data_in, &data_size_in))
    {
        return 1;
    }

    struct bpf_test_run_opts opts = {
        .data_in = data_in,
        .data_size_in = data_size_in,
        .data_out = NULL,
        .data_size_out = SZ_32K, // 32KB
        .retval = 0,
        .duration = 0,
        .repeat = repeats,
        .flags = 0,
    };

    opts.sz = sizeof(opts);

    err = bpf_prog_test_run_opts(fd, &opts);
    if (err)
    {
        fprintf(stderr, "Failed to run BPF program: %s\n", strerror(errno));
        return 1;
    }

    if (verbose)
    {
        fprintf(stdout, "Successfully ran BPF program\n");
        fprintf(stdout, "Return value: %u, duration%s: %uns\n", opts.retval, repeats > 1 ? " (average)" : "",
                opts.duration);
    }
    else
    {
        fprintf(stdout, "%u\n", opts.duration);
        fflush(stdout);
    }

    free(data_in);

#ifdef TRACE
    xdp_pass_kern_trace__detach(skel);
    xdp_pass_kern_trace__destroy(skel);
#else
    xdp_pass_kern__detach(skel);
    xdp_pass_kern__destroy(skel);
#endif
    return 0;
}