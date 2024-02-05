#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: %s <filename> <section>\n", argv[0]);
        return 1;
    }

    char *section = "xdp";
    if (argc == 3)
    {
        section = argv[2];
    }

    char *filename = argv[1];

    struct xdp_program *prog = xdp_program__open_file(filename, section, NULL);
    if (libxdp_get_error(prog))
    {
        fprintf(stderr, "ERROR: Failed to open program\n");
        return 1;
    }

    int fd = xdp_program__fd(prog);
    if (fd < 0)
    {
        fprintf(stderr, "ERROR: Failed to get fd: %s\n", strerror(errno));
        return 1;
    }

    struct bpf_prog_info info = {};
    unsigned int info_len = sizeof(info);
    int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "ERROR: Failed to get info: %s\n", strerror(errno));
        return 1;
    }

    printf("[INFO]: Collecting stats for program %s\n", section);

    while (1)
    {
        printf("[STATS]: %llu\n", info.run_cnt);
        printf("[STATS]: %llu\n", info.run_time_ns);
        printf("[STATS]: %llu\n", info.func_info);
        sleep(1);
    }

    return 0;
}