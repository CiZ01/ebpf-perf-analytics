#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <errno.h>
#include <signal.h>
#include <sys/vfs.h>

#include <sys/mount.h>

#include <net/if.h>

#include "../common/readconf.h"
#include "../common/common_params.h"

#define PIN_DIR "/sys/fs/bpf/"

/*
    loader <filename> <ifname> [section] [-P]
*/

int check_mount_or_create()
{
    struct statfs s;
    int err;
    if (statfs(PIN_DIR, &s) == -1)
    {
        // mount bpffs

        err = mount("bpffs", PIN_DIR, "bpf", 0, NULL);
        return err;
    }
    printf("[INFO]: bpffs already mounted\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Usage: %s <filename> <ifname>\n", argv[0]);
        return 1;
    }

    char *section = "xdp";
    int pin_mode = 0;
    if (argc == 4)
    {
        if (strcmp(argv[3], "-P") == 0)
        {
            pin_mode = 1;
        }
        else
        {
            section = argv[3];
        }
    }

    if (argc == 5)
    {
        if (strcmp(argv[4], "-P") == 0)
        {
            pin_mode = 1;
        }
        section = argv[3];
    }

    char *filename = argv[1];
    char *ifname = argv[2];

    int err = 0;
    err = mount("none", PIN_DIR, "bpf", 0, NULL);
    if (err)
    {
        fprintf(stderr, "ERROR: Failed to mount bpffs: %s\n", strerror(errno));
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "ERROR: Failed to get ifindex of interface %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    struct xdp_program *prog = xdp_program__open_file(filename, section, NULL);
    if (!prog)
    {
        fprintf(stderr, "ERROR: Failed to open program\n");
        return 1;
    }

    err = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (err)
    {
        fprintf(stderr, "ERROR: Failed to attach program\n");
        goto detach;
    }

    printf("FD: %d\n", xdp_program__fd(prog));

    if (pin_mode) // PENSO CHE IL SEGF SIA QUI
    {
        char path[256];
        snprintf(path, sizeof(path), "%s%s", PIN_DIR, section);
        err = xdp_program__pin(prog, path);
        if (err)
        {
            fprintf(stderr, "ERROR: Failed to pin program\n");
            goto detach;
        }
        printf("[INFO]: Pinned program %s to %s\n", section, path);
    }

    printf("[INFO]: Attached program %s to interface %s\n", section, ifname);

    printf("[INFO]: Press enter to detach program\n");

    char end;
    scanf("%c", &end);

detach:
    xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
    xdp_program__close(prog);

    printf("[INFO]: Detached program %s from interface %s\n", section, ifname);

    return err ? 1 : 0;
}
