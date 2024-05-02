#ifndef __USER_MYCHARDEV_H_
#define __USER_MYCHARDEV_H_

#include <stdio.h>
#include <asm/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mykperf_module.h"
#include "mykperf_ioctl.h"

#define PINNED_PROG_PATH "/sys/fs/bpf/"
#define DATA_MAP ".bss"

struct message
{
    __u64 event;
    __u64 reg;
    int cpu;
};

struct bss
{
    __u64 __sample_rate;
    __u64 run_cnt;
    char sections[15][8];
};

/*
 * Find the data map in the bpf map list and return the file descriptor.
 * @return the file descriptor of the data map, error otherwise
 */
int find_data_map()
{
    int fd = 0;
    unsigned int id = 0;
    int err;

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    while (1)
    {
        err = bpf_map_get_next_id(id, &id);
        if (err)
        {
            return err;
        }

        fd = bpf_map_get_fd_by_id(id);
        if (fd < 0)
        {
            return err;
        }

        err = bpf_map_get_info_by_fd(fd, &info, &len);
        if (err)
        {
            return err;
        }

        if (strcmp(DATA_MAP, info.name + strlen(info.name) - strlen(DATA_MAP)) == 0)
        {
            break;
        }
        close(fd);
    }
    fprintf(stdout, "Map name: %s\n", info.name);
    return fd;
}

/*
 * Set the shared variable beetwen usersapce and xdp to `out_reg` value, so xdp knows where read
 * the counter value.
 * @param out_reg: the value to set
 * @param funcname: the name of the xdp function
 * @return 0 if the operation is successful, -1 otherwise
 */
/* int set_counter(__u64 out_reg)
{
    __u32 zero = 0;
    int fd = -1;
    int err;

    fd = find_data_map();
    if (fd < 0)
    {
        fprintf(stderr, "Failed to find data map\n");
        return -1;
    }

    struct bss data = {0};

    err = bpf_map_lookup_elem(fd, &zero, &data);
    if (err)
    {
        fprintf(stderr, "Failed to update map element\n");
        return -1;
    }

    data.reg_counter = out_reg;

    err = bpf_map_update_elem(fd, &zero, &data, 0);
    if (err)
    {
        fprintf(stderr, "Failed to update map element\n");
        return -1;
    }

    close(fd);
    return 0;
} */

/*
 * Enable the passed event and write the result in the out_reg.
 * `out_reg` is the register where measurments are stored
 * @param event: the event to enable
 * @param out_reg: the register where to write the result
 * @return 0 if the operation is successful, -1 otherwise
 */
int enable_event(__u64 event, __u64 *out_reg, int cpu)
{
    int fd;
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open the device");
        return -1;
    }

    fprintf(stdout, "Enabling event %llu\n", event);

    struct message msg = {
        .event = event,
        .cpu = cpu,
    };

    if (ioctl(fd, ENABLE_EVENT, &msg) < 0)
    {
        perror("Failed to perform IOCTL GET");
        close(fd);
        return -1;
    }

    *out_reg = msg.reg;

    /*     if (set_counter(*out_reg) < 0)
        {
            perror("Failed to set counter in xdp program");
            close(fd);
            return -1;
        } */

    close(fd);
    return 0;
}

/*
 * Disable the passed event.
 * @param event: the event to disable
 * @return 0 if the operation is successful, -1 otherwise
 */
int disable_event(__u64 reg, __u64 event, int cpu)
{
    struct message msg = {
        .event = event,
        .reg = reg,
        .cpu = cpu,
    };

    int fd;
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open the device.");
        return -1;
    }

    if (ioctl(fd, DISABLE_EVENT, &msg) < 0)
    {
        perror("Failed to perform IOCTL GET.");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

#endif // __USER_MYCHARDEV_H_