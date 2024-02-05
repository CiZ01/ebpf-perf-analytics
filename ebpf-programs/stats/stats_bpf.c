#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>

/*
 * retrieve the stats from output_map and print them
 *
 * */

struct perf_trace_event
{
    __u64 timestamp;
    __u32 processing_time;
    __u8 type;
};

int main(int argc, char **argv)
{

    if (argc < 2)
    {
        printf("Usage: %s <bpf_program.o>\n", argv[0]);
        return 1;
    }
    char *filename = argv[1];
    struct bpf_object *obj;
    struct bpf_map *map;
    int fd;

    // load the bpf object file
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Error opening file: %s\n", strerror(-libbpf_get_error(obj)));
        return 1;
    }

    // get the file descriptor of the output_map
    map = bpf_object__find_map_by_name(obj, "output_map");
    if (!map)
    {
        fprintf(stderr, "Error finding map: %s\n", strerror(-libbpf_get_error(obj)));
        return 1;
    }

    __u32 key = 0;
    struct perf_trace_event value = {0};

    bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0);

    printf("timestamp: %llu\n", value.timestamp);
    printf("processing_time: %u\n", value.processing_time);
    printf("type: %u\n", value.type);

    return 0;
}
