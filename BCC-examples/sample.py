from bcc import BPF, Perf, PerfHWConfig
from time import sleep

bpf_text = """
#include <linux/perf_event.h>
struct key_t {
    int cpu;
    int pid;
    char name[100];
};

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int on_sample_hit(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    u64 addr = 0;
    struct bpf_perf_event_data_kern *kctx;
    struct perf_sample_data *data;

    kctx = (struct bpf_perf_event_data_kern *)ctx;

    bpf_probe_read(&data, sizeof(struct perf_sample_data*), &(kctx->data));
    if (data)
        bpf_probe_read(&addr, sizeof(u64), &(data->addr));

    bpf_trace_printk("Hit a sample with pid: %ld, comm: %s, addr: 0x%llx\\n", key.pid, key.name, addr);
    return 0;
}

"""

b = BPF(text=bpf_text)
try:
    event_attr = Perf.perf_event_attr()
    event_attr.type = Perf.PERF_TYPE_HARDWARE
    event_attr.config = PerfHWConfig.CACHE_MISSES
    event_attr.sample_period = 1000000
    event_attr.sample_type = 0x8  # PERF_SAMPLE_ADDR
    event_attr.exclude_kernel = 1
    b.attach_perf_event_raw(attr=event_attr, fn_name="on_sample_hit", pid=1805, cpu=-1)
except Exception:
    print("Failed to attach to a raw event. Please check the event attr used")
    exit()

print(
    "Running for 4 seconds or hit Ctrl-C to end. Check trace file for samples information written by bpf_trace_printk."
)
sleep(5)
