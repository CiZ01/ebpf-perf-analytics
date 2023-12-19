from bcc import BPF, Perf, PerfHWConfig
from time import sleep

program = """
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>


struct key_t {
    int cpu;
    int pid;
    char name[100];
};


BPF_HASH(counts, struct key_t, u64, 10000);


static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}


int bpf_prog1(struct bpf_perf_event_data *ctx)
{
	struct key_t key;
    get_key(&key);

	u64 *val, one = 1;
	if (ctx->sample_period < 10000)
		/* ignore warmup */
		return 0;

	val = counts.lookup_or_init(&key, &one);
	if (val)
		(*val)++;
	else
        counts.increment(key);
	return 0;
}

"""

b = BPF(text=program)
counts = b["counts"]

try:
    event_attr = Perf.perf_event_attr()
    event_attr.type = Perf.PERF_TYPE_HARDWARE
    event_attr.config = PerfHWConfig.CACHE_MISSES
    event_attr.sample_period = 1000000
    event_attr.sample_type = 0x8  # PERF_SAMPLE_ADDR
    event_attr.exclude_kernel = 1
    b.attach_perf_event_raw(attr=event_attr, fn_name="bpf_prog1", pid=1805, cpu=-1)
except Exception:
    print("Failed to attach to a raw event. Please check the event attr used")
    exit()

while True:
    try:
        sleep(1)
    except KeyboardInterrupt:
        exit()

    for k, v in counts.items():
        print(k.name, v.value)
    counts.clear()

