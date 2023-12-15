from bcc import BPF
from time import sleep
#count cpu cycle

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

BPF_HASH(start, u32);
BPF_HASH(count, u32);

int do_count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int do_count_ret(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;
    u64 ts = bpf_ktime_get_ns();

    tsp = start.lookup(&pid);
    if (tsp != 0) {
        delta = ts - *tsp;
        count.increment(delta);
        start.delete(&pid);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_perf_event

print("Tracing... Ctrl-C to end.")

try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

print()
print("%10s %s" % ("COUNT", "TIME (ns)"))
count = b.get_table("count")

for k, v in sorted(count.items(), key=lambda count: count[1].value):
    print("%10d %d" % (v.value, k.value))

# Path: tracing-tools/my_tests/second.py
