#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

static __u64 mykperf_read_rdpmc(__u8 counter__k);
static __u64 mykperf_read_rdpmc__instructions(void);
static __u64 mykperf_read_rdpmc__cycles(void);
static __u64 mykperf_read_rdpmc(__u8 counter__k);

// -------------------- bpf prototypes ------------------------
__bpf_kfunc __u64 bpf_mykperf_read_rdpmc__instructions(void);
__bpf_kfunc __u64 bpf_mykperf_read_rdpmc__cycles(void);
__bpf_kfunc __u64 bpf_mykperf_read_rdpmc(__u8 counter__k);

static void my_test(void);

#define rdpmc(counter, low, high) __asm__ __volatile__("rdpmc" : "=a"(low), "=d"(high) : "c"(counter));

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Dummy Kernel Module");

static __u64 mykperf_read_rdpmc__cycles(void)
{
    return mykperf_read_rdpmc(0);
}

// I'm not sure if is the right counter for instructions
static __u64 mykperf_read_rdpmc__instructions(void)
{
    return mykperf_read_rdpmc(3);
}

static __u64 mykperf_read_rdpmc(__u8 counter__k)
{
    __u32 low, high;
    rdpmc(counter__k, low, high);
    asm volatile("lfence" ::: "memory");
    return ((__u64)high << 32) | low;
}

static void my_test()
{
    __u64 cycles = mykperf_read_rdpmc__cycles();
    __u64 instructions = mykperf_read_rdpmc__instructions();

    // consume cycles in kernel
    for (int i = 0; i < 1000000; i++)
    {
        __asm__ __volatile__("nop");
    }

    cycles = mykperf_read_rdpmc__cycles() - cycles;
    instructions = mykperf_read_rdpmc__instructions() - instructions;

    pr_info("Cycles: %llu\n", cycles);
    pr_info("Instructions: %llu\n", instructions);
}

__bpf_kfunc __u64 bpf_mykperf_read_rdpmc(__u8 counter__k)
{
    __u32 low, high;
    rdpmc(counter__k, low, high);
    asm volatile("lfence" ::: "memory");
    return ((__u64)high << 32) | low;
}

__bpf_kfunc __u64 bpf_mykperf_read_rdpmc__instructions(void)
{
    return mykperf_read_rdpmc__instructions();
}

__bpf_kfunc __u64 bpf_mykperf_read_rdpmc__cycles(void)
{
    return mykperf_read_rdpmc__cycles();
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, bpf_mykperf_read_rdpmc__cycles)
BTF_ID_FLAGS(func, bpf_mykperf_read_rdpmc__instructions)
BTF_ID_FLAGS(func, bpf_mykperf_read_rdpmc)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

static int __init mykperf_module_init(void)
{
    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_PERF_EVENT, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_task_kfunc_set);

    pr_info("kfunc registerd with success\n");
    return 0;
}

static void __exit mykperf_module_exit(void)
{
    printk(KERN_INFO "mykperf module removed\n");
}

module_init(mykperf_module_init);
module_exit(mykperf_module_exit);
