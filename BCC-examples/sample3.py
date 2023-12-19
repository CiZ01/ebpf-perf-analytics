from bcc import BPF, PerfType, PerfSWConfig

# Definisci il programma XDP
code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <bcc/proto.h>

BPF_HASH(cache_hits, u64, u64);

int xdp_prog(struct xdp_md *ctx) {
    // Porzione di codice da monitorare per cache miss

    // Se c'è un cache miss, incrementa il contatore
    u64 key = 0;
    u64 *value = cache_hits.lookup(&key);
    if (!value) {
        u64 miss = 1;
        cache_hits.update(&key, &miss);
    }

    return XDP_PASS;
}
"""

# Carica il programma XDP
b = BPF(text=code)

fn = b.load_func("xdp_prog", BPF.XDP)

b.attach_xdp("enp0s31f6", fn, 0)

# Inizializza il modulo di cache
cache_hits = b.get_table("cache_hits")

# Configura l'uscita di perf
perf = b.get_syscall_fnname("perf_event_output")
b.attach_perf_event(
    ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK,
    fn_name=perf,
)

# Esegui il loop per leggere i risultati dall'uscita di perf
while True:
    try:
        key, value = cache_hits.items()[0]
        print(f"Cache misses: {value.value}")
        cache_hits.clear()
        b.kprobe_poll()
    except KeyboardInterrupt:
        break
