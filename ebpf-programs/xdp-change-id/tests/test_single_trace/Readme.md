## Test 1
> *userspace*: xdp_cid_user_trace.o 
> *kernel space*: xdp_cid_kern_trace.o
> *confrontato con*: bpf_stats

a differenza di /test_trace/ ogni riga dei csv è un pacchetto **userspace** e un pacchetto **bpf_stats**
test001-test004 su 1000 run con invio di 1 pacchetto

## Test 2
> *userspace*: xdp_cid_user.o 
> *kernel space*: xdp_cid_kern.o
> *confrontato con*: bpf_stats

questi test servono insieme a (Test 1)[#Test-1] per capire l'hoverhead aggiunto da TRACE.
test005-test008 su 1000 run con invio di 1 pacchetto

## Test 3
> *userspace*: xdp_cid_user_trace.o 
> *kernel space*: xdp_cid_kern_trace.o (modificato, funziona solo lo start trace)
> *confrontato con*: bpf_stats

questi test servono per capire quanto costa START_TRACE
test009-
