TARGETS := cms

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	@echo "algn value: $(ALGN)"
	clang -g -O2 --target=bpf -I ../../kperf_ -c $@.bpf.c -o $@.bpf.o -DALGN=$(ALGN)
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
