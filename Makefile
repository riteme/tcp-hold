LIBNL3_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-route-3.0 libnl-cli-3.0)
LIBBPF_FLAGS = $(shell pkg-config --cflags --libs libbpf)
TARGETS = vmlinux.h main lockstep test.o test.skel.h test

all: $(TARGETS)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

main: main.cpp
	g++ -std=c++11 -lpthread -O2 main.cpp -o main

lockstep: lockstep.cpp
	g++ $(LIBNL3_FLAGS) $< -o $@

test.o: test.bpf.c vmlinux.h tc_act.h
	clang --target=bpf -O2 -g -Wall -c -o $@ $<

test.skel.h: test.o
	bpftool gen skeleton $< > $@

test: test.cpp test.skel.h
	g++ $(LIBBPF_FLAGS) $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGETS)
