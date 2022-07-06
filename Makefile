LIBNL3_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-route-3.0 libnl-cli-3.0)
LIBBPF_FLAGS = $(shell pkg-config --cflags --libs libbpf)

BPF_TARGETS = test demo
BPF_OBJECTS = $(addsuffix .o,$(BPF_TARGETS))
BPF_SKELETONS = $(addsuffix .skel.h,$(BPF_TARGETS))

TARGETS = main lockstep demo-nobpf \
	$(BPF_OBJECTS) \
	$(BPF_SKELETONS) \
	$(BPF_TARGETS)

.PHONY: all
all: $(TARGETS)

main: main.cpp
	g++ -std=c++11 -O2 main.cpp -o main -lpthread

lockstep: lockstep.cpp
	g++ $(LIBNL3_FLAGS) $< -o $@

$(BPF_OBJECTS) : %.o : %.bpf.c defines.h
	clang --target=bpf -O2 -g -Wall -c -o $@ $<

$(BPF_SKELETONS) : %.skel.h : %.o
	bpftool gen skeleton $< > $@

$(BPF_TARGETS) : % : %.cpp %.skel.h defines.h
	g++ $(LIBBPF_FLAGS) -O2 $< -o $@

demo-nobpf: demo.cpp
	g++ -std=c++11 -O2 -DDEMO_NO_BPF $< -o $@ -lpthread

.PHONY: clean
clean:
	rm -f $(TARGETS)
