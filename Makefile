LIBNL3_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-route-3.0 libnl-cli-3.0)
TARGETS = main lockstep

all: $(TARGETS)

main: main.cpp
	g++ -std=c++11 -lpthread -O2 main.cpp -o main

lockstep: lockstep.cpp
	g++ -std=c++11 -lpthread $(LIBNL3_FLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(TARGETS)
