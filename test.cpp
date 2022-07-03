#include <iostream>
#include <net/if.h>

#include "test.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int main() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    struct test *skel = test::open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF prgoram. errno=%d\n", errno);
        return -1;
    }

    skel->bss->mode = 0;

    if (test::load(skel) < 0) {
        fprintf(stderr, "Failed to load BPF program. errno=%d\n", errno);
        return -1;
    }

    int index = if_nametoindex("inner0");
    if (index == 0) {
        fprintf(stderr, "Failed to get ifindex. errno=%d\n", errno);
        return -1;
    }
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = index,
        .attach_point = BPF_TC_EGRESS,
    );
    if (bpf_tc_hook_create(&hook) < 0) {
        fprintf(stderr, "Failed to create tc hook. errno=%d\n", errno);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(skel->progs.tc_main),
    );
    if (bpf_tc_attach(&hook, &opts) < 0) {
        fprintf(stderr, "Failed to attach BPF program. errno=%d\n", errno);
        return -1;
    }

    while (true) {
        std::cin >> skel->bss->mode;
    }

    return 0;
}
