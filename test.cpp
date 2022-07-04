#include <signal.h>
#include <net/if.h>

#include <vector>
#include <functional>

#include "test.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

std::vector<std::function<void()>> defer;

static void exit_handler() {
    puts("Exiting...");
    for (auto fn = defer.rbegin(); fn != defer.rend(); fn++) {
        (*fn)();
    }
}

static void signal_handler(int) {
    exit(0);
}

int main() {
    atexit(exit_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    struct test *skel = test::open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF prgoram. errno=%d\n", errno);
        return -1;
    }
    defer.push_back([skel] {
        test::destroy(skel);
    });

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
    defer.push_back([hook]() mutable {
        hook.attach_point = static_cast<enum bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS);
        bpf_tc_hook_destroy(&hook);
    });

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(skel->progs.tc_main),
    );
    if (bpf_tc_attach(&hook, &opts) < 0) {
        fprintf(stderr, "Failed to attach BPF program. errno=%d\n", errno);
        return -1;
    }

    while (true) {
        printf("mode = ");
        scanf("%d", &skel->bss->mode);

        int k, *kp = NULL;
        while (bpf_map__get_next_key(skel->maps.count_map, kp, &k, sizeof(k)) != -ENOENT) {
            kp = &k;
            uint64_t v;
            if (bpf_map__lookup_elem(skel->maps.count_map, &k, sizeof(k), &v, sizeof(v), 0) < 0)
                v = 0;
            printf("count[%d]=%lu\n", k, v);
        }
    }
}
