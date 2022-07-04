#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <functional>

#include "demo.skel.h"

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

static void attach_program(
    struct bpf_tc_hook *hook,
    struct bpf_program *program
) {
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(program),
    );
    if (bpf_tc_attach(hook, &opts) < 0) {
        fprintf(stderr, "Failed to attach BPF program. errno=%d\n", errno);
        exit(-1);
    }
}

int main() {
    atexit(exit_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    struct demo *skel = demo::open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF prgoram. errno=%d\n", errno);
        return -1;
    }
    defer.push_back([skel] {
        demo::destroy(skel);
    });

    if (demo::load(skel) < 0) {
        fprintf(stderr, "Failed to load BPF program. errno=%d\n", errno);
        return -1;
    }

    int index = if_nametoindex("inner0");
    if (index == 0) {
        fprintf(stderr, "Failed to get ifindex. errno=%d\n", errno);
        return -1;
    }

    enum bpf_tc_attach_point both = static_cast<enum bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = index,
        .attach_point = both,
    );
    if (bpf_tc_hook_create(&hook) < 0) {
        fprintf(stderr, "Failed to create tc hook. errno=%d\n", errno);
        exit(-1);
    }
    defer.push_back([hook]() mutable {
        bpf_tc_hook_destroy(&hook);
    });

    hook.attach_point = BPF_TC_INGRESS;
    attach_program(&hook, skel->progs.ingress_main);
    hook.attach_point = BPF_TC_EGRESS;
    attach_program(&hook, skel->progs.egress_main);

    while (true) {
        sleep(1);

        struct bpf_sock_tuple k;
        while (bpf_map__get_next_key(skel->maps.syn_map, NULL, &k, sizeof(k)) != -ENOENT) {
            __u32 v;
            if (bpf_map__lookup_and_delete_elem(skel->maps.syn_map, &k, sizeof(k), &v, sizeof(v), 0) < 0)
                v = 0;

            char src[32], dst[32];
            strcpy(src, inet_ntoa((struct in_addr){k.ipv4.saddr}));
            strcpy(dst, inet_ntoa((struct in_addr){k.ipv4.daddr}));
            printf(
                "%s:%d -> %s:%d @%u\n",
                src, ntohs(k.ipv4.sport),
                dst, ntohs(k.ipv4.dport),
                v
            );
        }
    }
}
