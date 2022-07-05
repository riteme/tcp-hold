#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "defines.h"
#include "demo.skel.h"

#define fatal(...) { \
    fprintf(stderr, __VA_ARGS__); \
    exit(-1); \
}

struct Monitor {
    static constexpr auto BOTH_DIRECTION = static_cast<enum bpf_tc_attach_point>(
        BPF_TC_INGRESS | BPF_TC_EGRESS
    );

    static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
        return vfprintf(stderr, format, args);
    }

    struct demo *skel = NULL;
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
    };

    void realize() {
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        libbpf_set_print(libbpf_print_fn);

        skel = demo::open();
        if (!skel)
            fatal("Failed to open BPF prgoram. errno=%d\n", errno);
        if (demo::load(skel) < 0)
            fatal("Failed to load BPF program. errno=%d\n", errno);

        hook.ifindex = if_nametoindex("inner0");
        if (hook.ifindex == 0)
            fatal("Failed to get ifindex. errno=%d\n", errno);
        hook.attach_point = BOTH_DIRECTION;
        if (bpf_tc_hook_create(&hook) < 0)
            fatal("Failed to create tc hook. errno=%d\n", errno);

        struct bpf_tc_opts opts = {0};
        opts.sz = sizeof(opts);
        hook.attach_point = BPF_TC_INGRESS;
        opts.prog_fd = bpf_program__fd(skel->progs.ingress_main);
        if (bpf_tc_attach(&hook, &opts) < 0)
            fatal("Failed to attach ingress BPF program. errno=%d\n", errno);

        memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts);
        hook.attach_point = BPF_TC_EGRESS;
        opts.prog_fd = bpf_program__fd(skel->progs.egress_main);
        if (bpf_tc_attach(&hook, &opts) < 0)
            fatal("Failed to attach egress BPF program. errno=%d\n", errno);
    }

    void finalize() {
        if (hook.ifindex != 0) {
            hook.attach_point = BOTH_DIRECTION;
            bpf_tc_hook_destroy(&hook);
        }
        if (skel)
            demo::destroy(skel);
    }
};

static Monitor mon;

static void exit_handler() {
    puts("Exiting...");
    mon.finalize();
}

static void signal_handler(int) {
    exit(0);
}

int main() {
    atexit(exit_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    mon.realize();

    while (true) {
        sleep(1);

        struct tcp_key k;
        while (bpf_map__get_next_key(mon.skel->maps.syn_map, NULL, &k, sizeof(k)) != -ENOENT) {
            __u32 v;
            if (bpf_map__lookup_and_delete_elem(mon.skel->maps.syn_map, &k, sizeof(k), &v, sizeof(v), 0) < 0)
                v = 0;

            char src[32], dst[32];
            strcpy(src, inet_ntoa((struct in_addr){k.saddr}));
            strcpy(dst, inet_ntoa((struct in_addr){k.daddr}));
            printf(
                "%s:%d -> %s:%d @%u\n",
                src, ntohs(k.sport),
                dst, ntohs(k.dport),
                v
            );
        }
    }
}
