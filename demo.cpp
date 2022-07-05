#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <list>
#include <queue>
#include <atomic>
#include <chrono>
#include <thread>
#include <memory>
#include <random>
#include <condition_variable>

#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "defines.h"
#include "demo.skel.h"

static void safe_exit(int v) {
    static std::mutex exit_mutex;
    exit_mutex.lock();
    exit(v);
}

#define fatal(...) { \
    fprintf(stderr, __VA_ARGS__); \
    safe_exit(-1); \
}

static inline __u64 get_ts() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int env_hook = 0;

struct Monitor {
    static constexpr auto both_directions = static_cast<enum bpf_tc_attach_point>(
        BPF_TC_INGRESS | BPF_TC_EGRESS
    );

    struct Socket {
        static constexpr size_t initial_buffer_size = 4096;

        Monitor &mon;
        struct tcp_key ingress_key;
        struct tcp_key egress_key;
        int fd;
        __u32 initial_recv_seq = 0;
        __u32 num_bytes_read = 0;
        size_t beg = 0, end = 0;
        std::vector<__u8> buffer;

        void set_ack_seq(__u32 ack_seq) {
            int ret = 0;
            do {
                ret = bpf_map__update_elem(
                    mon.skel->maps.ack_map, &egress_key, sizeof(egress_key), &ack_seq, sizeof(ack_seq), BPF_ANY
                );
            } while (ret == -EBUSY);
            if (ret < 0)
                fprintf(stderr, "Failed to set ack sequence number. errno=%d\n", errno);
        }

        Socket(Monitor &_mon, int _fd) : mon(_mon), fd(_fd) {
            buffer.resize(initial_buffer_size);

            if (!env_hook)
                return;

            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            getpeername(fd, (struct sockaddr *)&addr, &len);
            ingress_key.saddr = addr.sin_addr.s_addr;
            ingress_key.sport = addr.sin_port;
            getsockname(fd, (struct sockaddr *)&addr, &len);
            ingress_key.daddr = addr.sin_addr.s_addr;
            ingress_key.dport = addr.sin_port;

            __u32 v;
            if (bpf_map__lookup_and_delete_elem(
                    mon.skel->maps.syn_map, &ingress_key, sizeof(ingress_key), &v, sizeof(v), 0
                ) < 0)
                fatal("Failed to get initial recv sequence number. errno=%d\n", errno);
            initial_recv_seq = v;
            printf("initial_recv_seq=%u\n", initial_recv_seq);

            egress_key = ingress_key;
            std::swap(egress_key.saddr, egress_key.daddr);
            std::swap(egress_key.sport, egress_key.dport);
            bpf_map__delete_elem(mon.skel->maps.syn_map, &egress_key, sizeof(egress_key), 0);

            set_ack_seq(initial_recv_seq + 1);
        }

        ~Socket() {
            finalize();
        }

        void write(const void *data, size_t size) {
            const __u8 *ptr = (const __u8 *)data;
            for (size_t i = 0; i < size; ) {
                int ret = send(fd, ptr + i, size - i, 0);
                if (ret < 0)
                    fatal("Failed to write to socket. errno=%d\n", errno);
                i += ret;
            }
        }

        auto read(size_t size) -> const void * {
            // Not at front && no enough space
            if (beg > 0 && size > buffer.size() - beg) {
                // Non-empty
                if (beg < end)
                    memmove(buffer.data(), buffer.data() + beg, end - beg);
                end -= beg;
                beg = 0;
            }

            if (size > buffer.size()) {
                size_t new_size = buffer.size() * 2;
                while (size > new_size) {
                    new_size *= 2;
                }
                buffer.resize(new_size);
            }

            while (size > end - beg) {
                int ret = recv(fd, buffer.data() + end, buffer.size() - end, 0);
                if (ret < 0)
                    fatal("Failed to read from socket. errno=%d\n", errno);
                end += ret;
            }

            const void *ptr = buffer.data() + beg;
            beg += size;
            num_bytes_read += size;
            if (env_hook)
                set_ack_seq(initial_recv_seq + num_bytes_read);
            return ptr;
        }

        void finalize() {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
    };

    using SocketPtr = std::shared_ptr<Socket>;

    struct Histogram {
        static constexpr int num_buckets = 65536;
        static constexpr int bucket_width = 512;

        std::atomic<__u64> bucket[num_buckets];

        void add(__u64 latency) {
            __u64 i = latency / bucket_width;
            if (i >= num_buckets)
                fprintf(stderr, "Warning: latency=%llu is too large\n", latency);
            else
                bucket[i].fetch_add(1, std::memory_order_relaxed);
        }

        void dump(__u64 dest[num_buckets + 1], __u64 delta[num_buckets + 1]) {
            dest[0] = delta[0] = 0;
            for (int i = 0; i < num_buckets; i++) {
                delta[i + 1] = dest[i] + bucket[i].load(std::memory_order_relaxed) - dest[i + 1];
                dest[i + 1] += delta[i + 1];
            }
        }
    };

    struct demo *skel = NULL;
    int ifindex;
    std::list<int> fds;
    std::list<SocketPtr> socks;
    Histogram latency;
    std::atomic<__u64> inbound_acc;
    std::atomic<__u64> outbound_acc;

    void realize() {
        if (!env_hook)
            return;

        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        libbpf_set_print(libbpf_print_fn);

        skel = demo::open();
        if (!skel)
            fatal("Failed to open BPF prgoram. errno=%d\n", errno);
        if (demo::load(skel) < 0)
            fatal("Failed to load BPF program. errno=%d\n", errno);

        ifindex = if_nametoindex("inner0");
        if (ifindex == 0)
            fatal("Failed to get ifindex. errno=%d\n", errno);

        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
            .ifindex = ifindex,
            .attach_point = both_directions,
        );
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
        for (int fd : fds) {
            close(fd);
        }
        for (auto &sock : socks) {
            sock->finalize();
        }

        if (skel) {
            // TODO: Sometimes atexit doesn't arrive here.
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
                .ifindex = ifindex,
                .attach_point = both_directions,
            );
            if (bpf_tc_hook_destroy(&hook) < 0)
                fprintf(stderr, "Failed to destroy tc hook. errno=%d\n", errno);
            demo::destroy(skel);
        }
    }

    auto attach(int fd) -> SocketPtr {
        socks.push_back(std::make_shared<Socket>(*this, fd));
        return socks.back();
    }

    void main() {
        double ts_0, ts_1, ts_2;
        __u64 acc[latency.num_buckets + 1], delta[latency.num_buckets + 1];
        __u64 inbound_acc_1, inbound_acc_2;
        __u64 outbound_acc_1, outbound_acc_2;
        auto fetch = [&] {
            ts_1 = ts_2;
            ts_2 = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
            latency.dump(acc, delta);
            inbound_acc_1 = inbound_acc_2;
            inbound_acc_2 = inbound_acc.load();
            outbound_acc_1 = outbound_acc_2;
            outbound_acc_2 = outbound_acc.load();
        };

        fetch();
        ts_0 = ts_2;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            auto begin_ts = get_ts();

            fetch();
            double n = delta[latency.num_buckets - 1];
            double avg_pkts = n / (ts_2 - ts_1);
            double in_tput = (inbound_acc_2 - inbound_acc_1) / (ts_2 - ts_1) / 1024 / 1024;
            double out_tput = (outbound_acc_2 - outbound_acc_1) / (ts_2 - ts_1) / 1024 / 1024;

            double p50 = NAN, p99 = NAN;
            for (int i = 0; i < latency.num_buckets; i++) {
                // if (delta[i + 1] - delta[i] > 0)
                //     printf("[%d] = %llu\n", i, delta[i + 1]);
                double lp = delta[i] / n;
                double rp = delta[i + 1] / n;
                if (lp < 0.5 && 0.5 <= rp)
                    p50 = i * latency.bucket_width + latency.bucket_width * (0.5 - lp) / (rp - lp);
                if (lp < 0.99 && 0.99 <= rp)
                    p99 = i * latency.bucket_width + latency.bucket_width * (0.99 - lp) / (rp - lp);
            }
            p50 /= 1000;
            p99 /= 1000;

            auto end_ts = get_ts();
            printf("Computed in %llu μs\n", end_ts - begin_ts);

            printf(
                "[%.1lfs] %.1lf pkts/s, p50 %.3lf ms, p99 %.3lf ms, in %.2lf MiB/s, out %.2lf MiB/s\n",
                ts_2 - ts_0, avg_pkts, p50, p99, in_tput, out_tput
            );
        }
    }
};

struct Packet {
    __u64 size;
    __u64 ts;
    __u8 data[];
};

__u64 packet_size;
int sleep_ms = 10;
std::vector<__u8> pad;
Monitor mon;

void do_ping(Monitor::SocketPtr sock) {
    while (true) {
        // Send
        {
            __u8 buf[packet_size];
            memcpy(buf, pad.data(), sizeof(buf));
            auto p = (Packet *)buf;
            p->size = packet_size;
            p->ts = get_ts();
            sock->write(buf, sizeof(buf));
        }

        // Receive
        {
            auto p = (Packet *)sock->read(sizeof(Packet));
            if (p->size > sizeof(Packet))
                sock->read(p->size - sizeof(Packet));
            __u64 begin_ts = p->ts;
            __u64 end_ts = get_ts();
            mon.latency.add(end_ts - begin_ts);
        }
    }
}

void do_push(Monitor::SocketPtr sock) {
    std::thread([&] {
        while (true) {
            auto p = (Packet *)sock->read(sizeof(Packet));
            if (p->size > sizeof(Packet))
                sock->read(p->size - sizeof(Packet));
            __u64 begin_ts = p->ts;
            __u64 end_ts = get_ts();
            mon.latency.add(end_ts - begin_ts);
        }
    }).detach();

    while (true) {
        __u8 buf[packet_size];
        memcpy(buf, pad.data(), sizeof(buf));
        auto p = (Packet *)buf;
        p->size = packet_size;
        p->ts = get_ts();
        sock->write(buf, sizeof(buf));
        if (sleep_ms > 0)
            usleep(1000 * sleep_ms);
    }
}

void do_echo(Monitor::SocketPtr sock) {
    while (true) {
        auto begin_ts = get_ts();

        auto p = (Packet *)sock->read(sizeof(Packet));
        if (p->size > sizeof(Packet))
            sock->read(sizeof(Packet) - p->size);

        if (sleep_ms > 0)
            usleep(sleep_ms * 1000);

        __u8 buf[packet_size];
        memcpy(buf, pad.data(), sizeof(buf));
        auto q = (Packet *)buf;
        q->size = packet_size;
        q->ts = p->ts;
        sock->write(buf, sizeof(buf));

        auto end_ts = get_ts();
        mon.latency.add(end_ts - begin_ts);
    }
}

void exit_handler() {
    puts("Exiting...");
    mon.finalize();
}

void signal_handler(int) {
    safe_exit(0);
}

int main(int argc, char *argv[]) {
    atexit(exit_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    auto env_hook_str = getenv("HOOK");
    if (env_hook_str)
        env_hook = atoi(env_hook_str);

    if (argc < 6) {
        fprintf(stderr, "%s client/server [count] push/echo [packet size] [address]:[port] [sleep_ms]\n", argv[0]);
        return -1;
    }

    bool is_client;
    if (strcmp(argv[1], "client") == 0)
        is_client = true;
    else if (strcmp(argv[1], "server") == 0)
        is_client = false;
    else {
        fprintf(stderr, "First CLI argument is invalid\n");
        return -1;
    }

    int count = atoi(argv[2]);

    bool is_push = false, is_ping = false;
    if (strcmp(argv[3], "push") == 0)
        is_push = true;
    else if (strcmp(argv[3], "ping") == 0)
        is_ping = true;
    else if (strcmp(argv[3], "echo") != 0) {
        fprintf(stderr, "Second CLI argument is invalid\n");
        return -1;
    }

    packet_size = atoi(argv[4]);
    if (packet_size < sizeof(Packet)) {
        fprintf(stderr, "Packet size is too small\n");
        return -1;
    }
    pad.resize(packet_size);
    std::random_device rd;
    std::mt19937 gen(rd());
    for (__u8 &b : pad) {
        b = gen();
    }

    char *sep = strchr(argv[5], ':');
    if (!sep) {
        fprintf(stderr, "Invalid address\n");
        return -1;
    }
    *sep = '\0';
    sep++;
    const char *address = argv[5];
    int port = atoi(sep);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!inet_aton(address, &addr.sin_addr)) {
        fprintf(stderr, "Failed to parse \"%s\"\n", address);
        return -1;
    }

    if (!is_push && !is_ping)
        sleep_ms = 0;
    if (argc > 6)
        sleep_ms = atoi(argv[6]);

    mon.realize();

    bool flag = false;
    std::mutex mtx;
    std::condition_variable cv;

    int sock = -1;
    if (!is_client) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            fprintf(stderr, "Failed to create socket. errno=%d\n", errno);
            return -1;
        }

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "Failed to bind to %s:%d. errno=%d\n", address, port, errno);
            return -1;
        }

        if (listen(sock, count) < 0) {
            fprintf(stderr, "Failed to listen socket. errno=%d\n", errno);
            return -1;
        }

        puts("Ready to accept connections");
    }

    for (int i = 0; i < count; i++) {
        int conn = -1;
        if (is_client) {
            conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (conn < 0) {
                fprintf(stderr, "Failed to create socket. errno=%d\n", errno);
                return -1;
            }

            if (connect(conn, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                fprintf(stderr, "Failed to connect to %s:%d. errno=%d\n", address, port, errno);
                return -1;
            }

            printf("Connected #%d\n", i + 1);
        } else {
            socklen_t len = sizeof(addr);
            conn = accept(sock, (struct sockaddr *)&addr, &len);
            if (conn < 0) {
                fprintf(stderr, "Failed to accept new connections. errno=%d\n", errno);
                return -1;
            }

            printf("Connection #%d from %s:%d\n", i + 1, inet_ntoa(addr.sin_addr), addr.sin_port);
        }

        int flag = 1;
        if (setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            fprintf(stderr, "Failed to set TCP_NODELAY. errno=%d\n", errno);
        }
        // if (setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag)) < 0) {
        //     fprintf(stderr, "Failed to set TCP_QUICKACK. errno=%d\n", errno);
        // }

        std::thread([&, conn] {
            auto sock = mon.attach(conn);

            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return flag; });
            }

            if (is_push)
                do_push(sock);
            else if (is_ping)
                do_ping(sock);
            else
                do_echo(sock);
        }).detach();
    }

    close(sock);

    {
        std::unique_lock<std::mutex> lock(mtx);
        flag = true;
    }
    cv.notify_all();

    puts("Benchmark started");
    mon.main();

    return 0;
}
