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
#include <sstream>
#include <condition_variable>

#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/types.h>

// #define DEMO_NO_BPF

#ifndef DEMO_NO_BPF
#include "defines.h"
#include "demo.skel.h"
#endif

#define fatal(...) { \
    fprintf(stderr, __VA_ARGS__); \
    exit(-1); \
}

static inline __u64 get_ts() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

#ifndef DEMO_NO_BPF
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}
#endif

struct Monitor {
#ifndef DEMO_NO_BPF
    static constexpr auto both_directions = static_cast<enum bpf_tc_attach_point>(
        BPF_TC_INGRESS | BPF_TC_EGRESS
    );
#endif

    struct Socket {
        static constexpr size_t initial_buffer_size = 65536;

        Monitor &mon;
#ifndef DEMO_NO_BPF
        struct tcp_key ingress_key;
        struct tcp_key egress_key;
#endif
        int fd;
        __u32 initial_ack_seq = 0;
        __u32 num_bytes_read = 0;
        size_t beg = 0, end = 0;
        std::vector<__u8> buffer;

#ifndef DEMO_NO_BPF
        void set_ack_seq(__u32 ack_seq) {
            int ret = 0;
            do {
                ret = bpf_map__update_elem(
                    mon.skel->maps.ack_map, &egress_key, sizeof(egress_key), &ack_seq, sizeof(ack_seq), BPF_ANY
                );
            } while (ret == -EBUSY);
            if (ret < 0) {
                fprintf(stderr, "Failed to set ack sequence number. errno=%d\n", errno);
                throw std::runtime_error("set_ack_seq");
            }
        }
#endif

        Socket(Monitor &_mon, int _fd) : mon(_mon), fd(_fd) {
            buffer.resize(initial_buffer_size);

#ifndef DEMO_NO_BPF
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
            initial_ack_seq = v + 1;
            // printf("initial_recv_seq=%u\n", initial_recv_seq);

            egress_key = ingress_key;
            std::swap(egress_key.saddr, egress_key.daddr);
            std::swap(egress_key.sport, egress_key.dport);
            bpf_map__delete_elem(mon.skel->maps.syn_map, &egress_key, sizeof(egress_key), 0);

            set_ack_seq(initial_ack_seq);
#endif
        }

        void write(const void *data, size_t size) {
            const __u8 *ptr = (const __u8 *)data;
            for (size_t i = 0; i < size; ) {
                int ret = send(fd, ptr + i, size - i, 0);
                if (ret < 0)
                    throw std::runtime_error("send");
                    // fatal("Failed to write to socket. errno=%d\n", errno);
                i += ret;
            }
            mon.outbound_acc.fetch_add(size, std::memory_order_relaxed);
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
                    throw std::runtime_error("recv");
                    // fatal("Failed to read from socket. errno=%d\n", errno);
                if (ret == 0)
                    throw std::runtime_error("recv: shutdown");
                end += ret;
                num_bytes_read += ret;
            }

            const void *ptr = buffer.data() + beg;
            beg += size;
            // num_bytes_read += size;
#ifndef DEMO_NO_BPF
            __u32 new_ack_seq;
            if (__builtin_uadd_overflow(initial_ack_seq, num_bytes_read, &new_ack_seq))
                fprintf(stderr, "Ack sequence number wrapped around\n");
            set_ack_seq(new_ack_seq);
#endif
            mon.inbound_acc.fetch_add(size, std::memory_order_relaxed);
            return ptr;
        }
    };

    using SocketPtr = std::shared_ptr<Socket>;

    struct Histogram {
        static constexpr int num_buckets = 131072;
        static constexpr int bucket_width = 128;

        std::atomic<__u64> sum;
        std::atomic<__u64> num_samples;
        std::atomic<__u64> bucket[num_buckets];

        void add(__u64 latency) {
            sum.fetch_add(latency, std::memory_order_relaxed);
            num_samples.fetch_add(1, std::memory_order_relaxed);
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

#ifndef DEMO_NO_BPF
    struct demo *skel = NULL;
    int ifindex;
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
    };
#endif
    std::list<int> fds;
    std::list<SocketPtr> socks;
    Histogram latency;
    std::atomic<__u64> inbound_acc;
    std::atomic<__u64> outbound_acc;

    void realize() {
#ifndef DEMO_NO_BPF
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

        hook.ifindex = ifindex;
        hook.attach_point = both_directions;
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
#endif
    }

    void finalize() {
        for (auto &sock : socks) {
            shutdown(sock->fd, SHUT_RDWR);
            close(sock->fd);
        }
        for (int fd : fds) {
            close(fd);
        }

#ifndef DEMO_NO_BPF
        if (skel) {
            hook.attach_point = both_directions;
            if (bpf_tc_hook_destroy(&hook) < 0)
                fprintf(stderr, "Failed to destroy tc hook. errno=%d\n", errno);
            demo::destroy(skel);
        }
#endif
    }

    auto attach(int fd) -> SocketPtr {
        socks.push_back(std::make_shared<Socket>(*this, fd));
        return socks.back();
    }

    void run(int num_iters, const std::string &name) {
        double ts_0 = 0, ts_1 = 0, ts_2 = 0;
        __u64 sum_1 = 0, sum_2 = 0;
        __u64 num_samples_1 = 0, num_samples_2 = 0;
        __u64 inbound_acc_1 = 0, inbound_acc_2 = 0;
        __u64 outbound_acc_1 = 0, outbound_acc_2 = 0;
        auto fetch = [&] {
            ts_1 = ts_2;
            ts_2 = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
            sum_1 = sum_2;
            sum_2 = latency.sum.load(std::memory_order_relaxed);
            num_samples_1 = num_samples_2;
            num_samples_2 = latency.num_samples.load(std::memory_order_relaxed);
            inbound_acc_1 = inbound_acc_2;
            inbound_acc_2 = inbound_acc.load(std::memory_order_relaxed);
            outbound_acc_1 = outbound_acc_2;
            outbound_acc_2 = outbound_acc.load(std::memory_order_relaxed);
        };

        fetch();
        ts_0 = ts_2;
        double num_pkts = 0;
        double in_tput_sum = 0;
        double out_tput_sum = 0;
        double duration = 0;
        __u64 acc[latency.num_buckets + 1], delta[latency.num_buckets + 1];
        for (int t = 0; t < num_iters; t++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            fetch();
            double n = num_samples_2 - num_samples_1;
            double d = ts_2 - ts_1;
            double avg_pkts = n / d;
            double avg_lat = (sum_2 - sum_1) / n / 1000;
            double in_tput = (inbound_acc_2 - inbound_acc_1) / d / 1024;
            double out_tput = (outbound_acc_2 - outbound_acc_1) / d / 1024;

            printf(
                "[%.1lfs]\t%.1lf pkts/s\tavg %.3lf ms\tin %.3lf KiB/s\tout %.3lf KiB/s\n",
                ts_2 - ts_0, avg_pkts, avg_lat, in_tput, out_tput
            );

            if (t == 4 || t + 6 == num_iters) {
                num_pkts = num_samples_2 - num_pkts;
                in_tput_sum = inbound_acc_2 - in_tput_sum;
                out_tput_sum = outbound_acc_2 - out_tput_sum;
                duration = ts_2 - duration;
                latency.dump(acc, delta);
            }
        }

        double p50 = NAN, p99 = NAN;
        double n = delta[latency.num_buckets];
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

        num_pkts /= duration;
        in_tput_sum /= duration;
        out_tput_sum /= duration;
        printf(
            "%s %.1lf %.3lf %.3lf %.3lf %.3lf\n",
            name.c_str(), num_pkts, p50 / 1000, p99 / 1000, in_tput_sum / 1024, out_tput_sum / 1024
        );
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
        try {
            while (true) {
                auto p = (Packet *)sock->read(sizeof(Packet));
                if (p->size > sizeof(Packet))
                    sock->read(p->size - sizeof(Packet));
                __u64 begin_ts = p->ts;
                __u64 end_ts = get_ts();
                mon.latency.add(end_ts - begin_ts);
            }
        } catch (...) {}
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
            sock->read(p->size - sizeof(Packet));

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

void signal_handler(int sig) {
    printf("Received signal=%d\n", sig);
    mon.finalize();
    exit(0);
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (argc < 6) {
        fprintf(stderr, "%s client/server [count] ping/push/echo [packet size] [address]:[port] [sleep_ms]\n", argv[0]);
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
        mon.fds.push_back(sock);

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

    std::vector<std::thread> workers;
    workers.reserve(count);
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

        int value = 1;
        if (setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0)
            fprintf(stderr, "Failed to set TCP_NODELAY. errno=%d\n", errno);
        // if (setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(value)) < 0)
        //     fprintf(stderr, "Failed to set TCP_QUICKACK. errno=%d\n", errno);
        struct linger linger_opts {
            .l_onoff = 1,
            .l_linger = 0,
        };
        if (setsockopt(conn, SOL_SOCKET, SO_LINGER, &linger_opts, sizeof(linger_opts)) < 0)
            fprintf(stderr, "Failed to set SO_LINGER. errno=%d\n", errno);

        workers.emplace_back([&, conn] {
            auto sock = mon.attach(conn);

            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return flag; });
            }

            try {
                if (is_push)
                    do_push(sock);
                else if (is_ping)
                    do_ping(sock);
                else
                    do_echo(sock);
            } catch (...) {};
        });
    }

    {
        std::unique_lock<std::mutex> lock(mtx);
        flag = true;
    }
    cv.notify_all();

    int env_count = 20;
    const char *count_str = getenv("COUNT");
    if (count_str)
        env_count = atoi(count_str);

    puts("Benchmark started");
    std::stringstream ss;
    ss << argv[0] << "\t";
    ss << argv[1] << "-" << argv[3] << "-t" << argv[2] << "-sz" << packet_size;
    mon.run(env_count, ss.str());

    puts("Benchmark stopped");
    mon.finalize();

    for (auto &t : workers) {
        t.join();
    }

    return 0;
}
