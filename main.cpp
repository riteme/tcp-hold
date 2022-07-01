#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>

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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

using u8 = unsigned char;
using u64 = unsigned long long;

struct Closer {
    int fd;

    ~Closer() {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
};

struct Packet {
    u64 size;
    u64 ts;
    u8 data[];
};

struct Histogram {
    static constexpr int num_buckets = 65536;
    static constexpr int bucket_width = 512;

    std::atomic<u64> bucket[num_buckets];

    void add(u64 latency) {
        u64 i = latency / bucket_width;
        if (i >= num_buckets)
            printf("Warning: latency=%llu is too large\n", latency);
        else
            bucket[i].fetch_add(1, std::memory_order_relaxed);
    }

    void dump(u64 dest[num_buckets + 1], u64 delta[num_buckets + 1]) {
        dest[0] = delta[0] = 0;
        for (int i = 0; i < num_buckets; i++) {
            delta[i + 1] = dest[i] + bucket[i].load(std::memory_order_relaxed) - dest[i + 1];
            dest[i + 1] += delta[i + 1];
        }
    }
};

u64 packet_size;
int sleep_ms = 10;
std::vector<u8> pad;
Histogram latency;
std::atomic<u64> inbound_acc;
std::atomic<u64> outbound_acc;

u64 get_ts() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

void monitor() {
    double ts_0, ts_1, ts_2;
    u64 acc[latency.num_buckets + 1], delta[latency.num_buckets + 1];
    u64 inbound_acc_1, inbound_acc_2;
    u64 outbound_acc_1, outbound_acc_2;
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

int read_socket(int fd, void *buf, size_t size) {
    int ret = read(fd, buf, size);
    if (ret < 0) {
        fprintf(stderr, "Failed to read from socket. errno=%d\n", errno);
        exit(-1);
    }
    return ret;
}

void read_all(int fd, void *_buf, size_t size) {
    u8 *buf = (u8 *)_buf;
    for (size_t i = 0; i < size; ) {
        int cnt = read_socket(fd, buf + i, size - i);
        i += cnt;
        inbound_acc.fetch_add(cnt, std::memory_order_relaxed);
    }
}

int write_socket(int fd, const void *buf, size_t size) {
    int ret = write(fd, buf, size);
    if (ret < 0) {
        fprintf(stderr, "Failed to write to socket. errno=%d\n", errno);
        exit(1);
    }
    return ret;
}

void write_all(int fd, const void *_buf, size_t size) {
    const u8 *buf = (const u8 *)_buf;
    for (size_t i = 0; i < size; ) {
        int cnt = write_socket(fd, buf + i, size - i);
        i += cnt;
        outbound_acc.fetch_add(cnt, std::memory_order_relaxed);
    }
}

#define read_object(fd, obj) read_all((fd), &(obj), sizeof(obj))
#define write_object(fd, obj) write_all((fd), &(obj), sizeof(obj))

void do_ping(int sock) {
    while (true) {
        {
            u8 buf[packet_size];
            memcpy(buf, pad.data(), sizeof(buf));
            auto p = (Packet *)buf;
            p->size = packet_size;
            p->ts = get_ts();
            write_object(sock, buf);
        }

        {
            Packet p;
            read_object(sock, p);
            if (p.size > sizeof(p)) {
                u8 buf[p.size - sizeof(p)];
                read_object(sock, buf);
            }

            u64 begin_ts = p.ts;
            u64 end_ts = get_ts();
            latency.add(end_ts - begin_ts);
        }
    }
}

void do_push(int sock) {
    std::thread([&] {
        while (true) {
            Packet p;
            read_object(sock, p);
            if (p.size > sizeof(p)) {
                u8 buf[p.size - sizeof(p)];
                read_object(sock, buf);
            }

            u64 begin_ts = p.ts;
            u64 end_ts = get_ts();
            latency.add(end_ts - begin_ts);
        }
    }).detach();

    while (true) {
        u8 buf[packet_size];
        memcpy(buf, pad.data(), sizeof(buf));
        auto p = (Packet *)buf;
        p->size = packet_size;
        p->ts = get_ts();
        write_object(sock, buf);
        usleep(1000 * sleep_ms);
    }
}

void do_echo(int sock) {
    while (true) {
        auto begin_ts = get_ts();

        Packet p;
        read_object(sock, p);
        if (p.size > sizeof(p)) {
            u8 buf[p.size - sizeof(p)];
            read_object(sock, buf);
        }

        u8 buf[packet_size];
        memcpy(buf, pad.data(), sizeof(buf));
        auto q = (Packet *)buf;
        q->size = packet_size;
        q->ts = p.ts;
        write_object(sock, buf);

        auto end_ts = get_ts();
        latency.add(end_ts - begin_ts);
    }
}

void signal_handler(int) {
    puts("Exiting...");
    exit(0);
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

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
    for (u8 &b : pad) {
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

    if (argc > 6) {
        sleep_ms = atoi(argv[6]);
    }

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

    Closer _ {sock};

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
            Closer _ {conn};

            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return flag; });
            }

            if (is_push)
                do_push(conn);
            else if (is_ping)
                do_ping(conn);
            else
                do_echo(conn);
        }).detach();
    }

    {
        std::unique_lock<std::mutex> lock(mtx);
        flag = true;
    }
    cv.notify_all();

    puts("Benchmark started");
    std::thread(monitor).detach();

    while (true) {
        pause();
    }

    return 0;
}
