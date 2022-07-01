#include <assert.h>
#include <signal.h>
#include <unistd.h>

#include <chrono>

#include <netlink/cli/tc.h>
#include <netlink/cli/link.h>
#include <netlink/cli/qdisc.h>
#include <netlink/cli/utils.h>
#include <netlink/route/qdisc/plug.h>

static struct nl_sock *sock;
static struct rtnl_qdisc *qdisc;

static void signal_handler(int) {
    puts("Exiting...");
    int ret = rtnl_qdisc_delete(sock, qdisc);
    if (ret != 0)
        nl_cli_fatal(-1, "rtnl_qdisc_delete: ret=%d", ret);
    exit(0);
}

static void replace_qdisc() {
    int ret = rtnl_qdisc_add(sock, qdisc, NLM_F_CREATE | NLM_F_REPLACE);
    if (ret != 0)
        nl_cli_fatal(-1, "rtnl_qdisc_add: ret=%d", ret);
}

int main(int argc, char *argv[]) {
    if (argc < 2)
        nl_cli_fatal(-1, "%s [interval]", argv[0]);

    int interval = atoi(argv[1]);

    sock = nl_cli_alloc_socket();
    nl_cli_connect(sock, NETLINK_ROUTE);
    struct nl_cache *link_cache = nl_cli_link_alloc_cache(sock);
    qdisc = nl_cli_qdisc_alloc();
    struct rtnl_tc *tc = (struct rtnl_tc *)qdisc;

    char str[16];
    strcpy(str, "inner0");
    nl_cli_tc_parse_dev(tc, link_cache, str);
    strcpy(str, "root");
    nl_cli_tc_parse_parent(tc, str);
    assert(rtnl_tc_set_kind(tc, "plug") == 0);
    assert(rtnl_qdisc_plug_set_limit(qdisc, 32 * 1024 * 1024) == 0);
    assert(rtnl_qdisc_plug_buffer(qdisc) == 0);
    replace_qdisc();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    puts("Qdisc plug has been set up");
    while (true) {
        using clock = std::chrono::steady_clock;

        usleep(interval * 1000);

        auto begin_ts = clock::now();
        assert(rtnl_qdisc_plug_buffer(qdisc) == 0);
        replace_qdisc();
        assert(rtnl_qdisc_plug_release_one(qdisc) == 0);
        replace_qdisc();
        auto end_ts = clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_ts - begin_ts).count();
        // printf("%ld μs\n", duration);
    }
}
