#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

int mode;

SEC("tc")
int tc_main(struct __sk_buff *skb) {
    if (mode == 0)
        return TC_ACT_OK;
    if (mode == 1)
        return TC_ACT_SHOT;
    return TC_ACT_STOLEN;
}

SEC("license")
char LICENSE[] = "GPL";
