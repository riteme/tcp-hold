#include "vmlinux.h"
#include "tc_act.h"
#include <bpf/bpf_helpers.h>

int mode;

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, u64);
} count_map;

SEC("tc")
int tc_main(struct __sk_buff *skb) {
    u64 *vp = bpf_map_lookup_elem(&count_map, &mode);
    u64 v = vp ? *vp + 1 : 1;
    bpf_map_update_elem(&count_map, &mode, &v, BPF_ANY);

    if (mode == 0)
        return TC_ACT_OK;
    if (mode == 1)
        return TC_ACT_SHOT;
    return TC_ACT_STOLEN;
}

SEC("license")
char LICENSE[] = "GPL";
