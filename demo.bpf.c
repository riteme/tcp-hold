#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "defines.h"

#define TCP_MAP_SIZE 1024

static inline int parse_header(struct tcphdr **out_tcp, struct tcp_key *out_key, struct __sk_buff *skb) {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 len = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);

    void *data = (void *)(__u64)skb->data;
    void *end = (void *)(__u64)skb->data_end;
    if ((len > skb->len) ||
        (data + len > end && bpf_skb_pull_data(skb, len) < 0))
        return -EINVAL;
    data = (void *)(__u64)skb->data;
    end = (void *)(__u64)skb->data_end;
    if (data + len > end)
        return -EINVAL;

    eth = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -EINVAL;
    ip = data + sizeof(*eth);
    if (ip->protocol != IPPROTO_TCP)
        return -EINVAL;
    tcp = data + sizeof(*eth) + sizeof(*ip);

    if (out_tcp)
        *out_tcp = tcp;
    if (out_key) {
        out_key->saddr = ip->saddr;
        out_key->sport = tcp->source;
        out_key->daddr = ip->daddr;
        out_key->dport = tcp->dest;
    }
    return 0;
}

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TCP_MAP_SIZE * 2);  // To record sequence numbers for both direction
    __type(key, struct tcp_key);
    __type(value, __u32);
} syn_map;

SEC("tc")
int ingress_main(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct tcp_key key = {0};
    if (parse_header(&tcp, &key, skb) < 0)
        goto out;

    if (tcp->syn) {
        __u32 v = bpf_ntohl(tcp->seq);
        bpf_map_update_elem(&syn_map, &key, &v, BPF_ANY);
    }

out:
    return TC_ACT_OK;
}

__u32 ack_map[TCP_MAP_SIZE];

SEC("tc")
int egress_main(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct tcp_key key = {0};
    if (parse_header(&tcp, &key, skb) < 0)
        goto out;

    if (tcp->syn) {
        __u32 v = bpf_ntohl(tcp->seq);
        bpf_map_update_elem(&syn_map, &key, &v, BPF_ANY);
    }

    __u32 index = ~skb->mark;
    if (tcp->ack && index < TCP_MAP_SIZE) {
        __u32 ack_seq = ack_map[index];
        __u32 offset = (__u32)(__u64)tcp - skb->data + offsetof(struct tcphdr, ack_seq);
        __u32 value = bpf_htonl(ack_seq);
        bpf_skb_store_bytes(skb, offset, &value, sizeof(value), BPF_F_RECOMPUTE_CSUM);
    }

out:
    return TC_ACT_OK;
}

SEC("license")
char LICENSE[] = "GPL";
