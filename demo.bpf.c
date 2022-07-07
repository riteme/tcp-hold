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

static inline int parse_header(
    struct tcphdr **out_tcp,
    struct tcp_key *out_key,
    __u32 *out_payload_size,
    struct __sk_buff *skb
) {
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
    if (out_payload_size)
        *out_payload_size = bpf_ntohs(ip->tot_len) - (ip->ihl + tcp->doff) * sizeof(__u32);
    return 0;
}

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TCP_MAP_SIZE * 2);  // To record sequence numbers for both direction
    __type(key, struct tcp_key);
    __type(value, __u32);
} syn_map;

__u32 last_seq[TCP_MAP_SIZE];
__u32 last_ack[TCP_MAP_SIZE];
__u32 curr_ack[TCP_MAP_SIZE];

SEC("tc")
int ingress_main(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct tcp_key key = {0};
    if (parse_header(&tcp, &key, NULL, skb) < 0)
        goto out;

    if (tcp->syn) {
        __u32 v = bpf_ntohl(tcp->seq);
        bpf_map_update_elem(&syn_map, &key, &v, BPF_ANY);
    }

out:
    return TC_ACT_OK;
}

static inline int seq_num_less(__u32 a, __u32 b) {
    return b - a < (1u << 31);
}

SEC("tc")
int egress_main(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct tcp_key key;
    __u32 payload_size;
    if (parse_header(&tcp, &key, &payload_size, skb) < 0)
        goto out;

    if (tcp->syn) {
        __u32 v = bpf_ntohl(tcp->seq);
        bpf_map_update_elem(&syn_map, &key, &v, BPF_ANY);
    }

    __u32 i = ~skb->mark;
    if (i >= TCP_MAP_SIZE)
        goto out;

    __u32 curr_seq = bpf_ntohl(tcp->seq);
    __u32 next_seq = curr_seq + payload_size;
    int is_keepalive = (payload_size == 0 && curr_seq == last_seq[i] - 1);

    if (tcp->ack) {
        __u32 ack_seq = curr_ack[i];
        if (ack_seq != last_ack[i])
            last_ack[i] = ack_seq;
        else if (payload_size == 0)
            return TC_ACT_SHOT;

        __u32 off = (__u32)(__u64)tcp - skb->data;
        __u32 value = bpf_htonl(ack_seq);
        bpf_skb_store_bytes(
            skb, off + offsetof(struct tcphdr, ack_seq), &value, sizeof(value), BPF_F_RECOMPUTE_CSUM
        );

        if (is_keepalive) {
            value = bpf_htonl(last_seq[i]);
            bpf_skb_store_bytes(
                skb, off + offsetof(struct tcphdr, seq), &value, sizeof(value), BPF_F_RECOMPUTE_CSUM
            );
        }
    }

    if (seq_num_less(last_seq[i], next_seq))
        last_seq[i] = next_seq;

out:
    return TC_ACT_OK;
}

SEC("license")
char LICENSE[] = "GPL";
