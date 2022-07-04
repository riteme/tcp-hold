#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static inline int parse_header(struct tcphdr **out_tcp, struct bpf_sock_tuple *out_tuple, struct __sk_buff *skb) {
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
    if (out_tuple) {
        out_tuple->ipv4.saddr = ip->saddr;
        out_tuple->ipv4.sport = tcp->source;
        out_tuple->ipv4.daddr = ip->daddr;
        out_tuple->ipv4.dport = tcp->dest;
    }
    return 0;
}

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32);
} syn_map;

SEC("tc")
int ingress_main(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct bpf_sock_tuple tuple = {0};
    if ((parse_header(&tcp, &tuple, skb) < 0) ||
        !(tcp->syn && tcp->ack))
        goto out;

    __u32 v = bpf_ntohl(tcp->seq);
    bpf_map_update_elem(&syn_map, &tuple, &v, BPF_ANY);

out:
    return TC_ACT_OK;
}

SEC("tc")
int egress_main(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

SEC("license")
char LICENSE[] = "GPL";
