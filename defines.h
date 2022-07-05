#pragma once

#include <linux/types.h>

struct tcp_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};
