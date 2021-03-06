## Prerequisites

- Linux kernel 5.18.6
- libbpf 0.8.0
- libnl 3.6.0
- clang 13.0.1

## Run

Server:

```bash
make demo-nobpf
export COUNT=60
./demo-nobpf server 32 ping 16 0.0.0.0:23324
```

Client:

```bash
sudo ./net-up.sh
sudo ip netns exec ns0 sudo -u $(whoami) bash
make demo
export COUNT=60
sudo -E ./demo client 32 echo 16 192.168.100.100:23324
```

See `demo.cpp` and `demo.bpf.c`.

## TODO

- [ ] Request latency
- [ ] Request throughput
- [ ] Stream throughput (and deviation)
- [ ] #TCP-retransmission
- [ ] Syscall latency
- [ ] CPU usage

## Notes

- ACK thinning

<https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.526.8062&rep=rep1&type=pdf>

- 如何主动触发 ack？

1. 利用退出 `TCP_REPAIR` 模式的 `tcp_send_window_probe`：<https://elixir.bootlin.com/linux/v5.18.9/source/net/ipv4/tcp.c#L3506>
2. 利用 BPF helper：`bpf_tcp_send_ack`

主要问题在于 BPF 程序是事件触发的

- `BPF_PROG_TYPE_SOCK_OPS`

<https://lwn.net/Articles/727189/>

<https://arthurchiao.art/blog/bpf-advanced-notes-1-zh/#2-bpf_prog_type_sock_ops>

- TCP timed-wait && SIGPIPE

设置 `SO_LINGER` 可以强制发送 `RST` 而不是常规的 `FIN`，避免 TCP 连接进入 timed-wait 状态。

当 socket 被关闭后，`write`/`send` 会触发 `SIGPIPE` 信号。忽略即可。

- `bpf_map_update_elem` sometimes returns `-EBUSY`

不知道原因，但貌似重试一下就好了。

- WLAN packet

<https://wiki.wireshark.org/CaptureSetup/WLAN>

> Link-Layer (Radio) packet headers
>
> 802.11 adapters often transform 802.11 data packets into fake Ethernet packets before supplying them to the host, and, even if they don't, the drivers for the adapters often do so before supplying the packets to the operating system's networking stack and packet capture mechanism.
>
> This means that if you capture on an 802.11 network, the packets will look like Ethernet packets, and you won't be able to see all the fields in the 802.11 header.
>
> On some platforms, you can request that 802.11 headers be supplied when capturing, at least with some 802.11 adapters, regardless of whether you capture in monitor mode, sometimes called "rfmon mode" (see below); on some other platforms, you will get 802.11 headers in monitor mode, and only in monitor mode.

- libbpf tc 支持

<https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/>

- 在新的 netns 内无法使用 `ping`，`ping` 没有任何输出就退出

没有输出是因为没有使用 `-v` 参数。

无法使用 `ping` 是因为没有权限。新 netns 内 `net.ipv4.ping_group_range` 没有被正确设置。参见：

<https://fedoraproject.org/wiki/Changes/EnableSysctlPingGroupRange>

<https://unix.stackexchange.com/questions/608866/ping-inside-netns-requires-sudo-fedora>

- IPTables

<https://www.booleanworld.com/depth-guide-iptables-linux-firewall/>

- qdisc plug

<https://github.com/thom311/libnl/blob/main/lib/cli/qdisc/plug.c>

```python
import os
import time

while True:
    os.system('nl-qdisc-add --dev=inner0 --parent=root --update plug --buffer')
    os.system('nl-qdisc-add --dev=inner0 --parent=root --update plug --release-one')
    time.sleep(1)
```
