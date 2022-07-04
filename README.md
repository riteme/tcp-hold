## Notes

- WLAN packet

https://wiki.wireshark.org/CaptureSetup/WLAN

> Link-Layer (Radio) packet headers
>
> 802.11 adapters often transform 802.11 data packets into fake Ethernet packets before supplying them to the host, and, even if they don't, the drivers for the adapters often do so before supplying the packets to the operating system's networking stack and packet capture mechanism.
>
> This means that if you capture on an 802.11 network, the packets will look like Ethernet packets, and you won't be able to see all the fields in the 802.11 header.
>
> On some platforms, you can request that 802.11 headers be supplied when capturing, at least with some 802.11 adapters, regardless of whether you capture in monitor mode, sometimes called "rfmon mode" (see below); on some other platforms, you will get 802.11 headers in monitor mode, and only in monitor mode.

- libbpf tc 支持

https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/

- 在新的 netns 内无法使用 `ping`，`ping` 没有任何输出就退出

没有输出是因为没有使用 `-v` 参数。

无法使用 `ping` 是因为没有权限。新 netns 内 `net.ipv4.ping_group_range` 没有被正确设置。参见：

https://fedoraproject.org/wiki/Changes/EnableSysctlPingGroupRange

https://unix.stackexchange.com/questions/608866/ping-inside-netns-requires-sudo-fedora

- IPTables

https://www.booleanworld.com/depth-guide-iptables-linux-firewall/

- qdisc plug

https://github.com/thom311/libnl/blob/main/lib/cli/qdisc/plug.c

```python
import os
import time

while True:
    os.system('nl-qdisc-add --dev=inner0 --parent=root --update plug --buffer')
    os.system('nl-qdisc-add --dev=inner0 --parent=root --update plug --release-one')
    time.sleep(1)
```
