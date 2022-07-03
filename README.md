## Notes

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
