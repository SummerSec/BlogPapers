---
tags:
- blog-comments
---

# 把树莓派变成家里的透明代理旁路由：Mihomo + TPROXY + DHCP 接管踩坑记

一开始，这件事听起来很简单：家里所有连到华为 AX3 Pro 的设备，都能自动走代理，手机、电脑、平板不用一台台去填代理地址。

真正动手之后才发现，装 Clash 只是最容易的一步。后面等着我的是两个 DHCP 服务器互抢、客户端死守旧 IP、Docker 默认丢转发、同网段双网卡的 ARP 乱窜、IPv6 悄悄绕过代理，以及“服务显示 ACK 了但手机根本没用”的经典错觉。

这篇文章把最终的架构、关键配置和踩坑过程完整记一遍。具体节点名、订阅地址、控制器密钥和设备的 MAC 都做了脱敏，只保留可复现的思路。

## 一、目标与最终拓扑

目标很明确：

- 华为 AX3 Pro 继续做主路由，负责拨号、NAT 和 Wi-Fi；
- 树莓派 5 做旁路由，负责透明代理、DNS 和 DHCP；
- 所有设备连上 Wi-Fi 后自动拿到“网关 `192.168.3.27`、DNS `192.168.3.27`”，不需要手动设置；
- 出问题时能回滚，不能把家里的网搞成一次性工程。

最终拓扑大概是这样：

```text
Internet
   │
华为 AX3 Pro（192.168.3.1，关闭 DHCP 和 IPv6/RA）
   │ LAN
   ├── 树莓派 5 / sumpi
   │     ├── eth0 192.168.3.27（静态，网关/DNS 的唯一入口）
   │     ├── wlan0 192.168.3.25（仅管理，不参与转发）
   │     ├── Mihomo
   │     │     ├── mixed-port 7890
   │     │     ├── tproxy-port 7894
   │     │     └── DNS 127.0.0.1:1053
   │     ├── dnsmasq
   │     │     ├── 监听 192.168.3.27:53
   │     │     └── DHCP 下发网关/DNS 192.168.3.27
   │     └── nftables TPROXY + 策略路由
   └── 手机 / 电脑 / 平板
         └── 从树莓派 DHCP 获取地址，网关/DNS 指向 .27
```

树莓派本身不发射 Wi-Fi。设备还是连华为的 Wi-Fi，只是网关和 DNS 换成了树莓派；树莓派再把需要代理的流量接住，剩下交给 Mihomo 的规则决定直连还是走节点。

## 二、为什么不是“每台设备填代理”

最直接的做法是给每台设备手动填 HTTP/SOCKS 代理。但这样有几个问题：

- 手机、电视、平板、游戏机，并不是每台都能方便地设置代理；
- App 不一定会遵守系统代理，尤其是自己实现网络栈的应用；
- 设备一多，配置和维护成本会迅速失控。

旁路由的吸引力就在于：**设备什么都不用改，网关和 DNS 已经被 DHCP 指到树莓派**。

问题也在这里。华为 AX3 Pro 的 DHCP 不能自定义下发的网关地址，所以只能让树莓派接管 DHCP 和 DNS。于是整个工程从“装一个代理”变成了“在家庭网络里安全地替换掉一半的基础设施”。

## 三、组件和端口

这台树莓派 5 跑的是 Ubuntu，代理内核用 `clash-for-linux` 项目安装的 Mihomo。核心端口：

- `7890`：mixed 端口，HTTP/SOCKS 代理，方便本机调试；
- `7894`：TPROXY 端口，局域网客户端的透明流量从这里进入 Mihomo；
- `1053`：Mihomo 的本地 DNS，只监听 `127.0.0.1`；
- `9090`：external controller，面板和 API。

面板地址是：

```text
http://<树莓派地址>:9090/ui/
```

控制器密钥在运行时配置的 `secret:` 字段里。这个面板**只应该留在局域网**，不要做公网端口映射；它控制的是整条代理链路，不是普通网页。

本机可以先验证代理本身是否正常：

```bash
curl -x http://127.0.0.1:7890 -I https://www.google.com
curl -x http://192.168.3.27:7890 -I https://x.com
```

只要这一步不通，后面的 TPROXY、DHCP、IPv6 都先不用查。

## 四、TPROXY：不改应用，把流量送进代理

透明代理有几种常见做法：

- **HTTP 代理**：应用必须支持，覆盖不全；
- **REDIRECT/NAT**：改写目标地址，容易丢掉原始目标信息；
- **TUN**：新建虚拟网卡，接管路由，功能强但边界更大；
- **TPROXY**：保留原始目标地址，把匹配到的 TCP/UDP 透明地交给本地监听端口。

这套方案选的是 TPROXY。树莓派只处理从 `eth0` 进来的局域网流量，本机自己的流量不经过这条链路，避免代理把 Socks 出口又绕回自己。

核心 nftables 规则（脱敏）：

```nft
table ip sumpi_tproxy {
    set private4 {
        type ipv4_addr
        flags interval
        elements = {
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.168.0.0/16,
            224.0.0.0/4,
            240.0.0.0/4
        }
    }

    chain prerouting {
        type filter hook prerouting priority mangle
        policy accept

        # 局域网、回环、多播、链路本地不碰
        iifname "eth0" ip saddr 192.168.3.0/24 ip daddr @private4 return

        # DHCP 必须留给本地 dnsmasq
        iifname "eth0" udp dport 67 return

        # 其余局域网 TCP/UDP 全部交给 Mihomo
        iifname "eth0" ip saddr 192.168.3.0/24 \
            meta l4proto { tcp, udp } \
            tproxy to :7894 meta mark set 0x2333 counter
    }
}
```

注意 `198.18.0.0/15` 没有放进 `private4`。这是 Mihomo fake-IP 常用的地址段，必须让客户端的 fake-IP 连接进入 TPROXY，而不是被当成私有地址直连。

配套的策略路由：

```bash
ip rule add pref 100 fwmark 0x2333/0xffff lookup 233
ip route add local 0.0.0.0/0 dev lo table 233
```

这两条的意思是：被 nftables 打上 `0x2333` 标记的包，不再走正常路由，而是送到本机 `lo`，由监听 `7894` 的 Mihomo 接住。

这里我特意把它做成独立的 systemd oneshot 服务：启动时先做 preflight，确认表名、规则优先级和路由表都没被占用，再应用规则；停止时只删除自己创建的对象，不做全局 flush。这样即使重启失败，也不会误删别的网络配置。

## 五、DHCP/DNS 接管：让设备自动找到树莓派

dnsmasq 的配置骨架如下：

```ini
except-interface=wlan0
bind-dynamic
listen-address=192.168.3.27
port=53
no-resolv
no-poll
server=127.0.0.1#1053
cache-size=1000

# 迁移期把旧 DHCP 的地址范围也包进来
dhcp-range=192.168.3.2,192.168.3.254,255.255.255.0,1h
dhcp-option=3,192.168.3.27
dhcp-option=6,192.168.3.27
dhcp-authoritative
dhcp-leasefile=/var/lib/sumpi-gateway-dns/dnsmasq.leases

# 基础设施和固定设备单独保留
dhcp-host=<路由器 MAC>,192.168.3.1
dhcp-host=<树莓派 eth0 MAC>,192.168.3.27
dhcp-host=<树莓派 wlan0 MAC>,192.168.3.25
dhcp-host=<手机 MAC>,192.168.3.54
```

几个关键点：

- DNS 只转发给 `127.0.0.1#1053`，不要同时把 `192.168.3.1` 或 `/etc/resolv.conf` 加进上游，否则 fake-IP 和分流规则会被绕过；
- `except-interface=wlan0` 让 DHCP 只服务有线侧，避免树莓派自己的 Wi-Fi 接口也来抢；
- `dhcp-authoritative` 适合“只留一个 DHCP 服务器”的场景，但它会 NAK 掉不在池子里的地址请求，后面会看到它的副作用；
- 租约目录必须让 `dnsmasq` 用户可写，否则服务能启动，但租约永远写不进去。

在路由器侧，必须关闭 AX3 Pro 的 **DHCP 服务器** 和 **IPv6/RA**。这一步不是“点一下保存”就结束：我遇到过页面看起来已经关闭、设备端却还在拿 `.1` 网关的情况。保存后要刷新页面确认状态，必要时重启路由器，再用客户端实际拿到的网关/DNS 验证。

## 六、踩坑一：两个 DHCP 服务器互抢

这是整次排障里最隐蔽、也最伤的一个问题。

现象：

- 手机在 `.50` 和 `.53` 之间来回跳；
- 有时能上网，有时 x.com/Google 又打不开；
- Pi 的 dnsmasq 日志里反复出现：

```text
DHCPREQUEST 192.168.3.53
DHCPNAK 192.168.3.53 address not available
DHCPREQUEST 192.168.3.50
DHCPNAK 192.168.3.50 wrong server-ID
```

抓包之后才看明白：华为的 DHCP 其实还在工作。它和树莓派的 dnsmasq 各自给手机发租约，又各自 NAK 对方的租约；手机在两个服务器之间被来回拉扯。树莓派开了 `dhcp-authoritative` 之后，这种情况会更严重，因为它会把别人发的租约也当成“地址不可用”直接 NAK。

抓 DHCP 包的命脉命令：

```bash
sudo tcpdump -i eth0 -n -e -vv 'udp port 67 or udp port 68'
```

重点看三个字段：

- `DHCP-Message`：Discover / Offer / Request / ACK / NAK；
- `Server-ID`：这个回复到底来自哪个 DHCP 服务器；
- `Requested-IP`：客户端坚持要哪个地址。

只要看到两个不同的 `Server-ID` 在同一个交换里出现，就不用再猜了：先保证**全网只有一个 DHCP 服务器**。

最终的结论很朴素：不是 TPROXY 的错，也不是 mihomo 的错，是网络里有两个“权威”在发地址。

## 七、踩坑二：DHCP 池不覆盖旧租约

第二个坑紧跟着来。

为了让客户端换到树莓派，我一开始把池子设为 `192.168.3.100-199`。但家里设备之前的地址是华为 DHCP 发的，比如 `.53`、`.34`，客户端重启网络后会先尝试**续租自己记得的旧地址**（INIT-REBOOT），直接发 `DHCPREQUEST` 给旧地址。

树莓派的池子不包含这些地址，于是回 NAK。理想情况下，客户端收到 NAK 后会重新 DISCOVER，拿一个新地址；但现实里，有些手机和 IoT 设备会在“请求旧地址 → 被 NAK → 再 DISCOVER → 又请求旧地址”之间循环，迟迟不肯接受新地址。

解决方式不是继续跟客户端较劲，而是把池子改成**迁移友好**的范围：

```ini
dhcp-range=192.168.3.2,192.168.3.254,255.255.255.0,1h
```

同时把基础设施地址单独保留：

- `.1`：路由器；
- `.25`：树莓派 wlan0 管理地址；
- `.27`：树莓派 eth0 网关地址；
- `.54`：手机固定地址；
- 其他需要固定 IP 的设备，用 `dhcp-host` 预留。

这样客户端申请旧地址时，只要在池子里且没被占用，就能直接 ACK；它会保留原来的 IP，同时从 ACK 里拿到新的网关/DNS `.27`。整个过程对用户几乎没有感知，也不需要逐台设备改配置。

当然，池子开大之后要小心静态地址冲突。路由器、树莓派、NAS、打印机这类设备，最好都显式加 `dhcp-host` 保留。

## 八、踩坑三：`dhcp-broadcast` 反而让鸿蒙忽略 OFFER

在还没发现“两个 DHCP 服务器互抢”之前，我一度以为是 OFFER 没有送到手机，于是给 dnsmasq 加了：

```ini
dhcp-broadcast
```

它的作用是强制 DHCP 回复使用广播。对某些跨网桥、跨 VLAN 的场景确实有用，但在这台鸿蒙手机上，结果很反直觉：手机仍然只发 DISCOVER，不进入 REQUEST。抓包看，Pi 的 OFFER 已经发出去了，手机就是不接。

后来把华为 DHCP 彻底关掉、并且去掉 `dhcp-broadcast` 之后，dnsmasq 回到默认行为：客户端没设置广播标志就发单播 OFFER，手机才正常走完 `REQUEST → ACK`。

这件事的教训是：**不要在没定位根因之前叠加“看起来有用”的兼容选项**。`dhcp-broadcast` 没有错，它只是被用在了错误的阶段。等网络里只剩一个 DHCP 服务器后，默认行为往往就是最兼容的。

## 九、踩坑四：Docker 的 `FORWARD` 默认 DROP

透明代理跑通之后，一个新的问题出现了：走代理的网站正常，但局域网内的一些直连流量会断。

原因是树莓派上装了 Docker。Docker 会把 iptables 的 `FORWARD` 链策略设成 `DROP`，只给自己需要的流量开口子：

```text
-P FORWARD DROP
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
```

TPROXY 把代理流量重定向到了本机，不经过 `FORWARD`；但被 `private4` 排除的局域网流量（比如访问 `.1` 或其他内网设备）仍然要转发，就会被这条默认策略丢掉。

修复方式不是把全局策略改成 `ACCEPT`，而是只给有线局域网加一条明确规则：

```bash
iptables -I FORWARD 1 \
  -i eth0 -o eth0 -s 192.168.3.0/24 \
  -j ACCEPT
```

这条规则只放行 `eth0` 进、`eth0` 出的局域网流量，不影响 Docker 自己的隔离。它被写进了 netfilter 的 apply 脚本，服务和回滚脚本都会管理它。

## 十、踩坑五：同网段双网卡与 ARP flux

树莓派有两个接口：

- `eth0`：`192.168.3.27`，有线网关；
- `wlan0`：`192.168.3.25`，Wi-Fi 管理。

它们恰好在同一个 `/24` 里。Linux 默认的 ARP 行为（`arp_ignore=0`）允许它从任意接口回答本机地址的 ARP 请求。也就是说，客户端问“谁是 `192.168.3.27`”，树莓派可能从 `wlan0` 回一个 ARP，客户端就把网关解析到 `wlan0` 的 MAC。

后果很隐蔽：流量从 `wlan0` 进来，而 TPROXY 规则只匹配 `iifname "eth0"`，于是这部分流量绕过代理，接着又被 `FORWARD` 策略丢掉，表现就是“有时能上、有时不能上”。

修复：

```ini
# /etc/sysctl.d/90-sumpi-gateway.conf
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.eth0.arp_ignore=1
net.ipv4.conf.eth0.arp_announce=2
net.ipv4.conf.wlan0.arp_ignore=1
net.ipv4.conf.wlan0.arp_announce=2

# 顺手关掉 ICMP redirect，避免客户端被教着绕过网关
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.eth0.send_redirects=0
net.ipv4.conf.wlan0.send_redirects=0
```

`arp_ignore=1` 的含义是：只回答“请求的地址确实配在收到请求的那个接口上”的 ARP。这样 `.27` 只会在 `eth0` 上被回答，`.25` 只会在 `wlan0` 上被回答，客户端不会再把网关解析到错误的接口。

如果不需要 Wi-Fi 管理，最彻底的办法是把 `wlan0` 关掉，或者把它放到另一个网段。保留同网段管理地址时，上面这组 sysctl 基本是必需项。

## 十一、踩坑六：IPv6 绕过 TPROXY

这是整次排障里最容易被忽略的一层。

这套 TPROXY 只处理 IPv4。只要客户端还能拿到一个全局 IPv6 地址，而目标站点又有 AAAA 记录，它就可能直接走 IPv6 出去，完全不经过树莓派。

几个容易误判的点：

- Mihomo 的 `dns.ipv6: false` 只影响**发到 Pi 的 DNS 查询**，不代表客户端没有别的 IPv6 来源；
- 路由器通过 RA/RDNSS 下发的 IPv6 地址和 DNS，手机可能优先使用；
- 手机开启 Private DNS/DoH 时，也可能绕过 Pi 的 DNS，拿到 AAAA；
- 部分 App 甚至会走移动数据，连 Wi-Fi 网关都不看一眼。

这次的症状是：Pi 上能看到手机大量的国内 IPv4 流量在走代理，但 x.com/Google **一个 IPv4 连接都没有**；手机 Wi-Fi 详情里有一个 `2409:` 开头的全局 IPv6 地址。关掉路由器的 IPv6/RA、重新连接手机之后，IPv6 只剩 `fe80:`，问题才彻底消失。

所以排查顺序应该是：

1. 看客户端 Wi-Fi 详情里有没有全局 IPv6；
2. 看路由器 IPv6/RA 是否真的关闭；
3. 看客户端是否开了 Private DNS、VPN、加速器；
4. 再看移动数据是否在分流部分 App。

如果路由器无法关闭 IPv6，那就要么让 Pi 接管 IPv6（RA + IPv6 TPROXY，工作量大得多），要么在客户端侧限制 IPv6。只靠 `dns.ipv6: false` 是不够的。

## 十二、踩坑七：DHCP ACK 了，不代表客户端用了

有一个瞬间很容易让人误判：Pi 的日志明确显示：

```text
DHCPREQUEST 192.168.3.53 <手机 MAC>
DHCPACK 192.168.3.53 <手机 MAC>
```

租约文件也写进去了，但手机的 Wi-Fi 详情里网关和 DNS 仍然是 `.1`，x.com 还是打不开。

原因不在 DHCP 服务器，而在客户端：

- 手机可能还保留着旧的静态配置；
- 手机的 DHCP 客户端可能拿到了 ACK，但界面/系统没有把网关/DNS 应用到这个网络；
- 手机可能还有其他接口（热点、信号桥）在用另一套网络配置；
- 或者路由器 DHCP 其实没关干净，手机又拿到了 `.1` 的租约。

最后的排查方法很土但有效：**直接看客户端 Wi-Fi 详情里的 IP / 网关 / DNS / IPv6**，不要只看 Pi 的 ACK。Pi 的租约文件证明“服务器发出了什么”，客户端详情证明“客户端实际用了什么”，这两件事必须分开验证。

这次手机坚持保留旧地址 `.53`，我们最终把 Pi 的租约固定成 `.54`，并在手机上设置静态 `.54` + 网关/DNS `.27`，才把状态稳定下来。IP 数值没变并不代表失败——固定租约本来就会让它保持同一个地址。

## 十三、自动切换最优新加坡节点

代理链路稳定之后，新的需求是：国外流量不要死绑一个节点，节点变慢或挂掉时自动换。

Mihomo 的 `url-test` 组适合做这件事。原来 `🔰国外流量` 是一个 `select` 组，手动选了一个新加坡节点；我加了一个只包含新加坡节点的自动组：

```yaml
proxy-groups:
  - name: "♻️新加坡自动"
    type: url-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    lazy: true
    expected-status: 204
    proxies:
      - "<SG-01>"
      - "<SG-02>"
      - "<SG-03>"
```

然后把 `♻️新加坡自动` 放到 `🔰国外流量` 的选择列表里，并设为默认：

```text
🔰国外流量 → ♻️新加坡自动 → <当前最优的新加坡节点>
```

`url-test` 会定期请求 `generate_204`，按延迟和可用性选一个节点。几个参数的含义：

- `interval: 300`：每 5 分钟测一次；
- `tolerance: 50`：延迟差小于 50ms 时不来回切，避免抖动；
- `lazy: true`：没有使用时不必持续测速；
- `expected-status: 204`：只有返回 204 才算健康。

如果没有显式列出节点，也可以用 `include-all-proxies: true` 加 `filter` 做批量筛选。但要注意：

- 不要把“直连”类节点放进自动组，否则可能选中一个不代理的出口；
- 订阅更新/运行时配置重新生成时，这个手动加的组可能会被覆盖，最好保留配置文件备份；
- 自动组解决的是“节点选择和故障切换”，不改变规则分流本身。

验证方法是在面板或 `/connections` API 里看连接链，正常应该类似：

```text
[<当前新加坡节点>, ♻️新加坡自动, 🔰国外流量]
```

如果链里只有具体节点、没有自动组，说明选择器还停在手动节点上。

## 十四、验证清单

这套东西涉及 DNS、DHCP、路由、防火墙和客户端五层，出问题时不要凭感觉，按层验证：

**服务层**

```bash
systemctl is-active clash-for-linux sumpi-dns sumpi-gateway-netfilter
systemctl is-enabled clash-for-linux sumpi-dns sumpi-gateway-netfilter
```

**TPROXY 层**

```bash
ip rule
ip route show table 233
nft list table ip sumpi_tproxy
iptables -S FORWARD | head
```

**DNS 层**

```bash
dig @192.168.3.27 www.google.com
dig @192.168.3.27 AAAA x.com
dig @127.0.0.1 -p 1053 www.google.com
```

**代理层**

```bash
curl -x http://192.168.3.27:7890 -I https://www.google.com
curl -x http://192.168.3.27:7890 -I https://x.com
```

**透明转发层**

可以建一个临时的 network namespace + veth，模拟一个局域网客户端，给它一个假 IP 和默认路由，再用独立的 nft 规则把流量 tproxy 到 Mihomo，最后用 `curl --resolve` 访问 fake-IP，不设置任何代理变量，期望返回 204。这个测试能证明“客户端 → TPROXY → Mihomo”这条链路是通的，而不只是 HTTP 代理端口能连。

**客户端层**

- Wi-Fi 详情里网关/DNS 是否为 `192.168.3.27`；
- IPv6 是否只剩 `fe80:`；
- 是否能直接打开 `https://www.google.com` 和 `https://x.com`；
- 出问题时在 Pi 上抓 `tcpdump`，看客户端到底有没有把包发过来、DNS 发给了谁。

## 十五、回滚与维护

旁路由最怕的是“改完自己都回不去”。这套方案从一开始就准备了回滚：

```bash
sudo /usr/local/libexec/sumpi-gateway-rollback --confirm
```

回滚脚本会恢复安装时的文件备份，停止 dnsmasq/netfilter，并删除自己创建的 nft 表、策略路由和 FORWARD 规则。之后需要回到 AX3 Pro 管理页，重新打开 DHCP 和 IPv6。

日常维护要注意：

- 路由器重启后，确认 DHCP 和 IPv6 没有自己变回开启；
- 修改运行时配置前先备份，订阅更新可能覆盖 `config.yaml`；
- 重启 `clash-for-linux` 会连带重启 `sumpi-gateway-netfilter`，重启后检查 TPROXY 和 FORWARD 是否都在；
- systemd `ExecStart` 指向的脚本必须可执行。曾经因为把脚本改成 `0644`，服务报 `203/EXEC`，表现为“配置全对但 netfilter 起不来”；
- 控制面板和 `secret` 不要暴露到公网，也不要把订阅地址、节点密钥写进博客或提交到仓库。

## 十六、经验总结

如果只让我留下几条结论，会是这些：

1. **全网只能有一个 DHCP 服务器。** 两个 authoritative DHCP 互抢，会让整个网络表现出随机、间歇性的故障，非常难查。
2. **DHCP ACK 不等于客户端采用了租约。** 服务器日志和客户端 Wi-Fi 详情必须分开验证。
3. **迁移期要让 DHCP 池覆盖旧租约。** 否则客户端会死守旧 IP，在 NAK 和 DISCOVER 之间循环。
4. **`dhcp-authoritative` 是双刃剑。** 只有一个 DHCP 服务器时很好用，有第二个服务器时会把问题放大。
5. **先在包层面定位，再加兼容选项。** `dhcp-broadcast` 这种“看起来有用”的开关，在错误阶段只会让现象更迷惑。
6. **TPROXY 只处理它匹配到的地址族和接口。** IPv6、`wlan0`、本机流量，都可能绕过你以为已经覆盖的规则。
7. **Docker 的 `FORWARD DROP` 会咬人。** 加一条窄的 accept，不要动全局策略。
8. **同网段双网卡要收敛 ARP。** `arp_ignore=1`、`arp_announce=2`，必要时加 `send_redirects=0`。
9. **保留回滚路径和配置备份。** 旁路由不是一次性脚本，路由器固件更新、订阅更新、系统重启都会改变状态。
10. **节点自动切换和流量分流是两件事。** `url-test` 解决“选哪个节点”，规则解决“哪些流量走代理”。

最后，这套方案有一个前提：主路由器必须能关闭 DHCP 和 IPv6/RA。如果路由器不允许关闭 DHCP，那“接管 DHCP”这条路走不通，需要换方案，比如让树莓派做主路由/AP，或者用 ARP 方式接管网关。先把前提确认清楚，比后面抓十次包都省事。
