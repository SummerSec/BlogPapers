# `sumpi-mihomo-side-router` 配图 Prompt 清单

本文正文使用的四张配图均为 16:9 横版，最终文件尺寸均为 `1672×941`。每张图均使用内置 `image_gen` 单独生成或编辑，并参考同一人物模板：`writing-zh:sumsec-illustrations` v1.0.47 的 `assets/sumsec-observer-target.png`。

实际 prompt 原文保存在同目录的文本文件中；本清单只记录用途、正文落点、采用版本和生成方式，不重复 prompt 内容。

| 编号 | Prompt 原文 | 用途与正文落点 | 最终文件 | 生成方式 |
| --- | --- | --- | --- | --- |
| 01 | [01-prompt.txt](./01-prompt.txt) | 解释华为普通/备用 SSID 与旁路由 SSID 的手动切换；放在第二节双 SSID 故障切换段后 | `01-dual-wifi-fallback-v2.png` | 内置 `image_gen` 初次生成后按编辑 prompt 采用 v2；网关/DNS 按客户端保存和手动切换，不表示按频段自动分配 |
| 02 | [02-prompt.txt](./02-prompt.txt) | 解释 TPROXY 保留原目标并交给 Mihomo 按规则选择直连/代理；放在第四节 TPROXY 机制说明后 | `02-tproxy-transparent-routing.png` | 内置 `image_gen` 单张生成/重生成 |
| 03 | [03-prompt.txt](./03-prompt.txt) | 解释同网段双网卡 IPv4 回程排障与链路本地 IPv6 管理救援；放在第十节失联复盘末尾 | `03-dual-nic-ipv6-rescue-v2.png` | 内置 `image_gen` 初次生成后按编辑 prompt 采用 v2；`fe80::` 只用于同链路 SSH 救援管理，不提供备用上网 |
| 04 | [04-prompt.txt](./04-prompt.txt) | 解释 systemd `active` 不等于端口监听；放在第十四节服务层验证代码块后 | `04-active-versus-listening.png` | 内置 `image_gen` 单张生成 |

`01-dual-wifi-fallback.png` 和 `03-dual-nic-ipv6-rescue.png` 是未采用的初稿，保留在资产目录中作追溯，但正文不引用；正文只引用对应的 v2 文件。生成过程中的原始文件仍由工具保留，不在仓库内创建备份。
