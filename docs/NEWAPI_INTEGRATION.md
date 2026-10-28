# Aloha VPN → new-api 代理池 对接说明

> 状态：**未交付可用代理池**。本文件说明"已经能拿到的"和"还差什么"，避免后续会话重复踩坑。

---

## 0. 一句话结论

节点清单能白嫖（无鉴权、169 个 IP、含 REALITY 公钥），但 **VLESS 的 UUID / Shadowsocks 的密码拿不到**，
所以现在往 new-api 里塞任何东西都是死链。**先别接**。

---

## 1. 现在已经能拿到什么

`harvest_aloha.py` 一条命令：

```powershell
python harvest_aloha.py
# -> aloha_vpnlist_raw.json  80 分组 / 514 条 / 505 端点 / 169 IP + REALITY options
# -> aloha_ips.txt           纯 IP 清单
# -> aloha_vpnconfig.json    功能配置(测速域名/TTL/开关)
```

这些 IP **确实在线**（第一轮压测：443 有 87/169 通、990 有 85/169 通、83 个 443 TLSv1.3 握手成功），
但**通了也没有意义** —— 协议握手要凭证。

---

## 2. 缺的那块：凭证

| 协议 | 还缺 | 在哪 |
|---|---|---|
| vless (443, REALITY) | `id`(UUID) + 可能还有 `shortId` | 运行期 Java 算出来拼进 xray JSON |
| shadowsocks (990) | `password`（method=`chacha20-ietf-poly1305` 已知） | 同上 |
| ipsec | 用户名/密码 或 用户证书 | strongSwan profile，同样被加密 |

`options.vless` 里**公开的部分**（公钥/SNI/flow/network/encryption）已经有了，
差的只有客户端 id —— 也就是"这口井的钥匙"。

---

## 3. 打通步骤（有真机就能收口）

```powershell
# 前置: 真 arm64 安卓机 + root + arm64 frida-server + adb 连接(替换 emulator-5554)
# 1. 装包、点过隐私/欢迎弹窗、停在主界面
# 2. 抓内存里的 xray JSON（"id":" 命中即凭证）
python hooks/scan4.py
# 3. 或在 :xray 子进程 fork 瞬间挂 hook，直接打印 runXrayFromJSON 的入参
python hooks/drive6.py
```

拿到 JSON 后，凭证位置长这样（xray 标准结构）：

```json
{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,
  "users":[{"id":"<UUID>","flow":"xtls-rprx-vision","encryption":"none"}]}]},
  "streamSettings":{"security":"reality","realitySettings":{
    "serverName":"www.cloudflare.com","publicKey":"ze-5m3DGNZ7d2d_K7L8X2RIerzfCTK6By2mtA5clLxI",
    "shortId":"<可能为空>","fingerprint":"chrome"},"network":"tcp"}}]}
```

---

## 4. 拿到凭证后的接法（两条路，按投入排序）

### 路径 A（推荐，和 supervpn/quixsocks 一致的思路）：xray 实例池 → 本地 SOCKS5 → new-api 共享代理池

```
[aloha 节点清单] --定时--> [存活探测] --健康节点--> [xray 实例池]
                                                    每实例一个 socks5 inbound
                                                    (127.0.0.1:45000+n)
                                                          |
                                              new-api 渠道出站代理(共享代理池)
```

- 一个 xray 进程可挂多个 inbound+outbound，或用 sing-box 的 `urltest`/`selector` 做组内自动切换。
- 出口健康判定必须**看真实出口 IP**（`https://api.ipify.org`）而不是端口通，否则会把"端口开着但隧道死"的节点当成活节点。
- new-api 侧只需 `socks5://127.0.0.1:450xx`，和现有代理池清单文件可以走同一套多文件加载机制。

### 路径 B（轻量，但只能做节点源）：把 vpnlist 当"节点发现源"

只接清单、不接流量 —— 用来做**节点库存监控**（哪些地区新增/下线、REALITY 公钥是否轮换）。
REALITY 公钥轮换是很实际的运维信号：公钥一换，所有本地 xray 配置立刻全废。

---

## 5. 红线

- 节点是 **Aloha 运营方自有 VPS**。技术上能连 ≠ 有权长期占用。**不建议进生产池**。
- 别把 `options.dynamo{salt,chronos}` 当密钥用 —— 实测 Go 内核里根本没有 `dynamo`/`chronos` 符号，它是纯配置字段。
- 别再用 `platform=android` 之外的猜参数去试 `vpnconfig`：必需参数是 **`os=android`**。

---

## 6. 与其它 VPN 项目的差异（给后续会话省时间）

| 项目 | 凭证来源 | 本项目的不同 |
|---|---|---|
| eEagle | 硬编码 `x-api-key` + 任意 UUID | 这里没有硬编码 key，反而 Java 全加密 |
| SuperVPN Pro | DES 信封 + md5 规则可完全复现 | 这里规则在加密代码里 |
| Privify | RemoteConfig 下发三要素 + PBKDF2 | 这里下发的是公开发布参数，缺私有 id |
| QuixVPN / Indonesia | 配置直接吐节点 | 这里吐节点但**不给钥匙** |

**这一类"清单公开、钥匙加密"的形态是 Aloha 独有的**，后面遇到同类（DexProtector + 自有 xray 内核 + vpnlist/vpnconfig 双端点）可以直接按本报告第 3 节定位。
