# Aloha VPN 2.8.0 — APK 逆向研究

> `com.alohamobile.vpn` v2.8.0（Modded by ElaMods 二次重打包）
> SHA-256 `ca81ffc2abc4d88467e19047539e7494d77e2f8fb392dc689de68ea9e6f56c5a` · 56.8 MB
> 分析日期 2026-10-28 · Android 安全研究 / 互操作性研究

![status](https://img.shields.io/badge/节点清单API-已打通-3fb950)
![status](https://img.shields.io/badge/REALITY参数-已获取-3fb950)
![status](https://img.shields.io/badge/客户端凭证-受阻-d29922)
![status](https://img.shields.io/badge/代理池-不可用-f85149)

---

## 这是什么

对 **Aloha VPN（Aloha Browser 的 VPN 独立版）** 的静态 + 动态逆向记录。

结论先行：**节点清单可以无鉴权公开拉取（169 个 IP / 505 个端点 / REALITY 公钥），
但客户端凭证（VLESS UUID、Shadowsocks 密码）被 DexProtector 加固封在运行期，
静态无法还原，因此本仓库不提供、也不可能提供"开箱可用"的代理池。**

本仓库的价值在于：一套可复现的**协议坐标**（端点 / 参数 / 坑），
以及一份关于「DexProtector + 自有 xray 内核」这类形态的完整攻防记录。

---

## 状态表

| 能力 | 状态 | 证据 |
|---|---|---|
| 节点清单 API | ✅ 无鉴权 | `GET vpndb.alhapi.com/v1/vpnlist?platform=android` → 200 / 51 KB |
| 节点规模 | ✅ 已收割 | 80 地区分组 · 514 条 · 505 端点 · **169 个唯一 IP** |
| REALITY 参数 | ✅ 公开下发 | `public_key` / `server_name` / `flow` / `network` / `security` |
| 端口可达性 | ✅ 已压测 | 505 端点 TCP 开 **172 (34.1%)** |
| vless:443 | ✅ | **87 / 169 (51.5%)**，其中 **83** 个 TLS 握手成功 |
| shadowsocks:990 | ✅ | **85 / 169 (50.3%)** |
| 功能配置 API | ✅ 需 `os=android` | `GET alhapi.com/v1/vpnconfig` |
| VLESS UUID / SS 密码 | ❌ 受阻 | 见 [docs/REVERSE_REPORT.md](docs/REVERSE_REPORT.md) §7 |
| 变成可用代理 | ⛔ 不可行 | 缺钥匙；且节点属运营方自有 VPS |

压测聚合数据见 [docs/stress_summary.json](docs/stress_summary.json)（逐条 IP 已脱敏剔除）。

---

## 协议速查

```http
# 节点清单 —— 无需任何凭证
GET https://vpndb.alhapi.com/v1/vpnlist?platform=android

# 功能配置 —— 必需参数是 os, 不是 platform
GET https://alhapi.com/v1/vpnconfig?os=android&app_version=2.8.0&country=us
```

`options`（随清单下发，**REALITY 全部公开参数**）：

```json
{
  "vless": {
    "flow": "xtls-rprx-vision",
    "security": "reality",
    "network": "tcp",
    "server_name": "www.cloudflare.com",
    "encryption": "none",
    "public_key": "<服务端下发, 会轮换>"
  },
  "dynamo": {"salt": "salt", "chronos": "7"},
  "ipsec": {"dynamo": "true"},
  "shadowsocks": {"dynamo": "true"}
}
```

协议 / 端口：`vless:443`（REALITY + xtls-rprx-vision）、`shadowsocks:990`（chacha20-ietf-poly1305）、`ipsec`。

> `dynamo{salt,chronos}` 是**配置字段，不是密钥** —— Go 内核里根本没有这两个符号。

---

## 目录

```
docs/
  REVERSE_REPORT.md      完整逆向报告（架构 / 端点 / 协议 / 动态分析 / 阻塞点）
  NEWAPI_INTEGRATION.md  若要接入代理池，该怎么做（以及为什么现在不该做）
  stress_summary.json    压测聚合统计（脱敏）
tools/
  harvest_aloha.py       匿名拉取节点清单 + 功能配置
  stress_aloha.py        TCP/TLS 可达性压测 + 地理富化
  demo_server.py         只读节点池 Demo (:8940)
  demo.html              Demo 前端
  sanitize_for_github.py 脱敏脚本（IP -> x.x.x.x）
hooks/
  hook3.js               挂 libXray.LibXray 全部 JNI，打印 String 入参（抓 xray JSON）
  hook4.js / hook5.js    抓 Intent extras / Service.onStartCommand
  scan8.py               内存扫描（"id":" / xtls-rprx-vision）
  drive10.py             UI 自动定位 + spawn-gating 一体化采集
```

---

## 快速开始

```powershell
python tools/harvest_aloha.py    # 拉清单
python tools/stress_aloha.py     # 压测（约 20 秒）
python tools/demo_server.py      # http://127.0.0.1:8940
```

---

## 踩坑清单（省时间用）

1. **`v1/vpnlist` 必须带 `platform=android`**，不带会返回 **200 + 空 body**（不是 4xx，很容易误判为"接口挂了"）。
2. **`v1/vpnconfig` 的必需参数是 `os=android`**（不是 `platform`）。逐参数二分才试出来。
3. **jadx 1.5.1 在这批 dex 上全崩**（`newPosition > limit` / `newPosition < 0`，全量 259,715 条错误）；
   **apktool / baksmali 报 `Invalid element width: 3/5/7/9/11/13/17`** 直接跳过整类。
   👉 **只有 androguard 3.3.5 能正常解析**这些字节码 —— 这是本次能推进的关键。
4. **字段名 / 类名 / `static final String` 完整保留**，方法体被剥。所以"从常量反推协议"是可行的。
5. **frida 17.x 不自动注入 Java bridge**（`Java is not defined`），要用 **16.5.9** 客户端；
   且 server 与 client 必须同版本；frida-server 非 root 时 `spawn` 报 `need Gadget`。
6. 模拟器默认网络是坏的：缺默认路由 + `PARTIAL_CONNECTIVITY`（IPv6 探测失败）→ app 判"无网络"。
   修法：`ip route add default via 10.0.2.2 dev radio0` + `settings put global captive_portal_mode 0`，
   再 `svc data disable/enable`，直到 `everValidated=true` + `partialConnectivity=false`。
7. **x86_64 模拟器跑不了它的 arm64 内核**：`com.alohamobile.vpn:xray` 子进程读配置后 `SIGILL` 必崩。
8. 该 APK 进程被强杀后**包状态会坏**（`Error type 3 Activity does not exist` / `Failure starting process`），
   必须 `pm uninstall` + 重装才能再启动。

---

## 攻防记录摘要（为什么钥匙拿不到）

试过并失败的路径，全部有据可查：

| 手段 | 结果 |
|---|---|
| dex / arsc 常量反推 | 拿到端点与全部协议参数，但**没有** uuid/password 常量 |
| 全量 `v1/*` 端点枚举 | **不存在**凭证下发端点 |
| 数据模型字段审计 | `VpnServerConnectConfiguration` 无 id / 无 password 字段 |
| 内存字符串扫描 | 扫到 `"id":"` ×20、`xtls-rprx-vision` ×4，但读上下文时进程自毁 |
| 内存 dex dump | 内存中**没有任何 `dex\n035` magic**（加固把 magic 也抹了），代码页按需解密 |
| spawn-gating 抢 `:xray` | 拦截成功，但加固在 agent 早期加载时直接 abort 进程 |
| attach-after-UI | 能活几十秒，但始终抓不到 xray JSON 构建点 |

**结论**：钥匙是 DexProtector 保护下的**纯运行期产物**。要收口需要一台**真 arm64 安卓机**，
在 `:xray` 正常启动的前提下 hook `libXray.LibXray.runXrayFromJSON(String)` —— 本仓库的 `hooks/hook3.js` 已经写好可直接用。

---

## 合规声明

- 节点为 **Aloha Mobile 运营方自有 VPS**。拿到凭证 ≠ 有权使用。
- 本仓库**不包含**任何凭证、账号、私有密钥，也不包含可用节点地址（已脱敏）。
- 仅做协议层面的互操作性研究。压测只做了 TCP connect + TLS ClientHello，
  没有对任何节点发起业务请求。
- 请勿将本仓库内容用于未授权访问。
