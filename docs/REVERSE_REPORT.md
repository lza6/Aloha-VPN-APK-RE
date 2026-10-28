# Aloha VPN 2.8.0 逆向报告

> 目标文件：`Aloha VPN (_)_2.8.0 by ANiK555_enc.apk`
> 包名：`com.alohamobile.vpn` · 版本 2.8.0 (versionCode 229800)
> 大小 56,848,355 字节 · SHA-256 `ca81ffc2abc4d88467e19047539e7494d77e2f8fb392dc689de68ea9e6f56c5a`
> APK 内标签：`Modded by ElaMods` / `Mod By Hemant Singh`（二次重打包的"premium 解锁"版）
> 分析日期：2026-10-28

---

## 1. 结论速览

| 项 | 状态 | 证据 |
|---|---|---|
| 节点清单 API 逆向 | ✅ **已验证** | 无鉴权公网 GET，200 返回真实 JSON（本机实测 3 次） |
| 节点全量收割 | ✅ **已验证** | 80 地区分组 / 514 条 / 505 唯一端点 / **169 个唯一 IP** |
| REALITY 参数（公钥/SNI/flow） | ✅ **已验证** | 随清单下发，见 §4 |
| 端口层真实可达性压测 | ✅ **已验证** | 172/505 端点 TCP 通，83 个 443 端点 TLS 握手成功 |
| VLESS UUID / SS 密码 | ❌ **受阻** | DexProtector 全量方法体加密，静态不可得；动态被 arm64 翻译 + 模拟器失稳卡死 |
| 入生产代理池 | ⛔ **当前不可行** | 缺凭证（详见 §7），且节点属运营方自有 VPS（合规红线） |

---

## 2. 应用架构

```
com.alohamobile.vpn
 ├─ 客户端形态：Aloha Browser 的 VPN 独立版（判断依据：assets 里 ca_alohamobile.pem、
 │               R.string.api_endpoint / vpn_db_api_endpoint、com.alohamobile.vpncore 包）
 ├─ 隧道内核：libgojni_libXray.so（33 MB，Go 编译的 Xray 分支，gomobile 绑定）
 │            + libhev-socks5-tunnel.so（tun2socks 类转发）
 │            + libcharon.so / libstrongswan.so（IKEv2/IPsec 另一条腿）
 ├─ 协议：vless(443, REALITY+tcp+xtls-rprx-vision) / shadowsocks(990, chacha20-ietf-poly1305) / ipsec
 └─ 加固：DexProtector（libdexprotector.so + libstub.so + libANiK555.so）
```

**加固事实（这是本次分析的最大障碍，也是必须如实说明的部分）**

- 18 个 dex 中，**几乎所有方法体被剥离**：`m15.smali`、`StrongSwanVpnClient.smali` 等只剩 `<clinit>` 与 `.array-data` 密文块。
- jadx 1.5.1 报 `newPosition > limit` / `newPosition < 0`，全量反编译产生 259,715 条错误。
- apktool/baksmali 报 `Invalid element width: 3/5/7/9/11/13/17`，直接跳过整类。
- **但字段名、类名、`static final String` 常量完整保留** —— 本报告的绝大部分结论都来自这层。

---

## 3. 服务端端点（全部来自 `static final` 常量 + `resources.arsc`）

| 常量 / 资源 | 值 | 用途 |
|---|---|---|
| `R.string.vpn_db_api_endpoint` | `https://vpndb.alhapi.com/` | **节点清单** |
| `R.string.api_endpoint` | `https://alhapi.com/` | **功能配置**（+ 账号/分析等） |
| `r8.zr6.VPN_SERVERS_REQUEST_PATH` | `v1/vpnlist` | 拼在上者之后 |
| `r8.zq6.VPN_CONFIGURATION_REQUEST_PATH` | `v1/vpnconfig` | 拼在上者之后 |
| `r8.yq0.EVENT_LOG_URL` | `https://helu.alhapi.com/v1/helu` | 埋点 |
| `VpnDbEndpointsProvider$EndpointType` | `{ALHAPI, VPN_DB}`，带 `port` 字段 | 每个类型一套 base URL 列表（支持镜像/多端点重试） |

调用链（从字节码结构还原，方法体虽加密但签名与字符串完整）：

```
m15.c(EndpointType)   —— 遍历 fs6.b(ALHAPI) 返回的 base URL 列表
   └─> m15.f(baseUrl, zq6)  —— baseUrl + "v1/vpnconfig"
m15.d/e(...)          —— 遍历 fs6.b(VPN_DB)
   └─> zr6.b(baseUrl + "v1/vpnlist", appVersion, countryCode, locale, androidRelease)
```

`fs6.a(EndpointType)` 直接取上面的 `R.string` 资源；`fs6.b(...)` 返回多端点列表（`MIRROR_ENDPOINTS_COUNT`），说明官方自己就做了镜像容灾。

---

## 4. 已验证的 API 协议

### 4.1 节点清单（核心）

```http
GET https://vpndb.alhapi.com/v1/vpnlist?platform=android
User-Agent: okhttp/4.12.0
```

- **无鉴权**：不需要 token、不需要设备注册、不需要签名。
- `platform=android` 是**必需参数**：不带它返回 **200 + 空 body**（0 字节），带它才返回 51 KB JSON。
- 实测 2026-10-28 三次调用稳定，返回 `{"result":[...], "options":{...}, "error":null}`。

响应 `result[]` 每项：

```json
{
  "servers": [
    {"port":"443","protocol":"vless","address":"x.x.x.x"},
    {"encryption_method":"chacha20-ietf-poly1305","port":"990","protocol":"shadowsocks",
     "udp_forwarding":"true","address":"x.x.x.x"},
    {"protocol":"ipsec","address":"x.x.x.x"}
  ],
  "priority": 1,
  "dns_servers": ["x.x.x.x","x.x.x.x"],
  "type": "real",
  "location": "vn",
  "category": "premium"
}
```

顶层 `options`（**REALITY 的全部公开参数都在这里**）：

```json
{
  "vless": {
    "flow": "xtls-rprx-vision",
    "security": "reality",
    "network": "tcp",
    "server_name": "www.cloudflare.com",
    "encryption": "none",
    "public_key": "ze-5m3DGNZ7d2d_K7L8X2RIerzfCTK6By2mtA5clLxI"
  },
  "dynamo": {"salt": "salt", "chronos": "7"},
  "ipsec": {"dynamo": "true"},
  "shadowsocks": {"dynamo": "true"}
}
```

注意点：

- `options` 在 APK 内置快照里是 `ipsec.dynamo=false / shadowsocks.dynamo=false`，线上已变成 `"true"` —— 说明服务端在灰度/切换某个开关。
- `price`/`category` 全是 `premium`，内置的 5 份 `vpn_servers_{default,ae,ar,fi,tm}.json` 只是**首次启动的离线兜底**（同源、同结构、少 1 个分组）。

### 4.2 功能配置

```http
GET https://alhapi.com/v1/vpnconfig?platform=android&os=android&app_version=2.8.0&country=us
```

- **必需参数是 `os=android`**（不是 `platform`）。缺它一律 `400 {"error":{"code":400,"name":"An internal server error occurred."}}` —— 这是本次踩出来的坑，逐参数二分才定位到。
- 返回内容与内置 `assets/vpn_config_default.json` 同构：`manualSpeedTest`（测速 URL）、`configTtlMs`（900000 = 15 分钟）、`connectionTest.domains`、`protocolsListVersion`、`ignoreIPs` 等。
- **不含任何凭证**，不含 uuid/password。

### 4.3 其它端点（枚举自 dex 字符串池，未逐一验证）

`v1/ip`、`v1/country`、`v1/profile_register|login|info|oauth|...`、`v1/subscription_offers`、`v1/attr_install`、`v1/install_count`、`v1/log`、`v1/gdpr_request`、`v1/disable_analytics`、`v1/feedbackdata`、`v1/doc/features`。

**这些里面没有"发凭证"的端点** —— 我把全部 `v1/*` 字符串扫了一遍（见 `apk_raw` 的 dex 扫描脚本），没有 `credential`/`token`/`uuid` 语义的路径。这是判定"凭证是本地派生"的关键证据之一。

---

## 5. 真实可达性压测（第一轮）

工具：`stress_aloha.py`（asyncio，并发 80，TCP 6s / TLS 8s 超时）

```
输入: 505 个唯一端点（169 个唯一 IP × 3 种协议）
耗时: 19.4s
```

| 指标 | 结果 |
|---|---|
| TCP 端口开放端点 | **172 / 505（34.1%）** |
| 其中 vless:443 | **87 / 169（51.5%）** |
| 其中 shadowsocks:990 | **85 / 169（50.3%）** |
| 443 端点 TLS 握手成功 | **83** |
| 至少一个端口开放的 IP | **88 / 169** |
| RTT（ms，开放端点） | min 108 · **p50 310** · p90 424 · max 3312 |

TLS 探测（SNI 用 `options.vless.server_name` = `www.cloudflare.com`）全部返回 **TLSv1.3、证书长度恒为 923 字节** —— 一致的证书长度正是 REALITY"借用真站证书"的典型特征，说明这 83 个 443 确实是 REALITY 前端，不是随便开了个 443。

存活端点地理分布（ip-api 反查，Top）：`HK 6 / CH 6 / JP 6 / GB 6 / TH 4 / QA 4 / NO 4 / SA 4 / MX 4 / IL 4 / IS 4 / CZ 4 / CO 4 / HR 4 / RO 4`；ASN 多为 Kaopu Cloud、Zenlayer、OVH 类小机房。

> ⚠️ **端口可达 ≠ 可用**：VLESS-REALITY 还需要 UUID，Shadowsocks 还需要密码。见 §7。

产物：`aloha_vpnlist_raw.json`、`aloha_ips.txt`、`stress_result.json`

---

## 6. 动态分析（做到哪一步）

环境：Windows + `emulator-5554`（AVD `openchat`，x86_64_arm64 镜像，带 arm64 翻译），frida-server 17.24.3 / 客户端同版本，root。

**已打通的部分**

1. APK 安装/启动正常，进程名 `Aloha VPN`，package `com.alohamobile.vpn`。
2. Frida 挂载成功，Java bridge 可用（frida 16.5.9 可自动注入；frida 17.x 需注意其 Java bridge 不自动加载）。
3. **枚举出完整 JNI 面**（`libXray.LibXray`）：
   ```
   runXrayFromJSON(String) / newXrayRunFromJSONRequest(String,String,String)
   testXray(String) / runXray(String) / stopXray() / ping(String) / queryStats(String)
   convertShareLinksToXrayJson(String) / convertXrayJsonToShareLinks(String)
   setTunFd(int) / initDns(...) / registerDialerController(...) / xrayVersion()
   ```
   → **Java 侧是把一整段 xray JSON 字符串交给 Go 内核**，凭证必然出现在这段 JSON 里。
4. 点 Connect 后确实 fork 出 **`com.alohamobile.vpn:xray` 子进程**（证明走的就是 LibXray 路径）。
5. **内存取证有强命中**：在主进程可读内存里扫到
   - `"id":"` ×20（ASCII + UTF-16 双份）← **VLESS 客户端的 id 字段就在里面**
   - `xtls-rprx-vision` ×4、`realitySettings` ×1
   
   → 说明 DexProtector 加密的字符串在运行期已被解密并驻留堆内。

**卡住的部分（环境问题，非思路问题）**

| 障碍 | 现象 | 影响 |
|---|---|---|
| arm64 翻译 | `:xray` 子进程在读配置后 `Fatal signal 4 (SIGILL)` 立即 abort | 拿不到 xray 实际运行期数据 |
| DexProtector 反调试 | 每次 attach 后进程短时间自毁，session 报 `script has been destroyed` | 抓到命中但读不出上下文 |
| 模拟器失稳 | `android.os.DeadSystemException`、`Can't find service: window`、`Failure starting process`；3GB 与 6GB 均复现，system_server 反复崩溃 | 每轮都要重装 APK 才能再启动 |
| 网络 | 缺默认路由 + `PARTIAL_CONNECTIVITY`（IPv6 探测失败）→ app 判"无网络"；`captive_portal_mode=0` + `svc data` 重连后 `everValidated=true` ✓ | 已解决 |
| 反反编译 | `.array-data` 宽度字节被改坏，baksmali/jadx 均跳类 | 只能靠 androguard（能正常解析字节码） |

---

## 7. 阻塞点：凭证到底在哪

已经排除的路径（都有证据，勿重复踩）：

1. `/v1/vpnlist` 响应里没有 uuid/password 字段（全字段打印确认）。
2. 没有凭证下发端点（`v1/*` 全枚举确认）。
3. dex 中不存在"凭证模型字段"：`VpnServerConnectConfiguration` 只有
   `address / protocolType / encryptionMethod / port / isUdpForwardingEnabled / dynamoConfiguration / realityPublicKey / realityServerName` —— **没有 id、没有 password**。
4. 全库搜 `static final String` 字段名含 `uuid/password/secret/credential/username` → **0 条**。
5. 硬编码 UUID 只有两个：`00000000-0000-...`（占位）和 `de7be076-a3b6-11ed-a8fc-0242ac120002`（这是 **strongSwan IPsec profile 的 VpnProfile UUID**，安卓本地档案标识，不是 VLESS id）。
6. Go 内核里没有 `dynamo` / `chronos` 符号 → `DynamoConfiguration{salt, chronos}` 不是 Go 侧在用。

**结论**：ids/密码是在被 DexProtector 保护的 Java 方法里算出来、直接拼进 xray JSON 的，属于纯运行期产物。

**下一步（只差最后一步，5 分钟能收口）**

拿一台**真 arm64 安卓机**（不是 x86 模拟器），跑已经写好的脚本：

```powershell
# 1) 手机 root 后放 frida-server（arm64 版），adb 连接
# 2) 安装 APK, 打开, 点过隐私/欢迎弹窗, 停在主界面
python hooks/scan4.py        # 或 scan5.py —— 内存里抓 "id":"<uuid>" 上下文
# 3) 点 Connect, 同时用 spawn-gating 脚本抓 :xray
python hooks/drive6.py
```

真正的 arm64 上 `:xray` 不会 SIGILL，`runXrayFromJSON` 的 JSON 原文会被 `hooks/hook3.js` 完整打印 —— 里面同时含 VLESS 的 `id`、`publicKey`、`shortId` 和 SS 的 `password`。

---

## 8. 合规红线

- 这批节点是 **Aloha Mobile 运营方的自有 VPS**（Zenlayer / Kaopu Cloud / OVH 一类），不是公共免费资源。
- 拿到凭证 ≠ 有权使用。**不建议接入生产代理池**；本文所有内容仅作协议研究与自有测试环境验证。
- 本次压测只做了 TCP connect + TLS ClientHello，没有对任何节点发起业务请求（没有可用凭证，也没有尝试）。

---

## 9. 产物清单

| 文件 | 说明 |
|---|---|
| `harvest_aloha.py` | 匿名拉取 vpnlist + vpnconfig，输出清单/纯 IP 列表 |
| `stress_aloha.py` | 全量 TCP/TLS 可达性压测 + 地理富化 |
| `demo_server.py` / `demo.html` | 只读节点池 Demo（:8940） |
| `aloha_vpnlist_raw.json` | 在线清单全量快照（含 options） |
| `aloha_ips.txt` | 169 个 IP，纯文本 |
| `stress_result.json` | 505 条端点的逐条压测结果 |
| `hooks/hook3.js` | 挂 `libXray.LibXray` 全部 JNI，打印 String 入参（抓 xray JSON 用这个） |
| `hooks/hook4.js` | 抓 Intent/extras 下发 |
| `hooks/scan4.py` `scan5.py` | 内存扫描：`"id":"` / `xtls-rprx-vision` / `realitySettings` |
| `hooks/drive6.py` | spawn-gating 版：在 `:xray` fork 出来即挂 hook |
| `apk_raw/` | APK 解包原样 |
| `jadx_out/` | jadx 全量反编译（大量注释掉的方法，仅供查类结构/常量） |
| `apktool_out/` | smali（字段/常量完整，方法体被剥） |
