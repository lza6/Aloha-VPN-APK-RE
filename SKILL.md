# SKILL — Aloha VPN（DexProtector + 自有 xray 内核）逆向

> 适用形态：APK 同时满足 ①有 `libdexprotector.so`/`libstub.so` ②自带 Go 编译的 xray 内核（`libgojni_libXray.so`）③有 `vpnlist` / `vpnconfig` 双端点。
> 遇到这类包，按本卡顺序走，能省 2~3 小时。

## 0. 先判断值不值得做

```
unzip -l <apk> | grep -E "assets/vpn_servers|vpn_config|ca_.*\.pem"   # 有清单快照 => 有戏
unzip -l <apk> | grep -E "dexprotector|libstub|libjiagu|libshell"     # 有 => 方法体会被剥
```

**有 DexProtector 就别指望反编译拿逻辑**，直接转"常量 + 动态"两条腿。

## 1. 常量层（15 分钟能拿完）

- jadx / baksmali **一定会崩**（`newPosition > limit` / `Invalid element width`）—— 别浪费时间调参数。
- 用 **androguard 3.3.5**：`AnalyzeAPK()` → `dex.get_classes()` → `m.get_code().get_bc().get_instructions()`，能正常出字节码。
- 加固只剥**方法体**，`static final String` / 字段名 / 类名 / 接口签名全在。所以：

```bash
# 端点常量
strings classes*.dex | grep -E "v1/[a-z_]+"
# 域名常量(可能在 resources.arsc 里!)
python -c "d=open('resources.arsc','rb').read(); import re; print({m.group(0) for m in re.finditer(rb'https?://[ -~]{5,90}', d)})"
```

`R.string.xxx_endpoint` 这类资源名 + 对应的 URL 值是最快的入口（本案例：`api_endpoint` / `vpn_db_api_endpoint`）。

## 2. 端点层（协议真伪只能靠实测）

- 用 `curl` 逐个试，**注意必需参数**。本案例两个端点必需参数不同：
  - `v1/vpnlist?platform=android` —— 不带参数返回 **200 + 空 body**（不是 4xx！）
  - `v1/vpnconfig?os=android` —— 不带会 400
- 判断"缺参数"的方法：**逐参数二分**，别一次糊一堆参数（糊了成功了也不知道哪个是关键）。
- 用 `-w "%{http_code} %{size_download}"` 看 size，0 字节 = 参数不对。

## 3. 凭证层（真正的分水岭）

先做**三个否定性检查**，能快速判定"凭证是不是本地派生"：

1. 清单响应里有 uuid/password 字段吗？（全字段打印）
2. 全量 `v1/*` 字符串里有凭证语义端点吗？
3. 数据模型类字段里有没有 id/password？（`VpnServerConnectConfiguration` 只有 address/port/protocol/publicKey → **没有**）

三条都否定 → 凭证是运行期算的 → **只有动态能做**。

## 4. 动态层（按成功率排序）

```js
// 最高价值：直接抓内核入参
Java.use('libXray.LibXray').class.getDeclaredMethods()   // 先枚举 JNI
// runXrayFromJSON(String) 的入参就是含凭证的完整 xray JSON
```

| 手段 | 成功率 | 备注 |
|---|---|---|
| attach 主进程 + hook `libXray.*` | ★★★★ | frida **16.5.9**（17.x 不自动注入 Java bridge） |
| spawn-gating 抢 `:xray` 子进程 | ★★★ | `dev.enable_spawn_gating()`；但加固常在 agent 早期加载时 abort |
| hook `Intent.putExtra(String,String)` | ★★★ | 配置若走 Intent 下发，这里最省事 |
| 内存扫 `"id":"` / `xtls-rprx-vision` | ★★ | 命中是**瞬时**的，读上下文前进程可能已自毁 |
| 内存 dump dex | ✗ | 加固把 `dex\n035` magic 也抹了，代码页按需解密 |
| jadx/baksmali 反编译 | ✗ | 方法体全剥 |

**结论：真机（arm64）+ 真内核能跑，才有稳定窗口。x86 模拟器跑 arm64 内核必 SIGILL。**

## 5. 环境坑（都实测过）

```
# 模拟器网络默认坏：app 报"无网络"
adb shell ip route add default via 10.0.2.2 dev radio0
adb shell settings put global captive_portal_mode 0
adb shell svc data disable; sleep 2; adb shell svc data enable
# 直到 dumpsys connectivity 出现 everValidated{true} + partialConnectivity{false}

# 包状态会坏(进程被强杀后)
adb uninstall <pkg> && adb install -g -r <apk>     # 否则 Error type 3 / Failure starting process

# frida
fs --version  ==  python -c "import frida;print(frida.__version__)"   # 必须一致
adb shell setsid /data/local/tmp/fs -l 127.0.0.1:27999 &             # 别抢 27042(可能被 gadget 占)
adb forward tcp:27999 tcp:27999
```

## 6. UI 自动定位（别再猜坐标）

坐标会因为弹窗/分辨率变，一律改成解析 UI：

```python
adb('shell', 'uiautomator', 'dump', '/sdcard/u.xml')
adb('shell', 'cat', '/sdcard/u.xml')     # 正则提 clicked/text + bounds, 算中心点再 input tap
```

## 7. 产出物最低要求

- `harvest_*.py`（能一条命令重拉全量）
- `stress_*.py`（TCP + TLS 双测；**TLS 握手 + 证书长度一致性**是判断 REALITY 前端的硬证据）
- `demo_server.py`（只读面板，能被 curl 验证 4 个端点）
- 报告里**必须写清"端口可达 ≠ 可用"**，别把探测结果包装成可用代理池
