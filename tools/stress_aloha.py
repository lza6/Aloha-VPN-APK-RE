#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aloha VPN 节点真实可达性压测

测什么:
  1) TCP connect  -> 端口是否真的开着 (vless 443 / shadowsocks 990)
  2) TLS 握手     -> 443 上是否真的在说 TLS (REALITY 前端, SNI=列表下发的 server_name)
  3) 出口归属     -> ip-api 反查国家/ASN

注意: 端口可达 != 可用。VLESS-REALITY 还需要客户端 UUID, Shadowsocks 还需要密码,
      这两项在该 APK 中被 DexProtector 保护, 见 docs/REVERSE_REPORT.md 的"阻塞点"。
"""
import asyncio
import json
import os
import socket
import ssl
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "aloha_vpnlist_raw.json")
OUT = os.path.join(HERE, "stress_result.json")

CONCURRENCY = 80
TCP_TIMEOUT = 6.0
TLS_TIMEOUT = 8.0


async def tcp_probe(host, port, timeout=TCP_TIMEOUT):
    t0 = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, int(port))
        r, w = await asyncio.wait_for(fut, timeout=timeout)
        ms = (time.perf_counter() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True, round(ms, 1)
    except Exception:
        return False, None


def tls_probe_blocking(host, port, sni, timeout=TLS_TIMEOUT):
    """同步 TLS 握手, 在 executor 里跑, 拿证书信息"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as ss:
                cert = ss.getpeercert(binary_form=True)
                ver = ss.version()
                return True, ver, len(cert) if cert else 0
    except Exception as e:
        return False, type(e).__name__, 0


async def geo_lookup(ips):
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            r = requests.post("http://ip-api.com/batch?fields=query,country,countryCode,city,isp,as,org",
                              json=chunk, timeout=25)
            for item in r.json():
                out[item.get("query")] = {
                    "country": item.get("country"),
                    "cc": item.get("countryCode"),
                    "city": item.get("city"),
                    "isp": item.get("isp"),
                    "as": item.get("as"),
                }
        except Exception as e:
            print("[geo] fail", e)
        await asyncio.sleep(1.5)
    return out


async def main():
    with open(RAW, encoding="utf-8") as f:
        data = json.load(f)
    endpoints = data["endpoints"]
    ips = data["unique_ips"]
    sni = (data.get("options") or {}).get("vless", {}).get("server_name") or "www.cloudflare.com"
    target_ip = (data.get("options") or {}).get("vless", {}).get(
        "server_name") or "www.cloudflare.com"

    print("[init] endpoints=%d ips=%d sni=%s" % (len(endpoints), len(ips), sni))

    sem = asyncio.Semaphore(CONCURRENCY)
    loop = asyncio.get_event_loop()
    results = []

    async def one(ep):
        async with sem:
            host, proto, port = ep["address"], ep["protocol"], ep.get("port")
            if not port:
                results.append(dict(ep, tcp=False, tcp_ms=None, tls=False, tls_ver=None))
                return
            ok, ms = await tcp_probe(host, port)
            rec = dict(ep, tcp=ok, tcp_ms=ms, tls=False, tls_ver=None, tls_cert_len=0)
            if ok and str(port) == "443":
                tok, ver, clen = await loop.run_in_executor(None, tls_probe_blocking, host, port, sni)
                rec.update(tls=tok, tls_ver=ver, tls_cert_len=clen)
            results.append(rec)

    t0 = time.time()
    await asyncio.gather(*(one(ep) for ep in endpoints))
    dur = time.time() - t0
    print("[probe] done in %.1fs" % dur)

    geo = await geo_lookup(ips)
    for r in results:
        g = geo.get(r["address"], {})
        r.update({"geo_country": g.get("country"), "geo_cc": g.get("cc"),
                  "geo_city": g.get("city"), "geo_isp": g.get("isp"), "geo_as": g.get("as")})

    tcp_ok = [r for r in results if r["tcp"]]
    tls_ok = [r for r in results if r.get("tls")]
    ip_tcp = sorted({r["address"] for r in tcp_ok})

    summary = {
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_s": round(dur, 1),
        "endpoints": len(results),
        "unique_ips": len(ips),
        "tcp_open_endpoints": len(tcp_ok),
        "tls_ok_endpoints": len(tls_ok),
        "ips_with_any_open_port": len(ip_tcp),
        "tcp_open_pct": round(len(tcp_ok) * 100.0 / max(1, len(results)), 1),
        "by_protocol": {},
    }
    for proto in ("vless", "shadowsocks"):
        tot = len([r for r in results if r["protocol"] == proto])
        ok = len([r for r in tcp_ok if r["protocol"] == proto])
        summary["by_protocol"][proto] = {"total": tot, "tcp_open": ok,
                                        "pct": round(ok * 100.0 / max(1, tot), 1)}

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": results}, f, ensure_ascii=False, indent=1)

    print("[summary] %s" % json.dumps(summary["by_protocol"], ensure_ascii=False))
    print("[summary] tcp_open=%d/%d (%.1f%%)  tls_ok=%d  ips_with_open_port=%d"
          % (summary["tcp_open_endpoints"], summary["endpoints"], summary["tcp_open_pct"],
             summary["tls_ok_endpoints"], summary["ips_with_any_open_port"]))
    print("[saved] %s" % OUT)


if __name__ == "__main__":
    asyncio.run(main())
