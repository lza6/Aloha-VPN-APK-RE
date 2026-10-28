#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aloha VPN 2.8.0 —— 节点收割器 (匿名, 无需任何凭证)

协议来源: APK 内 resources.arsc 的 vpn_db_api_endpoint / api_endpoint 字符串资源
  VPN_DB : https://vpndb.alhapi.com/   -> GET v1/vpnlist?platform=android
  ALHAPI : https://alhapi.com/         -> GET v1/vpnconfig (功能配置, 非凭证)

实测 (2026-10-28): vpnlist 无鉴权, 200 返回 ~51KB JSON, 80 个地区分组 / 169 个唯一 IP。
REALITY 参数随列表下发 (public_key / server_name / flow / security / network)。
"""
import json
import os
import sys
import time

import requests

VPN_DB = "https://vpndb.alhapi.com/"
ALHAPI = "https://alhapi.com/"
UA = "okhttp/4.12.0"

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch_vpnlist(platform: str = "android", timeout: int = 25) -> dict:
    url = VPN_DB + "v1/vpnlist"
    r = requests.get(url, params={"platform": platform},
                     headers={"User-Agent": UA}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def fetch_vpnconfig(platform: str = "android", app_version: str = "2.8.0",
                    country: str = "us", timeout: int = 25) -> dict:
    url = ALHAPI + "v1/vpnconfig"
    # 实测: 缺 os=android 必 400; platform 不是 vpnconfig 的必需参数
    r = requests.get(url, params={"platform": platform,
                                  "os": platform,
                                  "app_version": app_version,
                                  "country": country},
                     headers={"User-Agent": UA}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def flatten(data: dict) -> list:
    """把 result[].servers[] 展平成 (location, category, priority, protocol, address, port, extra)"""
    rows = []
    for grp in data.get("result", []):
        loc = grp.get("location")
        cat = grp.get("category")
        typ = grp.get("type")
        prio = grp.get("priority")
        dns = ",".join(grp.get("dns_servers") or [])
        for s in grp.get("servers", []):
            rows.append({
                "location": loc,
                "category": cat,
                "group_type": typ,
                "priority": prio,
                "dns": dns,
                "protocol": s.get("protocol"),
                "address": s.get("address"),
                "port": s.get("port"),
                "encryption_method": s.get("encryption_method"),
                "udp_forwarding": s.get("udp_forwarding"),
            })
    return rows


def unique_endpoints(rows: list) -> list:
    seen, out = set(), []
    for r in rows:
        key = (r["address"], r["protocol"], r["port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def main():
    t0 = time.time()
    data = fetch_vpnlist()
    rows = flatten(data)
    uniq = unique_endpoints(rows)
    ips = sorted({r["address"] for r in rows})
    print("[vpnlist] groups=%d servers=%d unique_endpoints=%d unique_ips=%d  (%.2fs)"
          % (len(data.get("result", [])), len(rows), len(uniq), len(ips), time.time() - t0))
    print("[options] %s" % json.dumps(data.get("options"), ensure_ascii=False))

    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": VPN_DB + "v1/vpnlist?platform=android",
        "options": data.get("options"),
        "group_count": len(data.get("result", [])),
        "server_count": len(rows),
        "unique_ips": ips,
        "endpoints": uniq,
        "groups": data.get("result"),
    }
    p = os.path.join(HERE, "aloha_vpnlist_raw.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("[saved] %s" % p)

    # 只写 IP 清单, 方便直接喂代理池工具
    with open(os.path.join(HERE, "aloha_ips.txt"), "w") as f:
        f.write("\n".join(ips) + "\n")
    print("[saved] aloha_ips.txt (%d)" % len(ips))

    try:
        cfg = fetch_vpnconfig()
        with open(os.path.join(HERE, "aloha_vpnconfig.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)
        print("[vpnconfig] keys=%s" % list(cfg.keys()))
    except Exception as e:
        print("[vpnconfig] fail: %s" % e)


if __name__ == "__main__":
    main()
