#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aloha VPN 节点池 Demo 服务 (只读)
  GET /                -> demo.html
  GET /api/summary     -> 压测汇总
  GET /api/pool        -> 合并后的节点池 (含存活/地理/RTT)
  GET /api/refresh     -> 实时重新拉取 v1/vpnlist 并合并(不跑压测)
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import harvest_aloha as hv

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8940

_lock = threading.Lock()
_state = {"stress": None, "raw": None, "refreshed_at": None}


def load_local():
    sp = os.path.join(HERE, "stress_result.json")
    rp = os.path.join(HERE, "aloha_vpnlist_raw.json")
    if os.path.exists(sp):
        with open(sp, encoding="utf-8") as f:
            _state["stress"] = json.load(f)
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as f:
            _state["raw"] = json.load(f)


def build_pool():
    stress = (_state.get("stress") or {}).get("results") or []
    raw = _state.get("raw") or {}
    opts = raw.get("options") or {}
    nodes = []
    for r in stress:
        nodes.append({
            "address": r.get("address"),
            "port": r.get("port"),
            "protocol": r.get("protocol"),
            "location": r.get("location"),
            "priority": r.get("priority"),
            "encryption_method": r.get("encryption_method"),
            "tcp_open": r.get("tcp"),
            "tcp_ms": r.get("tcp_ms"),
            "tls_ok": r.get("tls"),
            "tls_ver": r.get("tls_ver"),
            "country": r.get("geo_country"),
            "cc": r.get("geo_cc"),
            "city": r.get("geo_city"),
            "isp": r.get("geo_isp"),
            "as": r.get("geo_as"),
        })
    return {"nodes": nodes, "options": opts, "refreshed_at": _state.get("refreshed_at")}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            with open(os.path.join(HERE, "demo.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if p == "/api/summary":
            return self._send(200, (_state.get("stress") or {}).get("summary") or {})
        if p == "/api/pool":
            with _lock:
                return self._send(200, build_pool())
        if p == "/api/refresh":
            try:
                data = hv.fetch_vpnlist()
                rows = hv.flatten(data)
                uniq = hv.unique_endpoints(rows)
                with _lock:
                    _state["raw"] = {
                        "options": data.get("options"),
                        "endpoints": uniq,
                        "unique_ips": sorted({r["address"] for r in rows}),
                    }
                    _state["refreshed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                return self._send(200, {"ok": True, "endpoints": len(uniq),
                                        "options": data.get("options")})
            except Exception as e:
                return self._send(500, {"ok": False, "error": str(e)})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    load_local()
    print("[demo] http://127.0.0.1:%d  (%d nodes)" % (
        PORT, len(build_pool()["nodes"])))
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
