#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把本地取证产物脱敏成可公开的仓库内容。

脱敏规则:
  - 所有节点 IPv4 -> x.x.x.x (保留协议/端口/地区/地理/RTT 统计)
  - 不输出逐条端点明细, 只输出聚合统计
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.join(ROOT, 'gh_repo')

IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# 允许保留的文档示例地址(RFC5737 / 本地回环)
KEEP = {'127.0.0.1', '0.0.0.0', '1.2.3.4', '10.0.2.2', '10.0.2.3', '10.0.2.19',
        '10.0.2.15', '255.255.255.255'}


def scrub(text):
    def rep(m):
        s = m.group(0)
        if s in KEEP:
            return s
        # 常见非节点 IP(版本号/掩码) 原样保留
        if s.startswith(('192.168.0.', '172.16.', '192.0.2.')):
            return s
        return 'x.x.x.x'
    return IPV4.sub(rep, text)


def main():
    os.makedirs(os.path.join(REPO, 'docs'), exist_ok=True)

    # 1) 文档脱敏
    for name in ('REVERSE_REPORT.md', 'NEWAPI_INTEGRATION.md'):
        src = os.path.join(ROOT, 'docs', name)
        dst = os.path.join(REPO, 'docs', name)
        with open(src, encoding='utf-8') as f:
            t = f.read()
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(scrub(t))
        print('[doc]', dst)

    # 2) 压测结果 -> 只保留聚合
    with open(os.path.join(ROOT, 'stress_result.json'), encoding='utf-8') as f:
        d = json.load(f)
    s = d['summary']
    res = d['results']
    by_cc = {}
    for r in res:
        if not r.get('tcp'):
            continue
        cc = r.get('geo_cc') or '??'
        by_cc[cc] = by_cc.get(cc, 0) + 1
    out = {
        'summary': s,
        'alive_endpoints_by_country': dict(sorted(by_cc.items(), key=lambda kv: -kv[1])),
        'note': '逐条端点(IP/端口/RTT)已按脱敏要求剔除, 只保留聚合统计',
    }
    p = os.path.join(REPO, 'docs', 'stress_summary.json')
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print('[doc]', p)

    # 3) 工具脚本
    tdir = os.path.join(REPO, 'tools')
    os.makedirs(tdir, exist_ok=True)
    for name in ('harvest_aloha.py', 'stress_aloha.py', 'demo_server.py', 'demo.html'):
        shutil.copy2(os.path.join(ROOT, name), os.path.join(tdir, name))
        print('[tool]', name)

    # 4) frida 脚本
    hdir = os.path.join(REPO, 'hooks')
    os.makedirs(hdir, exist_ok=True)
    for name in ('hook3.js', 'hook4.js', 'hook5.js', 'scan8.py', 'drive10.py'):
        src = os.path.join(ROOT, 'hooks', name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(hdir, name))
            print('[hook]', name)


if __name__ == '__main__':
    main()
