#!/usr/bin/env python3
"""
VPN Gate 自动化家宽节点抓取与检测流水线 (语法修复版)
================================================================
通过 Cloudflare Worker (CheckSocks5) 远程检测节点，自动生成 nodes.txt。
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

CHECK_WORKER_HOST = os.environ.get("DOMAIN", "").strip()

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get("EDGE_HOSTS", "").split(",")
    if h.strip()
]

OPTIMAL_API = os.environ.get("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443")

def derive_nodes_url() -> str:
    explicit = os.environ.get("NODES_URL", "").strip()
    if explicit:
        return explicit
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if "/" in repo:
        owner, name = repo.split("/", 1)
        if owner and name:
            return f"https://{owner}.github.io/{name}/nodes.txt"
    return "https://suibian1982.github.io/gate/nodes.txt"

NODES_URL = derive_nodes_url()

_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    traceback.print_exc()
    sys.exit(1)

def fetch_optimal_api_endpoints(api_urls_str):
    if not api_urls_str.strip():
        return []
    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        if ":" not in endpoint: endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
        except Exception:
            pass
    return endpoints

def get_combined_edge_hosts():
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)
    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)
    return combined if combined else EDGE_HOSTS

def fetch_vpngate():
    try:
        log("VPN GATE", f"正在请求稳定镜像源: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            rows = parse_mirror_json(data)
            if rows:
                log("VPN GATE", f"镜像源获取并解析成功，共 {len(rows)} 个原始节点")
                return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"镜像源请求异常: {exc}")
    die("无法从镜像源获取节点数据。")

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

def check_one_via_worker(node):
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["success"] = False
    out["residential"] = "datacenter"
    
    if not CHECK_WORKER_HOST:
        return check_local_fallback(node)

    check_url = f"https://{CHECK_WORKER_HOST}/check?lastp=vpn:vpn@{node['host']}:{node['port']}"
    try:
        resp = requests.get(check_url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            res_json = resp.json()
            if res_json.get("success") is True:
                out["success"] = True
                out["latency_ms"] = res_json.get("responseTime", 100)
                exit_info = res_json.get("exit", {})
                if exit_info.get("is_datacenter") is False:
                    out["residential"] = "residential"
                else:
                    out["residential"] = "datacenter"
        return out
    except Exception:
        out["success"] = False
        return out

def check_local_fallback(node):
    out = dict(node)
    out["success"] = False
    out["residential"] = "residential"
    try:
        t0 = time.time()
        s = socket.create_connection((node["ip"], node["port"]), timeout=5.0)
        s.close()
        out["success"] = True
        out["latency_ms"] = int((time.time() - t0) * 1000)
    except Exception:
        out["success"] = False
    return out

def check_all(nodes):
    results = []
    concurrency = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
    log("WORKER CHECK", f"开始通过边缘 Worker 批量检测，并发数: {concurrency}, 总数: {len(nodes)}")
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(check_one_via_worker, n) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

def build_outputs(results, raw_count, sstp_count, source, duration_s):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        code = n["country_code"] or "?"
        countries.setdefault(c, {"code": code, "name": c, "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n.get("residential") == "residential"),
        "datacenter_est": sum(1 for n in available if n.get("residential") == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n.get("residential") == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n.get("residential") == "datacenter")
        grp["nodes"].sort(key=lambda n: (
            0 if n.get("residential") == "residential" else 1,
            n.get("latency_ms") or 0,
            n.get("host") or ""
        ))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "duration_s": round(duration_s, 1),
        "worker": "cloudflare-worker-check",
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def build_nodes_text(data, edge_hosts):
    countries = data["countries"]
    edge = edge_hosts
    lines = []
    idx = 0
    ordered = sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"], key=lambda n: (
            0 if n.get("residential") == "residential" else 1,
            n.get("latency_ms") or 0,
            n.get("host") or ""
        ))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            if edge:
                entry = edge[idx % len(edge)]
                idx += 1
                lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
            else:
                lines.append(f"{n['host']}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            if edge:
                entry = edge[idx % len(edge)]
                idx += 1
                lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
            else:
                lines.append(f"{n['host']}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"

def atomic_write(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = f"{path}.tmp-{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp_path, path)

def write_step_summary(data, nodes_count):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        return
    stats = data["stats"]
    rows = [
        "## check 摘要\n\n",
        "| 指标 | 数值 |\n| :--- | ---: |\n",
        f"| 原始节点 | {stats['raw_nodes']} |\n",
        f"| SSTP 候选 | {stats['sstp_nodes']} |\n",
        f"| 已检测 | {stats['checked']} |\n",
        f"| 可用 | {stats['success']} |\n",
        f"| 失败 | {stats['failed']} |\n",
        f"| 国家/地区 | {stats['countries']} |\n",
        f"| 住宅 / 机房 | {stats['residential_est']} / {stats['datacenter_est']} |\n",
        f"| 发布节点行数 | {nodes_count} |\n",
        f"| 用时 | {data['duration_s']}s |\n",
        f"| 数据源 | {data['source']} |\n\n",
    ]
    top = sorted(data["countries"].values(), key=lambda g: -g["count"])[:5]
    if top:
        rows.append("### 节点最多的 5 个国家/地区\n\n| 国家/地区 | 数量 | 住宅 |\n| :--- | ---: | ---: |\n")
        for group in top:
            c_code = group.get('code', '')
            c_name = COUNTRY_ZH.get(c_code, group['name'])
            rows.append(f"| {c_name}（{c_code}）| {group['count']} | {group['residential']} |\n")
    rows.append(f"\n订阅地址：`{NODES_URL}`\n")
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("".join(rows))

def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    atomic_write(os.path.join(PUBLIC_DIR, ".nojekyll"), "")

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    atomic_write(data_path, json.dumps(data, ensure_ascii=False, indent=1))

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = "<html><head><meta charset='utf-8'><title>VPN Gate 节点看板</title></head><body><h1>VPN Gate 优选节点</h1></body></html>"
    atomic_write(html_path, html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    nodes_text = build_nodes_text(data, edge_hosts)
    atomic_write(nodes_path, nodes_text)

    return data_path, html_path, nodes_path, nodes_text

def main():
    started = time.time()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0: die("VPN Gate 返回 0 个有效原始节点")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0: die("未解析出任何 SSTP 节点")
    uniq = dedupe(sstp_nodes)

    max_check = int(os.environ.get("MAX_CHECK_NODES", "0"))
    if max_check > 0: uniq = uniq[:max_check]

    log("VPN GATE", f"获取原始节点: {raw_count}, SSTP 候选: {sstp_count}, 去重后: {len(uniq)}")
    results = check_all(uniq)

    success = [r for r in results if r.get("success")]
    log("CHECK RESULT", f"检测成功有效节点: {len(success)}")

    duration_s = time.time() - started
    data = build_outputs(results, raw_count, sstp_count, source, duration_s)
    edge_hosts = get_combined_edge_hosts()
    _, _, _, nodes_text = write_outputs(data, edge_hosts)
    
    nodes_count = len([line for line in nodes_text.splitlines() if line.strip()])
    write_step_summary(data, nodes_count)
    log("WEBSITE", "完成全部节点检测、过滤与打包发布")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"程序运行异常: {exc}")
        traceback.print_exc()
        sys.exit(1)
