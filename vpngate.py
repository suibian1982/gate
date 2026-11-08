#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (强日志诊断版)
=========================================================
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import socket
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

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "64")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "6.0"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

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

def fetch_vpngate():
    try:
        log("VPN GATE", f"正在请求官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        log("VPN GATE", f"官方 API 响应状态码: {resp.status_code}, 长度: {len(resp.text)}")
        if resp.status_code == 200 and len(resp.text) > 100:
            rows = parse_csv(resp.text)
            if rows:
                log("VPN GATE", f"官方 API 获取并解析成功，共 {len(rows)} 个节点")
                return rows, "vpngate.net/api/iphone"
    except Exception as exc:
        log("VPN GATE", f"官方 API 请求异常: {exc}")

    try:
        log("VPN GATE", f"切换至备用镜像源: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        log("VPN GATE", f"备用镜像响应状态码: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            rows = parse_mirror_json(data)
            if rows:
                log("VPN GATE", f"备用镜像获取成功，共 {len(rows)} 个节点")
                return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"备用镜像请求异常: {exc}")

    die("所有数据源（官方 API 与备用镜像）均获取失败。")

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        log("PARSE CSV", "警告: 未在 CSV 中找到 HostName 表头")
        return []

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    rows = []
    for ln in data_lines:
        try:
            fields = next(csv.reader(io.StringIO(ln)))
        except Exception:
            continue
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows

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

def classify_network(host):
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "residential"

def check_one(node):
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = classify_network(node["host"])
    
    target_ip = node["ip"]
    target_port = node["port"]
    
    t0 = time.time()
    try:
        s = socket.create_connection((target_ip, target_port), timeout=CHECK_TIMEOUT)
        s.close()
        latency = int((time.time() - t0) * 1000)
        
        out["success"] = True
        out["status"] = "success"
        out["latency_ms"] = latency
        out["error"] = None
    except Exception as exc:
        out["success"] = False
        out["status"] = "failed"
        out["error"] = str(exc)
    
    return out

def check_all(nodes):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n) for n in nodes]
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
            n.get("latency_ms") is None,
            n.get("latency_ms") or 0,
            n.get("host") or ""
        ))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "duration_s": round(duration_s, 1),
        "worker": "python-native-tcp-check",
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
            n.get("latency_ms") is None,
            n.get("latency_ms") or 0,
            n.get("host") or ""
        ))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential"] != "residential"]
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
        f"| 失败 | {stats['failed']}（Worker 异常 0）|\n",
        f"| 国家/地区 | {stats['countries']} |\n",
        f"| 住宅 / 机房 / 未知 | {stats['residential_est']} / {stats['datacenter_est']} / 0 |\n",
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
        html = "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head><body><h1>VPN Gate SSTP 节点</h1></body></html>"
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

    if MAX_CHECK_NODES > 0: uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}, SSTP 节点: {sstp_count}, 去重后: {len(uniq)}")
    results = check_all(uniq)

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]

    log("TCP CHECK", f"检测成功: {len(success)}, 检测失败: {len(failed)}")

    duration_s = time.time() - started
    data = build_outputs(results, raw_count, sstp_count, source, duration_s)
    edge_hosts = get_combined_edge_hosts()
    data_path, html_path, nodes_path, nodes_text = write_outputs(data, edge_hosts)
    
    nodes_count = len([line for line in nodes_text.splitlines() if line.strip()])
    write_step_summary(data, nodes_count)
    log("WEBSITE", "完成文件生成与打包发布")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"程序运行异常捕获: {exc}")
        traceback.print_exc()
        sys.exit(1)
