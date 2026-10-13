#!/usr/bin/env python3
"""
VPN Gate SSTP 住宅节点检测流水线
=================================
目标：定时获取住宅 IP（residential），只输出住宅节点。

流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker（CheckSocks5）
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt（nodes.txt 仅住宅）

为什么必须用 CheckSocks5、不能用 edgetunnel 的 /admin/check：
  - edgetunnel 的 admin/* 是 Cookie 鉴权（MD5(UA+秘钥+密码)），不认
    `Authorization: Bearer`，不带 Cookie 一律 302 到 /login，Action 里
    88 个节点会全部 HTTP 302、判定为 Worker 异常、整轮失败。
  - edgetunnel 的 /admin/check 只回 {success, ip, loc, responseTime}，
    没有 exit.asn / is_datacenter，无法区分住宅/机房。
  - CheckSocks5 回 exit（含 is_datacenter = privacy.is_hosting、
    asn.type、asn.org），是本项目判断住宅的唯一依据。
"""

import base64
import csv
import io
import ipaddress
import json
import os
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))


def _env(name, default):
    """空字符串当作未设置（GitHub Secret 为空时 env 会是 ""，不是缺省值）。"""
    v = os.environ.get(name, "")
    v = v.strip() if isinstance(v, str) else v
    return v if v else default


VPNGATE_API = _env("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = _env(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 检测统一走 CheckSocks5。Action 里用 secrets.YMYM 覆盖为你自己的 Worker；
# Secret 为空时退回下方公共默认值（共享 Worker 易被限流，建议部署自己的）。
WORKER_CHECK_URL = _env("CHECK_WORKER", "https://ip.v77580.fun/check?sstp=vpn:vpn@")
# 注意：这里故意没有 ADMIN_PASSWORD。edgetunnel 的 Bearer 头对 /admin/check
# 无效，不要再加；CheckSocks5 的 /check 本身不需要鉴权。
# CheckSocks5 内部超时约 12s 连接 + 8s 读取，90s 是白等；30s 足够。
# 并发 32 会把 iplocate.io /api/lookup 打出 429 误杀，降到 8。
CONCURRENCY = max(1, int(_env("CHECK_CONCURRENCY", "8")))
CHECK_TIMEOUT = float(_env("CHECK_TIMEOUT", "30"))
CHECK_RETRIES = max(0, int(_env("CHECK_RETRIES", "2")))
RETRY_BACKOFF_BASE = float(_env("RETRY_BACKOFF_BASE", "5"))
MAX_CHECK_NODES = int(_env("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(_env("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = _env("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# 可重试错误：这些不是“节点死了”，而是检测链路被限流/抖动，重试才公平。
# CheckSocks5 经 SSTP 调 www.iplocate.io/api/lookup，burst 时常回 429。
RETRYABLE_SUBSTRINGS = (
    "429",
    "too many requests",
    "/api/lookup",
    "lookup",
    "timed out",
    "timeout",
    "target returned no data",
    "reading target response",
    "connection reset",
    "connection aborted",
)

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

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

# 静态优选域名池
# ---------------------------------------------------------------------------
# 2026-10-12 在中国电信(河北邢台)实测的排序（SNI=worker 域名，直连测总耗时）：
#   第一档 172.64.229.10 → CF 东京 NRT，总耗时 184~211ms（最快）
#   第二档 172.64.229.17x / 104.18.x → NRT / 新加坡 SIN，总耗时 316~427ms
# 已剔除 www.bilibili.com —— 它不是 Cloudflare 域名（解析到国内 106.118.30.x），
# 拿来当入口 100% 失败，白白占掉 1/20 的轮转槽位。
# 顺序 = 优先级，靠前的入口会被分配给排名靠前的节点。
# ---------------------------------------------------------------------------
EDGE_HOSTS = [
    h.strip()
    for h in _env(
        "EDGE_HOSTS",
        # ---- 第一档：实测最快 ----
        "www.mfyx.cn:443,cdn.ctn32.us.kg:443,cdn.204910.best:443,saas.sin.fan:443,"
        # ---- 第二档：可用但慢一档 ----
        "cf.nyanya.moe:443,cf.877774.xyz:443,p.etime.vip:443,"
        "uspto.gov:443,securecircle.com:443,openai.com:443,spring.io:443,op.chinwa.eu.cc:443,"
        "www.leics.police.uk:443,linear.app:443,www.shopify.com:443,www.carousell.sg:443,"
        "www.dbs.com.sg:443,www.vmware.com:443,www.sloomb.com:443",
    ).split(",")
    if h.strip()
]

# Cloudflare 官方 IPv4 段（用于剔除「伪优选域名」）
CF_NETWORKS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_NET_OBJS = [ipaddress.ip_network(n) for n in CF_NETWORKS]

# 优选 API 地址配置 (支持逗号分隔多个，可配置在 GitHub Action Secret / Env 中)
OPTIMAL_API = _env("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443")

NODES_URL = _env("NODES_URL", "https://vip060.github.io/ippp/nodes.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
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
    sys.exit(1)


def _is_retryable(text):
    if not text:
        return False
    low = str(text).lower()
    return any(s in low for s in RETRYABLE_SUBSTRINGS)


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
    }

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        # config 在最后一列（Base64 本身不含逗号），用 fields[-1] 而不是表头
        # 索引，避免 Message 字段里的逗号把列错位。
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[-1].strip(),
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
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)。
    注意：该 API 有时回换行分隔、有时回空格分隔（实测两种都出现过），
    所以按任意空白切分，而不是只按行切分，否则空格格式会丢 5/6 个。
    """
    if not (api_urls_str or "").strip():
        return []

    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                # 该 API 有时回换行分隔、有时回空格分隔，且备注 "CF 电信优选"
                # 里本身带空格——按空白切会把备注切碎（"电信优选" 会被当成
                # 一个端点）。所以用正则直接抽 IP(:port)，备注一律忽略。
                found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", resp.text)
                count = 0
                for endpoint in found:
                    if ":" not in endpoint:
                        endpoint = f"{endpoint}:443"
                    endpoints.append(endpoint)
                    count += 1
                if not found:
                    # 兜底：API 回的不是 IP 而是域名时，按行解析
                    for line in resp.text.strip().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        endpoint = line.split("#")[0].strip()
                        if endpoint:
                            if ":" not in endpoint:
                                endpoint = f"{endpoint}:443"
                            endpoints.append(endpoint)
                            count += 1
                log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints


def resolve_ipv4(host):
    """取域名/IP 的首个 IPv4，失败返回 None"""
    h = host.split(":")[0].strip()
    try:
        return socket.gethostbyname(h)
    except Exception:
        return None


def is_cloudflare_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in net for net in _CF_NET_OBJS)


def probe_edge_host(host):
    """
    判定一个入口是否真的是 Cloudflare 前置。
    正向判据：请求 https://<host>/cdn-cgi/trace 能拿到 colo= / fl= 字段。
    回退判据：解析出的 IP 落在 Cloudflare 官方段内。
    目的：把 www.bilibili.com 这类「根本不是 CF 域名」的伪入口清出去。
    """
    h = host.split(":")[0].strip()
    try:
        r = requests.get(f"https://{h}/cdn-cgi/trace", timeout=8,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
        body = r.text[:400]
        if "colo=" in body and "fl=" in body:
            return True, "CF trace"
    except Exception:
        pass
    ip = resolve_ipv4(host)
    if ip and is_cloudflare_ip(ip):
        return True, f"CF 段 {ip}"
    return False, (ip or "DNS 失败")


def validate_edge_hosts(hosts):
    """
    剔除「伪优选域名」。多线程探测，失败即丢弃（宁可少几个入口，也不要一个必死的入口）。
    单个探测异常不拖垮整轮；最后按落地 IP 去重（多个域名解析到同一 CF IP
    只留第一个，避免浪费轮转槽位）。
    """
    kept, dropped = [], []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(probe_edge_host, h): h for h in hosts}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                ok, note = fut.result()
            except Exception as exc:
                ok, note = False, f"探测异常 {type(exc).__name__}"
            if ok:
                kept.append(h)
            else:
                dropped.append((h, note))
    if dropped:
        log("EDGE POOL", "剔除非 Cloudflare 入口 %d 个: %s"
            % (len(dropped), ", ".join(f"{h}({n})" for h, n in dropped)))
    # 按落地 IP 去重：保留首次出现的域名
    seen_ip, deduped = set(), []
    for h in kept:
        ip = resolve_ipv4(h) or h
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        deduped.append(h)
    if len(deduped) != len(kept):
        log("EDGE POOL", f"按落地 IP 去重: {len(kept)} -> {len(deduped)}")
    return deduped


def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点，并做可用性校验。
    校验全部失败时返回 []（由调用方明确失败，不再悄悄退回未校验的
    EDGE_HOSTS——那样会把伪入口重新放进 nodes.txt）。
    """
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    raw = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            raw.append(h)

    combined = validate_edge_hosts(raw)
    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined


# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
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
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
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
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 检测 Worker（CheckSocks5）
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """
    住宅判定：只信 exit.is_datacenter（= privacy.is_hosting）。
    没有出口信息时返回 unknown，绝不拿 hostname（如 vpn12345）猜住宅，
    否则无出口证据的节点会被误标为住宅、拉低 nodes.txt 的真实有效率。
    """
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    return "unknown"


def check_one(node):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    out["retries"] = 0

    headers = {"User-Agent": "Mozilla/5.0 (gate-checker)"}
    # CheckSocks5 的 /check 不需要鉴权，不要发 Authorization 头。
    # （之前发 Bearer 给 edgetunnel /admin/check 是无效的，还会 302。）

    # 轻微抖动，避免 88 个请求同一毫秒 burst 打出 429
    time.sleep(random.uniform(0, 0.5))

    last_error = None
    for attempt in range(CHECK_RETRIES + 1):
        if attempt > 0:
            out["retries"] = attempt
            backoff = RETRY_BACKOFF_BASE * (2 ** (attempt - 1)) + random.uniform(0, 1)
            log("CHECK", f"重试 {node['host']}:{node['port']} 第 {attempt} 次，等待 {backoff:.1f}s（上次：{last_error}）")
            time.sleep(backoff)
        try:
            # 不复用跨线程 Session：requests.Session 不是线程安全的，
            # 88 个节点每次新建请求的开销可忽略，换线程安全。
            r = requests.get(url, timeout=CHECK_TIMEOUT, headers=headers)
            if r.status_code != 200:
                last_error = f"HTTP {r.status_code}: {r.text[:200]}"
                out["error"] = last_error
                out["worker_error"] = True
                # 429/502/503/504 是 Worker 侧限流/抖动，可重试；其它 4xx 直接判失败
                if r.status_code in (429, 502, 503, 504) and attempt < CHECK_RETRIES:
                    continue
                return out
            try:
                j = r.json()
            except Exception as exc:
                last_error = f"JSON 解析失败: {exc}"
                out["error"] = last_error
                out["worker_error"] = True
                return out
            ok = bool(j.get("success"))
            out["success"] = ok
            out["status"] = "success" if ok else "failed"
            out["latency_ms"] = j.get("responseTime")
            out["colo"] = j.get("colo")
            err_text = None if ok else (j.get("error") or j.get("message") or "check failed")
            out["error"] = err_text
            if not ok and _is_retryable(err_text) and attempt < CHECK_RETRIES:
                last_error = err_text
                # 429/lookup 类错误不是节点死，是检测链路限流：重试，不记为最终失败
                continue
            if not ok:
                return out
            exit_info = j.get("exit") or {}
            if exit_info:
                asn = exit_info.get("asn") or {}
                org = asn.get("org") or asn.get("name") or ""
                out["exit"] = {
                    "ip": exit_info.get("ip"),
                    "country": exit_info.get("country"),
                    "country_code": exit_info.get("country_code"),
                    "city": exit_info.get("city"),
                    "continent": exit_info.get("continent"),
                    "asn": asn.get("asn"),
                    "org": org,
                    "type": asn.get("type"),
                    "is_datacenter": exit_info.get("is_datacenter"),
                }
                out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
            else:
                # 成功但无出口信息：无法证明是住宅，标 unknown，nodes.txt 不收
                out["residential"] = "unknown"
            return out
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            out["error"] = last_error
            out["worker_error"] = True
            if _is_retryable(last_error) and attempt < CHECK_RETRIES:
                continue
            return out
    out["error"] = last_error or out.get("error")
    return out


def check_all(nodes):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    residential = [r for r in available if r.get("residential") == "residential"]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
        "unknown_est": sum(1 for n in available if n["residential"] == "unknown"),
        "residential_nodes": len(residential),
        "retried": sum(1 for n in results if n.get("retries")),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
        "residential": residential,
    }
    return data


def build_nodes_text(data, edge_hosts):
    """
    生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://...
    只收住宅节点（residential）。机房/未知不进 nodes.txt，避免把
    非住宅混进去拉低“住宅有效率”。
    """
    if not edge_hosts:
        raise RuntimeError("没有可用的 Cloudflare 入口（EDGE_HOSTS / OPTIMAL_API 校验全部失败），不生成 nodes.txt")
    residential = data.get("residential") or [
        n for n in data.get("available", []) if n.get("residential") == "residential"
    ]
    if not residential:
        return ""
    # 按国家分组，组内住宅按延迟排序；入口轮转分配
    by_country = {}
    for n in residential:
        by_country.setdefault(n.get("country") or "未知", []).append(n)
    ordered = sorted(
        by_country.items(),
        key=lambda kv: (-len(kv[1]), str(kv[1][0].get("country_code") or kv[0])),
    )
    # 更新时间戳塞进第一条节点的备注里（不另起一行，避免 edgetunnel
    # 把注释行当成一个入口）。例：2026-10-13-140142-UTC
    ts = (data.get("generated_at") or "").replace(" ", "-").replace(":", "")
    lines = []
    idx = 0
    for cname, nodes in ordered:
        code = str((nodes[0].get("country_code") or "?")).upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes_sorted = sorted(
            nodes,
            key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or ""),
        )
        for i, n in enumerate(nodes_sorted, 1):
            entry = edge_hosts[idx % len(edge_hosts)]
            suffix = f"-更新{ts}" if idx == 0 and ts else ""
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}{suffix}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_text = build_nodes_text(data, edge_hosts)
    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(nodes_text)

    return data_path, html_path, nodes_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s, 失败重试 {CHECK_RETRIES} 次)")
    t0 = time.time()
    results = check_all(uniq)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    residential = [r for r in success if r.get("residential") == "residential"]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}（其中住宅 {len(residential)}）")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    if not residential:
        die("本轮无住宅节点（成功节点全部为机房/未知，或全部检测失败）— 不覆盖旧文件，避免发布空 nodes.txt")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}，住宅: {len(residential)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts()
    if not edge_hosts:
        die("Cloudflare 入口校验全部失败（静态 + API 均无可用入口）— 不生成 nodes.txt，避免发布必死入口")

    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
