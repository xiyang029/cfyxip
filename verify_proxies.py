import base64
import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit

import requests

# IPINFO_TOKEN 用于优先查询出口国家。
IPINFO_TOKEN = "bb8e53e4d8d6a1"
# TARGET_URL 用于获取原始 SOCKS5 代理列表。
TARGET_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json"
# CLOUDFLARE_IP_API 用于获取 Cloudflare 优选 IP。
CLOUDFLARE_IP_API = "https://www.wetest.vip/api/cf2dns/get_cloudflare_ip?key=o1zrmHAF&type=v4"
# OUTPUT_FILE 用于保存 Cloudflare 优选 IP 结果。
OUTPUT_FILE = "cfyxip.txt"
# VALID_PROXY_FILE 用于保存可用 SOCKS5 结果。
VALID_PROXY_FILE = "valid_proxies.txt"
# MAX_WORKERS 用于限制并发检测线程数量。
MAX_WORKERS = 40
# CONNECT_TIMEOUT 用于 SOCKS5 握手和真实请求的超时。
CONNECT_TIMEOUT = 3
# GEO_TIMEOUT 用于出口国家查询的超时。
GEO_TIMEOUT = 5
# SOCKS5_HANDSHAKE_TARGET 用于原生握手阶段的目标站点。
SOCKS5_HANDSHAKE_TARGET = ("api.ipify.org", 443)
# VERIFY_ENDPOINTS 用于确认代理真实出口 IP。
VERIFY_ENDPOINTS = (
    ("https://api.ipify.org?format=json", "json"),
    ("https://api64.ipify.org?format=json", "json"),
    ("https://icanhazip.com", "text"),
)
# REQUEST_HEADERS 用于统一远端请求头。
REQUEST_HEADERS = {"User-Agent": "cfyxip/2.0"}
# GEO_CACHE_LOCK 用于保护出口国家缓存的并发读写。
GEO_CACHE_LOCK = Lock()


def request_content(
    url: str,
    timeout: float,
    proxies: Optional[Dict[str, str]] = None,
    expect: str = "json",
) -> Optional[Any]:
    """带有限次重试地获取远端内容。"""
    for _ in range(2):
        try:
            response = requests.get(url, headers=REQUEST_HEADERS, proxies=proxies, timeout=timeout)
            if response.status_code != 200:
                continue
            if expect == "json":
                return response.json()
            return response.text.strip()
        except (requests.RequestException, ValueError):
            continue
    return None


def parse_socks5_proxy(proxy_str: str) -> Optional[Tuple[str, int, str, str, str]]:
    """把代理字符串解析成标准 SOCKS5 连接信息。"""
    raw = proxy_str.strip().split("#", 1)[0].split("?", 1)[0].strip().rstrip("/")
    if not raw:
        return None
    if raw.lower().startswith("socks://"):
        encoded = raw.split("://", 1)[1].strip()
        padding = "=" * (-len(encoded) % 4)
        try:
            raw = base64.b64decode(encoded + padding).decode("utf-8").strip()
        except (ValueError, UnicodeDecodeError):
            return None
    body = raw[9:] if raw.lower().startswith("socks5://") else raw
    if "@" not in body and body.count(":") >= 3 and not body.startswith("["):
        host, port_text, user, password = body.split(":", 3)
        try:
            port = int(port_text)
        except ValueError:
            return None
        if not host or not 1 <= port <= 65535:
            return None
        auth = f"{quote(user.strip(), safe='')}:{quote(password.strip(), safe='')}@"
        return host.strip(), port, user.strip(), password.strip(), f"socks5://{auth}{host.strip()}:{port}"
    normalized = raw if "://" in raw else f"socks5://{raw}"
    try:
        parsed = urlsplit(normalized)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host or port is None or not 1 <= port <= 65535:
        return None
    user = unquote(parsed.username or "").strip()
    password = unquote(parsed.password or "").strip()
    host_text = f"[{host}]" if ":" in host and not host.startswith("[") else host
    auth = ""
    if user or password:
        auth = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    return host, port, user, password, f"socks5://{auth}{host_text}:{port}"


def extract_ip(payload: Any) -> Optional[str]:
    """从不同出口服务的响应中提取合法 IP。"""
    candidates: List[str] = []
    if isinstance(payload, dict):
        for key in ("ip", "origin", "query"):
            value = str(payload.get(key, "")).strip()
            if value:
                candidates.extend(part.strip() for part in value.split(","))
    elif isinstance(payload, str):
        candidates.extend(part.strip() for part in payload.replace("\n", ",").split(","))
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def lookup_country(ip: str, geo_cache: Dict[str, str]) -> str:
    """查询出口 IP 的真实国家并缓存结果。"""
    with GEO_CACHE_LOCK:
        cached_country = geo_cache.get(ip)
    if cached_country:
        return cached_country
    country = ""
    ipinfo_url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}" if IPINFO_TOKEN else f"https://ipinfo.io/{ip}/json"
    ipinfo_data = request_content(ipinfo_url, GEO_TIMEOUT)
    if isinstance(ipinfo_data, dict):
        country = str(ipinfo_data.get("country", "")).strip().upper()
    if not country:
        fallback_data = request_content(f"https://ipwho.is/{ip}", GEO_TIMEOUT)
        if isinstance(fallback_data, dict) and fallback_data.get("success", True):
            country = str(fallback_data.get("country_code", "")).strip().upper()
    final_country = country or "未知"
    with GEO_CACHE_LOCK:
        geo_cache[ip] = final_country
    return final_country


def socks5_probe(host: str, port: int, user: str, password: str, timeout: float) -> Tuple[bool, int]:
    """执行原生 SOCKS5 握手并确认代理可连到目标站点。"""
    start_time = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            reader = sock.makefile("rb")
            methods = b"\x00\x02" if user or password else b"\x00"
            sock.sendall(struct.pack("!BB", 5, len(methods)) + methods)
            reply = reader.read(2)
            if len(reply) != 2 or reply[0] != 5 or reply[1] == 0xFF:
                return False, 0
            if reply[1] == 0x02:
                user_bytes = user.encode("utf-8")
                password_bytes = password.encode("utf-8")
                auth_pack = struct.pack("!BB", 1, len(user_bytes)) + user_bytes
                auth_pack += struct.pack("!B", len(password_bytes)) + password_bytes
                sock.sendall(auth_pack)
                auth_reply = reader.read(2)
                if len(auth_reply) != 2 or auth_reply[1] != 0x00:
                    return False, 0
            target_host, target_port = SOCKS5_HANDSHAKE_TARGET
            host_bytes = target_host.encode("utf-8")
            connect_pack = b"\x05\x01\x00\x03" + struct.pack("!B", len(host_bytes)) + host_bytes
            sock.sendall(connect_pack + struct.pack("!H", target_port))
            header = reader.read(4)
            if len(header) != 4 or header[0] != 5 or header[1] != 0x00:
                return False, 0
            atyp = header[3]
            if atyp == 0x01 and len(reader.read(4)) != 4:
                return False, 0
            if atyp == 0x03:
                domain_len = reader.read(1)
                if len(domain_len) != 1 or len(reader.read(domain_len[0])) != domain_len[0]:
                    return False, 0
            if atyp == 0x04 and len(reader.read(16)) != 16:
                return False, 0
            if atyp not in (0x01, 0x03, 0x04) or len(reader.read(2)) != 2:
                return False, 0
            return True, int((time.perf_counter() - start_time) * 1000)
    except (OSError, ValueError):
        return False, 0


def process_proxy(item: Dict[str, str], geo_cache: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """校验单个代理的握手、真实出口和国家标签。"""
    parsed = parse_socks5_proxy(item.get("proxy", ""))
    if not parsed:
        return None
    host, port, user, password, proxy_url = parsed
    ok, latency_ms = socks5_probe(host, port, user, password, CONNECT_TIMEOUT)
    if not ok:
        return None
    proxy_url_h = proxy_url.replace("socks5://", "socks5h://", 1)
    proxy_map = {"http": proxy_url_h, "https": proxy_url_h}
    outbound_ip = None
    for url, expect in VERIFY_ENDPOINTS:
        outbound_ip = extract_ip(request_content(url, CONNECT_TIMEOUT, proxy_map, expect))
        if outbound_ip:
            break
    if not outbound_ip:
        return None
    source_country = str(item.get("country", "")).strip().upper()
    real_country = lookup_country(outbound_ip, geo_cache)
    final_country = real_country if real_country != "未知" else (source_country or "未知")
    return {
        "line": f"{proxy_url}#{final_country}",
        "ip": outbound_ip,
        "latency": latency_ms,
        "country": final_country,
    }


def fetch_cloudflare_ips() -> List[str]:
    """获取、清洗并稳定排序 Cloudflare 优选 IP 结果。"""
    payload = request_content(CLOUDFLARE_IP_API, 15)
    if not isinstance(payload, dict) or not payload.get("status"):
        message = payload.get("msg", "接口返回异常") if isinstance(payload, dict) else "接口返回异常"
        print(f"❌ Cloudflare 优选 IP 获取失败: {message}")
        return []
    info = payload.get("info", {})
    if not isinstance(info, dict):
        print("❌ Cloudflare 优选 IP 数据结构异常")
        return []
    cleaned: set[str] = set()
    for ip_list in info.values():
        if not isinstance(ip_list, list):
            continue
        for entry in ip_list:
            if not isinstance(entry, dict):
                continue
            ip_text = str(entry.get("ip", "")).strip()
            line_name = str(entry.get("line_name", "")).strip() or "未知线路"
            colo = str(entry.get("colo", "")).strip() or "未知机房"
            try:
                ip_value = str(ipaddress.ip_address(ip_text))
            except ValueError:
                continue
            cleaned.add(f"{ip_value}:443#{line_name}-{colo}")
    return sorted(cleaned, key=lambda value: (value.split("#", 1)[-1], value))


def load_proxy_tasks() -> List[Dict[str, str]]:
    """拉取代理源并去重为待验证任务列表。"""
    payload = request_content(TARGET_URL, 15)
    if not isinstance(payload, list):
        print("❌ 代理源返回异常")
        return []
    tasks: List[Dict[str, str]] = []
    seen_proxies = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        proxy = str(entry.get("proxy", "")).strip()
        if not proxy or proxy in seen_proxies:
            continue
        geolocation = entry.get("geolocation", {})
        country = str(geolocation.get("country", "")).strip().upper() if isinstance(geolocation, dict) else ""
        tasks.append({"proxy": proxy, "country": country})
        seen_proxies.add(proxy)
    return tasks


def write_lines(path: str, lines: List[str]) -> None:
    """把结果列表按行写入文本文件。"""
    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def main() -> None:
    """执行 Cloudflare 优选 IP 获取与 SOCKS5 代理验证。"""
    print("🚀 开始获取 Cloudflare 优选 IP...")
    cloudflare_ips = fetch_cloudflare_ips()
    if cloudflare_ips:
        write_lines(OUTPUT_FILE, cloudflare_ips)
        print(f"✅ Cloudflare 优选 IP 已更新: {len(cloudflare_ips)} 条")
    else:
        print("⚠️ Cloudflare 优选 IP 未更新，保留现有结果")
    print("\n🚀 开始获取 SOCKS5 代理源...")
    tasks = load_proxy_tasks()
    if not tasks:
        print("❌ 未获取到可验证的代理任务")
        return
    print(f"🔍 开始验证 {len(tasks)} 个代理，线程数: {MAX_WORKERS}")
    geo_cache: Dict[str, str] = {}
    valid_results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(process_proxy, task, geo_cache): task["proxy"] for task in tasks}
        for future in as_completed(future_map):
            try:
                result = future.result()
            except Exception:
                result = None
            if not result:
                continue
            print(f"✅ 有效: {result['ip']} [{result['country']}] {result['latency']}ms")
            valid_results.append(result)
    valid_results.sort(key=lambda item: (item["country"], item["latency"], item["line"]))
    write_lines(VALID_PROXY_FILE, [item["line"] for item in valid_results])
    print(f"\n✨ 验证完成，可用节点: {len(valid_results)}")
    print(f"📂 结果已保存至 {VALID_PROXY_FILE}")


if __name__ == "__main__":
    main()
