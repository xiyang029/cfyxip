import requests
import re
import base64
import json
import time
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置区 ---
IPINFO_TOKEN = "bb8e53e4d8d6a1"
TARGET_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json"
MAX_WORKERS = 40   # 并发线程数（GA 环境建议 20–40，过大易触发出口限流/连接失败）
TIMEOUT = 1        # 单次检测超时(秒)
SOCKS5_CHECK_TARGET = ("1.1.1.1", 80)
CLOUDFLARE_IP_API = "https://www.wetest.vip/api/cf2dns/get_cloudflare_ip?key=o1zrmHAF&type=v4"
OUTPUT_FILE = "cfyxip.txt"

def get_real_geo(ip):
    """使用 ipinfo.io 获取高精度地理位置"""
    try:
        url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('country', '未知')
    except:
        pass
    return "未知"

def parse_socks5_parts(proxy_str):
    """解析代理字符串为 (host, port, user, pass)，供原生 SOCKS5 检测用。"""
    raw = proxy_str.strip().split('#')[0].strip()
    if not raw:
        return None
    lower = raw.lower()
    # socks://base64
    if lower.startswith('socks://'):
        before = raw.split('?')[0].strip()
        b64 = re.sub(r'^socks://', '', before, flags=re.I).rstrip('/')
        if not b64:
            return None
        try:
            decoded = base64.b64decode(b64).decode('utf-8')
            at = decoded.find('@')
            if at == -1:
                return None
            user_pass, host_port = decoded[:at], decoded[at+1:]
            user, _, passwd = user_pass.partition(':')
            last_colon = host_port.rfind(':')
            host, port_s = host_port[:last_colon].strip(), host_port[last_colon+1:].strip()
            port = int(port_s)
            if not host or port < 1 or port > 65535:
                return None
            return (host, port, (user or '').strip(), (passwd or '').strip())
        except Exception:
            return None
    # socks5://
    if lower.startswith('socks5://'):
        rest = raw[9:].rstrip('/')
        at = rest.find('@')
        if at != -1:
            user_pass, host_port = rest[:at], rest[at+1:]
            user, _, passwd = user_pass.partition(':')
            last_colon = host_port.rfind(':')
            host, port_s = host_port[:last_colon].strip(), host_port[last_colon+1:].strip()
            try:
                port = int(port_s)
            except ValueError:
                return None
            if not host or port < 1 or port > 65535:
                return None
            return (host, port, (user or '').strip(), (passwd or '').strip())
        parts = rest.split(':')
        if len(parts) >= 4:
            host, port_s, user, passwd = parts[0], parts[1], parts[2], ':'.join(parts[3:])
            try:
                port = int(port_s)
            except ValueError:
                return None
            if not host or port < 1 or port > 65535:
                return None
            return (host, port, (user or '').strip(), (passwd or '').strip())
        if len(parts) >= 2:
            host, port_s = parts[0], parts[1]
            try:
                port = int(port_s)
            except ValueError:
                return None
            if not host or port < 1 or port > 65535:
                return None
            return (host, port, '', '')
    at = raw.find('@')
    if at != -1:
        user_pass, host_port = raw[:at], raw[at+1:]
        user, _, passwd = user_pass.partition(':')
        last_colon = host_port.rfind(':')
        host, port_s = host_port[:last_colon].strip(), host_port[last_colon+1:].strip()
        try:
            port = int(port_s)
        except ValueError:
            return None
        if not host or port < 1 or port > 65535:
            return None
        return (host, port, (user or '').strip(), (passwd or '').strip())
    parts = raw.split(':')
    if len(parts) >= 2:
        host, port_s = parts[0], parts[1]
        try:
            port = int(port_s)
        except ValueError:
            return None
        if host and 1 <= port <= 65535:
            return (host.strip(), port, '', '')
    return None

def socks5_connect_only(host, port, user, passwd, timeout):
    """SOCKS5 握手 + CONNECT，返回 (成功, 延迟ms)。"""
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except Exception:
        return False, 0
    try:
        has_auth = bool(user or passwd)
        method_buf = bytes([0x05, 0x02, 0x00, 0x02]) if has_auth else bytes([0x05, 0x01, 0x00])
        sock.sendall(method_buf)
        buf = sock.recv(32)
        if len(buf) < 2 or buf[0] != 0x05:
            return False, 0
        chosen = buf[1]
        if chosen == 0x02:
            u, p = (user or '').encode('utf-8'), (passwd or '').encode('utf-8')
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            buf = sock.recv(32)
            if len(buf) < 2 or buf[1] != 0x00:
                return False, 0
        elif chosen != 0x00:
            return False, 0
        target_host, target_port = SOCKS5_CHECK_TARGET
        host_b = target_host.encode('utf-8')
        sock.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host_b)]) + host_b + struct.pack('>H', target_port))
        buf = sock.recv(32)
        if len(buf) < 4 or buf[0] != 0x05 or buf[1] != 0x00:
            return False, 0
        return True, int((time.perf_counter() - t0) * 1000)
    except Exception:
        return False, 0
    finally:
        try:
            sock.close()
        except Exception:
            pass

def format_cloudflare_ip(ip_info):
    """格式化 Cloudflare IP 信息为指定格式"""
    ip = ip_info.get('ip')
    line_name = ip_info.get('line_name')
    colo = ip_info.get('colo')
    return f"{ip}:443#{line_name}-{colo}"

def fetch_cloudflare_ips():
    """获取并解析 Cloudflare IP 数据"""
    print("🚀 正在获取 Cloudflare 优选 IP...")
    try:
        resp = requests.get(CLOUDFLARE_IP_API, timeout=15)
        if resp.status_code != 200:
            print(f"❌ 获取失败: HTTP {resp.status_code}")
            return []
        data = resp.json()
        if not data.get('status'):
            print(f"❌ 获取失败: {data.get('msg', '未知错误')}")
            return []
        
        # 提取所有线路的 IP 信息
        all_ips = []
        info = data.get('info', {})
        for line_type, ip_list in info.items():
            for ip_info in ip_list:
                formatted = format_cloudflare_ip(ip_info)
                all_ips.append(formatted)
        
        print(f"✅ 成功获取 {len(all_ips)} 个 Cloudflare IP")
        return all_ips
    except Exception as e:
        print(f"❌ 获取失败: {e}")
        return []

def process_node(item):
    raw_proxy = item['proxy']
    orig_country = item.get('country', 'ZZ')

    parts = parse_socks5_parts(raw_proxy)
    if not parts:
        return False, None, None, 0
    host, port, user, passwd = parts
    ok, latency_ms = socks5_connect_only(host, port, user, passwd, TIMEOUT)
    if not ok:
        return False, None, None, 0

    # 用 parts 拼回 URL，走代理请求 ipify 取出口 IP 并打标签
    fmt = f"socks5://{user}:{passwd}@{host}:{port}" if (user or passwd) else f"socks5://{host}:{port}"
    proxies = {"http": fmt.replace("socks5://", "socks5h://"), "https": fmt.replace("socks5://", "socks5h://")}
    try:
        resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=TIMEOUT)
        if resp.status_code != 200:
            return False, None, None, 0
        out_ip = resp.json().get('ip')
        if orig_country.upper() in ["ZZ", "UNKNOWN", "未知"]:
            label = get_real_geo(out_ip)
        else:
            label = orig_country
        return True, f"{raw_proxy}#{label}", out_ip, latency_ms
    except Exception:
        pass
    return False, None, None, 0

def main():
    # 获取 Cloudflare 优选 IP
    cloudflare_ips = fetch_cloudflare_ips()
    if cloudflare_ips:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(cloudflare_ips))
        print(f"📂 Cloudflare 优选 IP 已保存至 {OUTPUT_FILE}")
    
    # 原有代理验证功能
    print(f"\n🚀 正在从源获取代理列表...")
    try:
        resp = requests.get(TARGET_URL, timeout=15)
        raw_list = resp.json()
        
        # 封装任务，去重处理
        tasks = []
        seen_proxies = set()
        for item in raw_list:
            p = item.get('proxy')
            if p and p not in seen_proxies:
                tasks.append({
                    "proxy": p,
                    "country": item.get('geolocation', {}).get('country', 'ZZ')
                })
                seen_proxies.add(p)
    except Exception as e:
        print(f"❌ 获取失败: {e}")
        return

    print(f"🔍 开始并发验证 {len(tasks)} 个代理 (线程数: {MAX_WORKERS})...")

    valid_results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(process_node, task): task for task in tasks}
        
        for future in as_completed(future_to_node):
            success, final_str, out_ip, latency_ms = future.result()
            if success:
                geo_info = final_str.split('#')[-1]
                print(f"✅ 有效: {out_ip} [{geo_info}] {latency_ms}ms")
                valid_results.append(final_str)

    # 保存验证结果
    with open("valid_proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(valid_results))

    print(f"\n✨ 验证完成！可用节点: {len(valid_results)}")
    print(f"📂 结果已保存至 valid_proxies.txt")

if __name__ == "__main__":
    main()