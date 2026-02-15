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
MAX_WORKERS = 40  # 并发线程数
TIMEOUT = 6      # 代理测试超时时间
SOCKS5_CHECK_TARGET = ("1.1.1.1", 80)

def get_real_geo(ip):
    """使用 ipinfo.io 获取高精度地理位置"""
    try:
        url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            country = data.get('country', '未知')
            city = data.get('city', '')
            # 如果城市名存在且不等于国家代码，则拼接
            if city and city.lower() != country.lower() and city != "Unknown":
                return f"{country}-{city}"
            return country
    except:
        pass
    return "未知"

def parse_proxy_string(proxy_str):
    """自适应解析多种格式并提取纯净代理地址"""
    proxy_str = proxy_str.strip().split('#')[0] # 去掉可能存在的旧标签
    if "socks://" in proxy_str or "socks5://" in proxy_str:
        content = proxy_str.split("://")[1].split("?")[0]
        try:
            # 尝试处理 base64 格式
            decoded = base64.b64decode(content).decode('utf-8')
            return f"socks5://{decoded}"
        except: pass
    
    if "@" in proxy_str:
        return proxy_str if "://" in proxy_str else f"socks5://{proxy_str}"
        
    clean_str = re.sub(r'^socks5?://', '', proxy_str)
    parts = clean_str.split(':')
    if len(parts) == 4:
        ip, port, user, pw = parts
        return f"socks5://{user}:{pw}@{ip}:{port}"
    return f"socks5://{proxy_str}" if not proxy_str.startswith("socks") else proxy_str

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
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except Exception:
        return False
    try:
        has_auth = bool(user or passwd)
        if has_auth:
            method_buf = bytes([0x05, 0x02, 0x00, 0x02])
        else:
            method_buf = bytes([0x05, 0x01, 0x00])
        sock.sendall(method_buf)
        buf = sock.recv(32)
        if len(buf) < 2 or buf[0] != 0x05:
            return False
        chosen = buf[1]
        if chosen == 0x02:
            u, p = (user or '').encode('utf-8'), (passwd or '').encode('utf-8')
            auth_buf = bytes([0x01, len(u)]) + u + bytes([len(p)]) + p
            sock.sendall(auth_buf)
            buf = sock.recv(32)
            if len(buf) < 2 or buf[1] != 0x00:
                return False
        elif chosen != 0x00:
            return False
        target_host, target_port = SOCKS5_CHECK_TARGET
        host_bytes = target_host.encode('utf-8')
        connect_buf = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + struct.pack('>H', target_port)
        sock.sendall(connect_buf)
        buf = sock.recv(32)
        if len(buf) < 4 or buf[0] != 0x05 or buf[1] != 0x00:
            return False
        return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass

def process_node(item):
    raw_proxy = item['proxy']
    orig_country = item.get('country', 'ZZ')
    orig_city = item.get('city', '')

    # 1. 仅 SOCKS5 检测：握手 + CONNECT 到 1.1.1.1:80
    parts = parse_socks5_parts(raw_proxy)
    if not parts:
        return False, None, None
    host, port, user, passwd = parts
    if not socks5_connect_only(host, port, user, passwd, TIMEOUT):
        return False, None, None

    # 2. SOCKS5 通过后，用代理请求 ipify 取出口 IP 并打地理标签
    formatted_proxy = parse_proxy_string(raw_proxy)
    proxies = {
        "http": formatted_proxy.replace("socks5://", "socks5h://"),
        "https": formatted_proxy.replace("socks5://", "socks5h://")
    }
    try:
        resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=TIMEOUT)
        if resp.status_code != 200:
            return False, None, None
        out_ip = resp.json().get('ip')
        if orig_country.upper() in ["ZZ", "UNKNOWN", "未知"]:
            label = get_real_geo(out_ip)
        else:
            label = f"{orig_country}-{orig_city}" if (orig_city and orig_city != "Unknown") else orig_country
        return True, f"{raw_proxy}#{label}", out_ip
    except Exception:
        pass
    return False, None, None

def main():
    print(f"🚀 正在从源获取代理列表...")
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
                    "country": item.get('geolocation', {}).get('country', 'ZZ'),
                    "city": item.get('geolocation', {}).get('city', '')
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
            success, final_str, out_ip = future.result()
            if success:
                geo_info = final_str.split('#')[-1]
                print(f"✅ 有效: {out_ip} [{geo_info}]")
                valid_results.append(final_str)

    # --- 结果保存 ---
    # 1. 保存为 TXT
    with open("valid_proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(valid_results))

    # 2. 保存为 JSON (包含更多统计信息)
    with open("valid_proxies.json", "w", encoding="utf-8") as f:
        json.dump({
            "update_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_valid": len(valid_results),
            "proxies": valid_results
        }, f, indent=4, ensure_ascii=False)

    print(f"\n✨ 验证完成！可用节点: {len(valid_results)}")
    print(f"📂 结果已保存至 valid_proxies.txt 和 valid_proxies.json")

if __name__ == "__main__":
    main()