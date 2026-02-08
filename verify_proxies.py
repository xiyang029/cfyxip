import requests
import re
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置区 ---
IPINFO_TOKEN = "bb8e53e4d8d6a1"
TARGET_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json"
MAX_WORKERS = 40  # 并发线程数
TIMEOUT = 6      # 代理测试超时时间

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

def process_node(item):
    """单个节点处理核心逻辑：测试 -> 补全 -> 格式化"""
    raw_proxy = item['proxy']
    orig_country = item.get('country', 'ZZ')
    orig_city = item.get('city', '')
    
    formatted_proxy = parse_proxy_string(raw_proxy)
    proxies = {
        "http": formatted_proxy.replace("socks5://", "socks5h://"),
        "https": formatted_proxy.replace("socks5://", "socks5h://")
    }
    
    try:
        # 1. 验证代理是否可用
        resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=TIMEOUT)
        if resp.status_code == 200:
            out_ip = resp.json().get('ip')
            
            # 2. 补全地理信息：如果是 ZZ/Unknown 则调用 ipinfo
            if orig_country.upper() in ["ZZ", "UNKNOWN", "未知"]:
                label = get_real_geo(out_ip)
            else:
                # 原始数据可用，直接拼接
                if orig_city and orig_city != "Unknown":
                    label = f"{orig_country}-{orig_city}"
                else:
                    label = orig_country
            
            # 3. 最终返回格式化字符串 (Worker 要求的格式)
            return True, f"{raw_proxy}#{label}", out_ip
    except:
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