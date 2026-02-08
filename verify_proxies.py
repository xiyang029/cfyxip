import requests
import re
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_proxy_string(proxy_str):
    """自适应解析多种格式"""
    proxy_str = proxy_str.strip()
    if "socks://" in proxy_str or "socks5://" in proxy_str:
        content = proxy_str.split("://")[1].split("?")[0]
        try:
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

def test_proxy(raw_proxy):
    """测试函数"""
    formatted_proxy = parse_proxy_string(raw_proxy)
    # 使用 socks5h 确保远程 DNS 解析
    proxies = {
        "http": formatted_proxy.replace("socks5://", "socks5h://"),
        "https": formatted_proxy.replace("socks5://", "socks5h://")
    }
    
    try:
        # Actions 环境网络较好，设置 6秒超时筛选优质代理
        resp = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=6)
        if resp.status_code == 200:
            return True, raw_proxy, resp.json().get('ip')
    except requests.exceptions.ConnectTimeout:
        return False, "Timeout", None
    except requests.exceptions.SSLError:
        return False, "SSLError", None
    except Exception as e:
        return False, type(e).__name__, None
    return False, "Unknown", None

def main():
    target_url = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json"
    
    print(f"正在获取代理列表...")
    try:
        resp = requests.get(target_url, timeout=15)
        remote_proxies = [item['proxy'] for item in resp.json() if 'proxy' in item]
    except Exception as e:
        print(f"获取失败: {e}")
        remote_proxies = []

    all_proxies = list(set(remote_proxies))
    print(f"开始验证 {len(all_proxies)} 个代理...")

    valid_results = []
    
    # 使用 50 线程并发
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in all_proxies}
        for future in as_completed(future_to_proxy):
            success, raw_or_err, out_ip = future.result()
            if success:
                print(f"✅ 成功: {out_ip}")
                valid_results.append(raw_or_err)
            # 可以在此处打印错误进行调试，但为了 Actions 日志整洁默认只打印成功

    # 1. 保存为 TXT (每行一个)
    with open("valid_proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(valid_results))

    # 2. 保存为 JSON
    with open("valid_proxies.json", "w", encoding="utf-8") as f:
        json.dump({
            "count": len(valid_results),
            "list": valid_results
        }, f, indent=4, ensure_ascii=False)

    print(f"\n验证完成！可用数量: {len(valid_results)}")

if __name__ == "__main__":
    main()