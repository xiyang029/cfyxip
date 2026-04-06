# cfyxip

自动筛选可用 SOCKS5 代理，并同步更新 Cloudflare 优选 IP。

## 输出文件

- `valid_proxies.txt`：通过原生握手和真实出口校验的 SOCKS5 代理，格式为 `socks5://host:port#国家`
- `cfyxip.txt`：清洗、去重后的 Cloudflare 优选 IP，格式为 `IP:443#线路-机房`

## 检测规则

- 先执行原生 SOCKS5 握手，确认代理可以连通 `api.ipify.org:443`
- 再通过 `socks5h://` 发起真实外网请求，确认代理具备真实转发能力
- 优先使用出口 IP 反查真实国家，反查失败时回退到源站标签
- Cloudflare 优选 IP 只在接口返回合法数据时更新，并进行格式校验、去重和稳定排序

## 本地运行

```bash
node verify_proxies.js
```

Node.js 原生模块，无需安装额外依赖。

## IP 来源

### Cloudflare 优选 IP
- https://cf.090227.xyz/ct?ips=6 (电信)
- https://cf.090227.xyz/cu (联通)
- https://cf.090227.xyz/cmcc?ips=8 (移动)
- https://cf.090227.xyz/CloudFlareYes (多线)
- https://cf.090227.xyz/ip.164746.xyz

### SOCKS5 代理源
- https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json

## GitHub Actions

- `.github/workflows/check.yml` 每小时自动运行一次
- 支持手动触发
- 仅在结果发生变化时提交

## 结果示例

```text
socks5://134.199.159.23:1080#AU
104.19.156.70:443#移动-HKG
```
