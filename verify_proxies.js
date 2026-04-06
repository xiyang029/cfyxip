const net = require("net");
const tls = require("tls");
const https = require("https");
const http = require("http");
const { URL } = require("url");
const fs = require("fs");

const IPINFO_TOKEN = "bb8e53e4d8d6a1";
const TARGET_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json";
const CLOUDFLARE_IP_APIS = [
  "https://cf.090227.xyz/ct?ips=6",
  "https://cf.090227.xyz/cu",
  "https://cf.090227.xyz/cmcc?ips=8",
  "https://cf.090227.xyz/CloudFlareYes",
  "https://cf.090227.xyz/ip.164746.xyz"
];
const OUTPUT_FILE = "cfyxip.txt";
const VALID_PROXY_FILE = "valid_proxies.txt";
const MAX_WORKERS = 40;
const CONNECT_TIMEOUT = 3;
const GEO_TIMEOUT = 5;
const SOCKS5_HANDSHAKE_TARGET = { host: "api.ipify.org", port: 443 };
const VERIFY_ENDPOINTS = [
  { url: "https://api.ipify.org?format=json", expect: "json" },
  { url: "https://api64.ipify.org?format=json", expect: "json" },
  { url: "https://icanhazip.com", expect: "text" }
];
const REQUEST_HEADERS = { "User-Agent": "cfyxip/2.0" };

const geoCache = new Map();

function httpGet(url, timeout = 15) {
  return new Promise((resolve) => {
    const protocol = url.startsWith("https") ? https : http;
    const req = protocol.get(url, { headers: REQUEST_HEADERS }, (res) => {
      if (res.statusCode !== 200) {
        resolve(null);
        return;
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data.trim());
        }
      });
    });
    req.on("error", () => resolve(null));
    req.setTimeout(timeout * 1000, () => {
      req.destroy();
      resolve(null);
    });
  });
}

function extractIP(payload) {
  const candidates = [];
  if (typeof payload === "object" && payload !== null) {
    for (const key of ["ip", "origin", "query"]) {
      const val = String(payload[key] || "").trim();
      if (val) candidates.push(...val.split(",").map((s) => s.trim()));
    }
  } else if (typeof payload === "string") {
    candidates.push(...payload.replace(/\n/g, ",").split(",").map((s) => s.trim()));
  }
  for (const candidate of candidates) {
    const ip = candidate.match(/(\d{1,3}\.){3}\d{1,3}/);
    if (ip) return ip[0];
  }
  return null;
}

async function lookupCountry(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip);
  let country = "";
  try {
    const data = await httpGet(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`, GEO_TIMEOUT);
    if (data && data.country) country = String(data.country).toUpperCase().trim();
  } catch {}
  if (!country) {
    try {
      const data = await httpGet(`https://ipwho.is/${ip}`, GEO_TIMEOUT);
      if (data && data.success !== false && data.country_code) {
        country = String(data.country_code).toUpperCase().trim();
      }
    } catch {}
  }
  const result = country || "未知";
  geoCache.set(ip, result);
  return result;
}

function parseSocks5Proxy(proxyStr) {
  let raw = proxyStr.trim().split("#")[0].split("?")[0].trim().replace(/\/$/, "");
  if (!raw) return null;
  if (raw.toLowerCase().startsWith("socks://")) {
    try {
      const encoded = raw.split("://")[1];
      const padding = "=".repeat((-encoded.length) % 4);
      raw = Buffer.from(encoded + padding, "base64").toString("utf-8").trim();
    } catch {
      return null;
    }
  }
  const body = raw.toLowerCase().startsWith("socks5://") ? raw.slice(9) : raw;
  const atCount = (body.match(/@/g) || []).length;
  if (atCount === 1 && body.split(":").length >= 3) {
    const [creds, hostPart] = body.split("@");
    const [user, password] = creds.split(":");
    const hp = hostPart.split(":");
    const host = hp[0];
    const port = parseInt(hp[1]);
    if (!host || isNaN(port) || port < 1 || port > 65535) return null;
    return { host, port, user, password, url: `socks5://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}` };
  }
  if (atCount === 0 && body.split(":").length >= 3) {
    const parts = body.split(":");
    if (parts.length === 4 && !parts[0].includes(".")) {
      const [host, port, user, password] = parts;
      const p = parseInt(port);
      if (!host || isNaN(p) || p < 1 || p > 65535) return null;
      return { host, port: p, user, password, url: `socks5://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}` };
    }
  }
  try {
    const normalized = raw.includes("://") ? raw : `socks5://${raw}`;
    const parsed = new URL(normalized);
    const host = parsed.hostname;
    const port = parsed.port ? parseInt(parsed.port) : null;
    if (!host || !port || port < 1 || port > 65535) return null;
    const user = decodeURIComponent(parsed.username || "");
    const password = decodeURIComponent(parsed.password || "");
    const hostText = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    const auth = user || password ? `${encodeURIComponent(user)}:${encodeURIComponent(password)}@` : "";
    return { host, port, user, password, url: `socks5://${auth}${hostText}:${port}` };
  } catch {
    return null;
  }
}

function socks5Probe(host, port, user, password, timeout) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = net.createConnection({ host, port, timeout: timeout * 1000 });
    socket.on("error", () => resolve([false, 0]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([false, 0]);
    });
    socket.on("connect", () => {
      const methods = user || password ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]);
      socket.write(methods);
      const waitReply = () => {
        socket.once("data", (reply) => {
          if (!reply || reply[0] !== 5 || reply[1] === 0xff) {
            socket.end();
            return resolve([false, 0]);
          }
          if (reply[1] === 2) {
            const userBuf = Buffer.from(user, "utf-8");
            const passBuf = Buffer.from(password, "utf-8");
            const authPack = Buffer.concat([Buffer.from([1, userBuf.length]), userBuf, Buffer.from([passBuf.length]), passBuf]);
            socket.write(authPack);
            socket.once("data", (authReply) => {
              if (!authReply || authReply[1] !== 0) {
                socket.end();
                return resolve([false, 0]);
              }
              sendConnect();
            });
          } else {
            sendConnect();
          }
        });
      };
      waitReply();
    });

    function sendConnect() {
      const targetHost = SOCKS5_HANDSHAKE_TARGET.host;
      const targetPort = SOCKS5_HANDSHAKE_TARGET.port;
      const hostBuf = Buffer.from(targetHost, "utf-8");
      const connectPack = Buffer.concat([Buffer.from([5, 1, 0, 3]), Buffer.from([hostBuf.length]), hostBuf]);
      const portBuf = Buffer.alloc(2);
      portBuf.writeUInt16BE(targetPort, 0);
      socket.write(Buffer.concat([connectPack, portBuf]));
      socket.once("data", (header) => {
        if (!header || header[0] !== 5 || header[1] !== 0) {
          socket.end();
          return resolve([false, 0]);
        }
        const atyp = header[3];
        let skipBytes = atyp === 1 ? 4 : atyp === 3 ? 1 : atyp === 4 ? 16 : 0;
        if (skipBytes > 0) {
          socket.once("data", (extra) => {
            skipBytes -= extra.length;
            if (skipBytes > 0) {
              socket.once("data", (rest) => {
                skipBytes -= rest.length;
                finishConnect();
              });
            } else {
              finishConnect();
            }
          });
        } else {
          finishConnect();
        }
      });
    }

    function finishConnect() {
      socket.read(2, (err, last) => {
        if (err || !last) {
          socket.end();
          return resolve([false, 0]);
        }
        const latency = Date.now() - startTime;
        socket.end();
        resolve([true, latency]);
      });
    }
  });
}

async function processProxy(item) {
  const parsed = parseSocks5Proxy(item.proxy);
  if (!parsed) return null;
  const { host, port, user, password, url } = parsed;
  const [ok, latencyMs] = await socks5Probe(host, port, user, password, CONNECT_TIMEOUT);
  if (!ok) return null;
  let outboundIp = null;
  for (const ep of VERIFY_ENDPOINTS) {
    const data = await httpGet(ep.url, CONNECT_TIMEOUT);
    outboundIp = extractIP(data);
    if (outboundIp) break;
  }
  if (!outboundIp) return null;
  const sourceCountry = (item.country || "").toUpperCase().trim();
  const realCountry = await lookupCountry(outboundIp);
  const finalCountry = realCountry !== "未知" ? realCountry : (sourceCountry || "未知");
  return { line: `${url}#${finalCountry}`, ip: outboundIp, latency: latencyMs, country: finalCountry };
}

async function fetchCloudflareIPs() {
  const results = new Set();
  for (const api of CLOUDFLARE_IP_APIS) {
    const data = await httpGet(api, 15);
    if (!data) continue;
    const text = typeof data === "string" ? data : JSON.stringify(data);
    const lines = text.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("{") || trimmed.startsWith("[")) continue;
      const ipMatch = trimmed.match(/(\d{1,3}\.){3}\d{1,3}/);
      if (ipMatch) {
        const ip = ipMatch[0];
        const parts = trimmed.split(/[#\s]/);
        const label = parts[1] || "优选IP";
        results.add(`${ip}:443#${label}`);
      }
    }
  }
  return Array.from(results).sort((a, b) => {
    const la = a.split("#")[1] || "";
    const lb = b.split("#")[1] || "";
    return la.localeCompare(lb) || a.localeCompare(b);
  });
}

async function loadProxyTasks() {
  const payload = await httpGet(TARGET_URL, 15);
  if (!Array.isArray(payload)) {
    console.log("❌ 代理源返回异常");
    return [];
  }
  const tasks = [];
  const seen = new Set();
  for (const entry of payload) {
    const proxy = (entry.proxy || "").trim();
    if (!proxy || seen.has(proxy)) continue;
    const geo = entry.geolocation || {};
    const country = (geo.country || "").toUpperCase().trim();
    tasks.push({ proxy, country });
    seen.add(proxy);
  }
  return tasks;
}

function writeLines(path, lines) {
  fs.writeFileSync(path, lines.join("\n"), "utf-8");
}

async function main() {
  console.log("🚀 开始获取 Cloudflare 优选 IP...");
  const cloudflareIPs = await fetchCloudflareIPs();
  if (cloudflareIPs.length) {
    writeLines(OUTPUT_FILE, cloudflareIPs);
    console.log(`✅ Cloudflare 优选 IP 已更新: ${cloudflareIPs.length} 条`);
  } else {
    console.log("⚠️ Cloudflare 优选 IP 未更新，保留现有结果");
  }

  console.log("\n🚀 开始获取 SOCKS5 代理源...");
  const tasks = await loadProxyTasks();
  if (!tasks.length) {
    console.log("❌ 未获取到可验证的代理任务");
    return;
  }
  console.log(`🔍 开始验证 ${tasks.length} 个代理，线程数: ${MAX_WORKERS}`);
  const validResults = [];
  const batches = [];
  for (let i = 0; i < tasks.length; i += MAX_WORKERS) {
    batches.push(tasks.slice(i, i + MAX_WORKERS));
  }
  for (const batch of batches) {
    const results = await Promise.all(batch.map((t) => processProxy(t)));
    for (const result of results) {
      if (!result) continue;
      console.log(`✅ 有效: ${result.ip} [${result.country}] ${result.latency}ms`);
      validResults.push(result);
    }
  }
  validResults.sort((a, b) => {
    if (a.country !== b.country) return a.country.localeCompare(b.country);
    if (a.latency !== b.latency) return a.latency - b.latency;
    return a.line.localeCompare(b.line);
  });
  writeLines(VALID_PROXY_FILE, validResults.map((r) => r.line));
  console.log(`\n✨ 验证完成，可用节点: ${validResults.length}`);
  console.log(`📂 结果已保存至 ${VALID_PROXY_FILE}`);
}

main().catch(console.error);
