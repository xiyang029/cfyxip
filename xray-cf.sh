#!/usr/bin/env bash
set -euo pipefail

# ── 常量 ──────────────────────────────────────────────
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="$XRAY_CONFIG_DIR/config.json"
XRAY_BINARY="/usr/local/bin/xray"
STATE_DIR="/etc/xray-cf-lite"
STATE_PATH="$STATE_DIR/state.json"
CF_ACCOUNT_PATH="$STATE_DIR/cf_account.json"
LAST_LINKS_PATH="$(pwd)/cf_lite_last_links.txt"

CF_API="https://api.cloudflare.com/client/v4"
MANAGED_PREFIX="xray-cf-lite "
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
SUB_BASE="https://yx-auto.pages.dev"


# ── 工具 ──────────────────────────────────────────────
die()     { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()      { printf '\033[32m✓\033[0m %s\n' "$*"; }
info()    { printf '\033[36m·\033[0m %s\n' "$*"; }
need_cmd(){ command -v "$1" &>/dev/null || die "缺少依赖: $1"; }

urlencode() {
    local s="$1" c
    local -i i
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
}

gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]'; }

# ── init 系统检测 ─────────────────────────────────────
INIT_SYSTEM=""
detect_init() {
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        die "不支持的 init 系统（需要 systemd 或 OpenRC）"
    fi
}

# ── 包管理器 ──────────────────────────────────────────
install_deps() {
    local missing=()
    command -v curl    &>/dev/null || missing+=(curl)
    command -v jq      &>/dev/null || missing+=(jq)
    command -v unzip   &>/dev/null || missing+=(unzip)
    command -v openssl &>/dev/null || missing+=(openssl)
    [[ ${#missing[@]} -eq 0 ]] && return

    echo "安装依赖: ${missing[*]}"
    if command -v apk &>/dev/null; then
        apk add --no-cache "${missing[@]}"
    elif command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y "${missing[@]}"
    else
        die "无法安装依赖 ${missing[*]}，请手动安装"
    fi
}

# ── xray 服务管理 ────────────────────────────────────
XRAY_OPENRC_SCRIPT="/etc/init.d/xray"

write_openrc_script() {
    cat > "$XRAY_OPENRC_SCRIPT" << 'INITEOF'
#!/sbin/openrc-run
name="xray"
description="Xray proxy server"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
output_log="/var/log/xray.log"
error_log="/var/log/xray.log"
respawn_delay=1
respawn_max=0
respawn_period=86400
supervise_daemon_args="--respawn-delay ${respawn_delay} --respawn-max ${respawn_max} --respawn-period ${respawn_period}"
supervisor=supervise-daemon
depend() { need net; after firewall; }
INITEOF
    chmod +x "$XRAY_OPENRC_SCRIPT"
}

svc_enable()    { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl enable xray &>/dev/null; else rc-update add xray default &>/dev/null; fi; true; }
svc_start()     { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else [[ -f "$XRAY_OPENRC_SCRIPT" ]] || write_openrc_script; rc-service xray restart; fi; }
svc_stop()      { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl stop xray &>/dev/null; systemctl disable xray &>/dev/null; else rc-service xray stop &>/dev/null; rc-update del xray default &>/dev/null; fi; true; }
svc_is_active() { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl is-active xray &>/dev/null; else rc-service xray status &>/dev/null 2>&1; fi; }

ensure_systemd_restart() {
    # 确保 systemd 下 xray 崩溃自动重启
    local drop="/etc/systemd/system/xray.service.d"
    if [[ "$INIT_SYSTEM" == "systemd" && ! -f "$drop/restart.conf" ]]; then
        mkdir -p "$drop"
        cat > "$drop/restart.conf" << 'SDEOF'
[Service]
Restart=on-failure
RestartSec=1
SDEOF
        systemctl daemon-reload
    fi
}

restart_xray() {
    [[ "$INIT_SYSTEM" == "systemd" ]] && ensure_systemd_restart
    svc_enable
    svc_start || die "xray 重启失败"
    sleep 1
    svc_is_active || die "xray 未正常启动，请查看日志"
    ok "xray 服务已启动"
}

stop_xray() { svc_stop; }

# ── 网络检测 ─────────────────────────────────────────
get_public_ip() {
    local ip
    for url in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        ip=$(curl -sf --max-time 8 "$url" 2>/dev/null) && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$ip" && return
    done
    die "获取公网 IPv4 失败"
}

detect_nat() {
    local public_ip
    public_ip=$(get_public_ip)
    if ip addr show 2>/dev/null | grep -q "inet ${public_ip}/"; then
        echo "direct"
    else
        echo "nat"
    fi
}

# ── CF API ────────────────────────────────────────────
cf_call() {
    local method="$1" endpoint="$2" data="${3:-}" no_fail="${4:-}"
    local args=(-s -X "$method" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json")
    [[ "$no_fail" != "--no-fail" ]] && args+=(-f)
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${CF_API}${endpoint}"
}

# ── CF 凭据 ───────────────────────────────────────────
CF_EMAIL="" CF_KEY=""

load_cf_account() {
    [[ -f "$CF_ACCOUNT_PATH" ]] || return 1
    CF_EMAIL=$(jq -r '.email // ""' "$CF_ACCOUNT_PATH")
    CF_KEY=$(jq -r '.api_key // ""' "$CF_ACCOUNT_PATH")
    [[ -n "$CF_EMAIL" && -n "$CF_KEY" ]]
}

save_cf_account() {
    mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
    jq -n --arg e "$CF_EMAIL" --arg k "$CF_KEY" '{email:$e,api_key:$k}' > "$CF_ACCOUNT_PATH"
    chmod 600 "$CF_ACCOUNT_PATH"
}

# 验证 CF 凭据是否有效（用 verify 接口，避免拿到无效 key 继续跑）
cf_verify_credentials() {
    # Global API Key 直接使用 zones 接口验证（tokens/verify 仅适用于 API Token）
    cf_call GET "/zones?per_page=1" | jq -e '.success == true' &>/dev/null
}

prompt_cf() {
    # 先尝试复用已保存凭据
    if load_cf_account; then
        local masked="${CF_KEY:0:6}...${CF_KEY: -4}"
        read -rp "复用已保存 CF 凭据 ($CF_EMAIL, Key=$masked)? (Y/n): " ans
        if [[ "${ans,,}" =~ ^(|y|yes)$ ]]; then
            if cf_verify_credentials; then
                return 0
            fi
            echo "已保存的 CF 凭据校验失败，请重新输入"
        fi
    fi
    # 循环让用户输入直到校验通过
    while true; do
        read -rp "Cloudflare 邮箱: " CF_EMAIL || die "输入已中断"
        read -rsp "Cloudflare Global API Key: " CF_KEY || die "输入已中断"; echo
        if [[ -z "$CF_EMAIL" || -z "$CF_KEY" ]]; then
            echo "邮箱和 API Key 不能为空，请重试"
            continue
        fi
        echo -n "校验凭据... "
        if cf_verify_credentials; then
            echo "通过"
            save_cf_account
            return 0
        fi
        echo "失败：邮箱或 API Key 错误，请重新输入（Ctrl+C 退出）"
    done
}

# ── CF DNS / SSL / Origin Rules ───────────────────────
cf_find_zone() {
    local domain="$1" zones best_name="" best_id=""
    zones=$(cf_call GET "/zones?per_page=100" | jq -r '.result[] | "\(.name) \(.id)"')
    while IFS=' ' read -r zone_name zone_id; do
        if [[ "$domain" == "$zone_name" || "$domain" == *".$zone_name" ]]; then
            [[ ${#zone_name} -gt ${#best_name} ]] && best_name="$zone_name" && best_id="$zone_id"
        fi
    done <<< "$zones"
    [[ -n "$best_id" ]] || return 1
    echo "$best_id"
}

cf_get_dns() {
    cf_call GET "/zones/$1/dns_records?type=A&name=$2" | jq '.result[0] // empty'
}

cf_upsert_dns() {
    local zone_id="$1" domain="$2" ip="$3"
    local payload existing
    payload=$(jq -n --arg n "$domain" --arg c "$ip" '{type:"A",name:$n,content:$c,proxied:true,ttl:1}')
    existing=$(cf_get_dns "$zone_id" "$domain")
    if [[ -n "$existing" ]]; then
        local rid; rid=$(echo "$existing" | jq -r '.id')
        cf_call PUT "/zones/${zone_id}/dns_records/${rid}" "$payload" | jq -r '.result.id'
    else
        cf_call POST "/zones/${zone_id}/dns_records" "$payload" | jq -r '.result.id'
    fi
}

cf_get_ssl()  { cf_call GET "/zones/$1/settings/ssl" | jq -r '.result.value'; }
cf_set_ssl()  { cf_call PATCH "/zones/$1/settings/ssl" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

# ── CF 安全规则 ───────────────────────────────────────
cf_get_security_level() { cf_call GET "/zones/$1/settings/security_level" | jq -r '.result.value'; }
cf_set_security_level() { cf_call PATCH "/zones/$1/settings/security_level" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

cf_get_browser_check() { cf_call GET "/zones/$1/settings/browser_check" | jq -r '.result.value'; }
cf_set_browser_check() { cf_call PATCH "/zones/$1/settings/browser_check" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

cf_get_bot_management() { cf_call GET "/zones/$1/bot_management" "" --no-fail | jq '.result // {}'; }

cf_set_bot_fight_off() {
    local zone_id="$1"
    cf_call PUT "/zones/${zone_id}/bot_management" "$(jq -n '{
        enable_js: false,
        sbfm_likely_automated: "allow",
        sbfm_definitely_automated: "allow",
        sbfm_verified_bots: "allow",
        sbfm_static_resource_protection: false
    }')" --no-fail | jq -e '.success' &>/dev/null
}

cf_restore_bot_management() {
    local zone_id="$1" backup="$2"
    # 只恢复我们改过的字段
    local payload
    payload=$(echo "$backup" | jq '{
        enable_js: .enable_js,
        sbfm_likely_automated: .sbfm_likely_automated,
        sbfm_definitely_automated: .sbfm_definitely_automated,
        sbfm_verified_bots: .sbfm_verified_bots,
        sbfm_static_resource_protection: .sbfm_static_resource_protection
    }')
    cf_call PUT "/zones/${zone_id}/bot_management" "$payload" --no-fail | jq -e '.success' &>/dev/null
}

# 安装时：备份安全设置 -> 关闭拦截
cf_relax_security() {
    local zone_id="$1"
    local sec_level bot_mgmt browser_check

    sec_level=$(cf_get_security_level "$zone_id")
    browser_check=$(cf_get_browser_check "$zone_id")
    bot_mgmt=$(cf_get_bot_management "$zone_id")

    # 降低 security level
    if [[ "$sec_level" != "essentially_off" ]]; then
        cf_set_security_level "$zone_id" "essentially_off"
        ok "Security Level: essentially_off"
    fi

    # 关闭 Browser Integrity Check
    if [[ "$browser_check" != "off" ]]; then
        cf_set_browser_check "$zone_id" "off"
        ok "Browser Check: off"
    fi

    # 关闭 Bot Fight Mode
    local sbfm_likely
    sbfm_likely=$(echo "$bot_mgmt" | jq -r '.sbfm_likely_automated // ""')
    if [[ "$sbfm_likely" != "allow" ]]; then
        cf_set_bot_fight_off "$zone_id"
        ok "Bot Fight Mode: 已关闭"
    fi

    # 返回备份 JSON
    jq -n --arg sl "$sec_level" --arg bc "$browser_check" --argjson bm "$bot_mgmt"         '{security_level:$sl, browser_check:$bc, bot_management:$bm}'
}

# 卸载时：恢复安全设置
cf_restore_security() {
    local zone_id="$1" backup="$2"
    [[ -z "$backup" || "$backup" == "null" ]] && return

    local sl bc bm
    sl=$(echo "$backup" | jq -r '.security_level // ""')
    bc=$(echo "$backup" | jq -r '.browser_check // ""')
    bm=$(echo "$backup" | jq '.bot_management // null')

    [[ -n "$sl" ]] && cf_set_security_level "$zone_id" "$sl" && ok "Security Level 已恢复: $sl"
    [[ -n "$bc" ]] && cf_set_browser_check "$zone_id" "$bc" && ok "Browser Check 已恢复: $bc"
    [[ "$bm" != "null" ]] && cf_restore_bot_management "$zone_id" "$bm" && ok "Bot Fight Mode 已恢复"
}

cf_get_origin_rules() {
    local r; r=$(cf_call GET "/zones/$1/rulesets/phases/http_request_origin/entrypoint" "" --no-fail)
    echo "$r" | jq -r 'if .success then .result.rules // [] else [] end' 2>/dev/null || echo '[]'
}

cf_put_origin_rules() {
    local r; r=$(cf_call PUT "/zones/$1/rulesets/phases/http_request_origin/entrypoint" \
        "$(jq -n --argjson r "$2" '{rules:$r}')" --no-fail)
    echo "$r" | jq -e '.success' &>/dev/null || die "Origin Rules 写入失败: $(echo "$r" | jq -c '.errors')"
}

# cf_port = 外部端口（CF Origin Rules 转发的目标端口）
build_origin_rule() {
    local domain="$1" route_json="$2"
    local port; port=$(echo "$route_json" | jq -r '.cf_port')
    echo "$route_json" | jq --arg d "$domain" --arg pfx "$MANAGED_PREFIX" --argjson p "$port" '{
        description: ($pfx + "vless"),
        enabled: true,
        expression: ("(http.host eq \"" + $d + "\")"),
        action: "route",
        action_parameters: { origin: { port: $p } }
    }'
}

apply_origin_rule() {
    local zone_id="$1" domain="$2" route_json="$3"
    local existing kept new_rule merged
    existing=$(cf_get_origin_rules "$zone_id")
    kept=$(echo "$existing" | jq --arg d "$domain" --arg pfx "$MANAGED_PREFIX" '[
        .[] | select(
            (.description | startswith($pfx) | not) or
            (.expression | ascii_downcase | contains("http.host eq \"" + ($d|ascii_downcase) + "\"") | not)
        )
    ]')
    new_rule=$(build_origin_rule "$domain" "$route_json")
    merged=$(jq -n --argjson a "$kept" --argjson b "$new_rule" '$a + [$b]')
    cf_put_origin_rules "$zone_id" "$merged"
}

# ── CF 源证书 ─────────────────────────────────────────
CERT_DIR="/usr/local/etc/xray"

gen_origin_cert() {
    local domain="$1"
    info "正在生成 CF 源证书..."
    mkdir -p "$CERT_DIR"

    # 生成 ECC 私钥
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/origin.key" 2>/dev/null || die "私钥生成失败"
    ok "私钥已生成: $CERT_DIR/origin.key"

    # 生成 CSR
    openssl req -new -sha256 -key "$CERT_DIR/origin.key" -subj "/CN=${domain}" -out /tmp/origin.csr 2>/dev/null || die "CSR 生成失败"
    local csr
    csr=$(awk '{printf "%s\\n", $0}' /tmp/origin.csr)
    rm -f /tmp/origin.csr

    # 通过 CF API 签名
    local resp
    resp=$(curl -s -X POST "${CF_API}/certificates" \
        -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"csr\":\"${csr}\",\"hostnames\":[\"${domain}\"],\"request_type\":\"origin-ecc\",\"requested_validity\":365}")
    if ! echo "$resp" | jq -e '.success' &>/dev/null; then
        rm -f "$CERT_DIR/origin.key"
        die "CF 源证书签名失败: $(echo "$resp" | jq -c '.errors')"
    fi
    echo "$resp" | jq -r '.result.certificate' > "$CERT_DIR/origin.crt"
    ok "源证书已签名: $CERT_DIR/origin.crt"
    ok "有效期: $(echo "$resp" | jq -r '.result.expires_on // "未知"')"
}

revoke_origin_cert() {
    local domain="$1"
    info "正在吊销 CF 源证书..."
    local certs
    certs=$(curl -s -X GET "${CF_API}/certificates" \
        -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" \
        -H "Content-Type: application/json" 2>/dev/null)
    local cert_id
    cert_id=$(echo "$certs" | jq -r --arg d "$domain" '.result[] | select(.hostnames[] | contains($d)) | .id' 2>/dev/null | head -1)
    if [[ -n "$cert_id" ]]; then
        curl -s -X DELETE "${CF_API}/certificates/${cert_id}" \
            -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" \
            -H "Content-Type: application/json" >/dev/null 2>&1 || true
        ok "CF 源证书已吊销"
    else
        info "未找到匹配的源证书"
    fi
    rm -f "$CERT_DIR/origin.key" "$CERT_DIR/origin.crt"
    ok "本地证书文件已清理"
}

# ── xray 安装 ─────────────────────────────────────────
install_xray() {
    echo "正在安装 xray-core ..."

    # 优先尝试官方安装脚本（需要 systemd）
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        if bash -c "curl -fsSL $XRAY_INSTALL_URL | bash -s -- install" 2>/dev/null; then
            [[ -f "$XRAY_BINARY" ]] && { ok "xray-core 安装完成"; return; }
        fi
    fi

    # 回退：手动下载二进制
    info "使用手动安装方式"
    local arch
    case "$(uname -m)" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        armv7*)        arch="arm32-v7a" ;;
        *)             die "不支持的架构: $(uname -m)" ;;
    esac

    local ver
    ver=$(curl -sf "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r '.tag_name') || die "获取 xray 版本失败"
    info "xray $ver ($arch)"

    local tmp="/tmp/xray-install-$$"
    mkdir -p "$tmp"
    curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${arch}.zip" || die "下载失败"

    unzip -o "$tmp/xray.zip" xray -d /usr/local/bin/ || die "解压失败"
    chmod +x "$XRAY_BINARY"
    rm -rf "$tmp"

    # 下载 geodata
    local geo_dir="/usr/local/share/xray"
    mkdir -p "$geo_dir"
    for f in geoip.dat geosite.dat; do
        [[ -f "$geo_dir/$f" ]] || curl -fsSL -o "$geo_dir/$f" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/$f" || true
    done

    [[ -f "$XRAY_BINARY" ]] || die "安装后未找到 xray"
    ok "xray-core 安装完成: $($XRAY_BINARY version | head -1)"
}

# ── xray 配置生成 ─────────────────────────────────────
gen_xray_config() {
    local route_json="$1" uid="$2"
    local port; port=$(echo "$route_json" | jq -r '.listen_port')
    local path; path=$(echo "$route_json" | jq -r '.path')
    local transport; transport=$(echo "$route_json" | jq -r '.transport // "ws"')
    local domain; domain=$(echo "$route_json" | jq -r '.domain // ""')
    local tls_enabled; tls_enabled=$(echo "$route_json" | jq -r '.tls // false')

    local stream_settings
    if [[ "$tls_enabled" == "true" ]]; then
        # 启用 TLS 的 streamSettings
        case "$transport" in
            httpupgrade)
                stream_settings=$(jq -n --arg p "$path" --arg d "$domain" '{
                    network:"httpupgrade", security:"tls",
                    tlsSettings:{serverName:$d, certificates:[{certificateFile:"/usr/local/etc/xray/origin.crt",keyFile:"/usr/local/etc/xray/origin.key"}]},
                    httpupgradeSettings:{path:$p, host:$d}
                }')
                ;;
            splithttp)
                stream_settings=$(jq -n --arg p "$path" --arg d "$domain" '{
                    network:"splithttp", security:"tls",
                    tlsSettings:{serverName:$d, certificates:[{certificateFile:"/usr/local/etc/xray/origin.crt",keyFile:"/usr/local/etc/xray/origin.key"}]},
                    xhttpSettings:{host:$d, path:$p, mode:"packet-up"}
                }')
                ;;
            *)
                stream_settings=$(jq -n --arg p "$path" --arg d "$domain" '{
                    network:"ws", security:"tls",
                    tlsSettings:{serverName:$d, certificates:[{certificateFile:"/usr/local/etc/xray/origin.crt",keyFile:"/usr/local/etc/xray/origin.key"}]},
                    wsSettings:{path:$p}
                }')
                ;;
        esac
    else
        # 无 TLS 的 streamSettings（当前逻辑）
        case "$transport" in
            httpupgrade)
                stream_settings=$(jq -n --arg p "$path" --arg d "$domain" '{
                    network:"httpupgrade", security:"none",
                    httpupgradeSettings:{path:$p, host:$d}
                }')
                ;;
            splithttp)
                stream_settings=$(jq -n --arg p "$path" --arg d "$domain" '{
                    network:"splithttp", security:"none",
                    xhttpSettings:{host:$d, path:$p, mode:"packet-up"}
                }')
                ;;
            *)
                stream_settings=$(jq -n --arg p "$path" '{
                    network:"ws", security:"none",
                    wsSettings:{path:$p}
                }')
                ;;
        esac
    fi

    jq -n --arg uid "$uid" --argjson port "$port" --argjson ss "$stream_settings" '{
        log:{loglevel:"warning"},
        inbounds:[{
            tag:"in-vless",
            listen:"0.0.0.0",
            port:$port,
            protocol:"vless",
            settings:{clients:[{id:$uid,flow:""}],decryption:"none"},
            streamSettings:$ss,
            sniffing:{enabled:true,destOverride:["http","tls"]}
        }],
        outbounds:[{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}],
        routing:{domainStrategy:"AsIs",rules:[{type:"field",outboundTag:"block",protocol:["bittorrent"]}]}
    }'
}

write_xray_config() {
    mkdir -p "$XRAY_CONFIG_DIR"
    echo "$1" > "$XRAY_CONFIG_PATH"
    chmod 644 "$XRAY_CONFIG_PATH"
    ok "xray 配置已写入 $XRAY_CONFIG_PATH"
}

# ── 订阅链接 ─────────────────────────────────────────
build_link() {
    local uid="$1" domain="$2" path="$3" transport="$4"
    echo "${SUB_BASE}/${uid}/sub?domain=${domain}&transport=${transport}&epd=yes&epi=yes&egi=no&dkby=yes&ev=yes&path=$(urlencode "$path")"
}

# ── 状态 ──────────────────────────────────────────────
load_state() { [[ -f "$STATE_PATH" ]] && cat "$STATE_PATH"; }
save_state() { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; echo "$1" > "$STATE_PATH"; chmod 600 "$STATE_PATH"; }
remove_state() { rm -f "$STATE_PATH"; }

save_links_snapshot() {
    local domain="$1" uid="$2" link="$3"
    { echo "域名: $domain"; echo "UUID: $uid"; echo "VLESS订阅 $link"; } > "$LAST_LINKS_PATH"
    chmod 600 "$LAST_LINKS_PATH"
}

print_link() {
    echo "  VLESS订阅 $1"
}

# ── 交互辅助 ─────────────────────────────────────────
prompt_uuid() {
    local uid
    read -rp "UUID(留空=自动生成): " custom_uuid
    if [[ -n "$custom_uuid" ]]; then
        [[ "$custom_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "UUID 格式不正确"
        uid="${custom_uuid,,}"
    else
        uid=$(gen_uuid)
    fi
    echo "$uid"
}

prompt_path_prefix() {
    local default="$1"
    read -rp "传输路径(留空=/${default}): " pfx
    [[ -z "$pfx" ]] && pfx="/${default}"
    [[ "$pfx" == /* ]] || pfx="/${pfx}"
    echo "$pfx"
}

prompt_transport() {
    read -rp "传输协议(1=WebSocket, 2=HTTPUpgrade, 3=SplitHTTP/XHTTP，留空=WebSocket): " tr_raw
    case "${tr_raw:-1}" in
        1|ws|websocket)           echo "ws" ;;
        2|httpupgrade|upgrade)    echo "httpupgrade" ;;
        3|splithttp|xhttp)        echo "splithttp" ;;
        *)                        die "无效传输协议: $tr_raw" ;;
    esac
}

prompt_tls() {
    read -rp "启用 CF→VPS 加密(源证书)? (y/N): " tls_raw
    case "${tls_raw,,}" in
        y|yes) echo "true" ;;
        *)     echo "false" ;;
    esac
}

# 生成单条 vless 路由 JSON
# NAT 时 xray 监听 listen_port(内部)，CF 转发到 cf_port(外部)
# 直连时 listen_port == cf_port
build_route() {
    local net_mode="$1" path_prefix="$2" transport="$3" tls_enabled="$4"

    local port
    read -rp "端口: " port
    [[ "$port" =~ ^[0-9]+$ ]] || die "无效端口: $port"

    if [[ "$net_mode" == "nat" ]]; then
        local ext_port
        read -rp "外部映射端口(对外暴露): " ext_port
        [[ "$ext_port" =~ ^[0-9]+$ ]] || die "无效端口: $ext_port"
        jq -n --arg p "vless" --argjson lp "$((port))" --argjson cp "$((ext_port))" --arg pa "$path_prefix" --arg tr "$transport" --argjson tls "$tls_enabled" \
            '{protocol:$p, listen_port:$lp, cf_port:$cp, path:$pa, transport:$tr, tls:$tls}'
    else
        jq -n --arg p "vless" --argjson lp "$((port))" --arg pa "$path_prefix" --arg tr "$transport" --argjson tls "$tls_enabled" \
            '{protocol:$p, listen_port:$lp, cf_port:$lp, path:$pa, transport:$tr, tls:$tls}'
    fi
}

# ── 1. 安装 ──────────────────────────────────────────
do_install() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] && die "检测到上次配置($(echo "$state" | jq -r '.domain // "?"'))，请先卸载"

    [[ -f "$XRAY_BINARY" ]] && ok "xray-core 已安装" || install_xray

    local net_mode
    net_mode=$(detect_nat)
    [[ "$net_mode" == "nat" ]] && info "检测到 NAT 环境（内网 IP）" || info "直连环境"

    prompt_cf

    # 输入域名并校验能匹配到 CF Zone，失败可重输
    local domain zone_id
    while true; do
        read -rp "绑定域名: " domain || die "输入已中断"
        if [[ -z "$domain" ]]; then
            echo "域名不能为空，请重试"
            continue
        fi
        if zone_id=$(cf_find_zone "$domain"); then
            info "匹配到 Zone: $zone_id"
            break
        fi
        echo "无法在该 CF 账号下匹配 Zone: $domain，请确认域名已托管并重输（Ctrl+C 退出）"
    done

    local uid
    uid=$(prompt_uuid)
    local transport
    transport=$(prompt_transport)
    local tls_enabled
    tls_enabled=$(prompt_tls)
    local path_prefix
    path_prefix=$(prompt_path_prefix "${uid:0:8}")

    local route_json
    route_json=$(build_route "$net_mode" "$path_prefix" "$transport" "$tls_enabled")
    # 将域名注入 route JSON，供 gen_xray_config 中的 streamSettings 使用
    route_json=$(echo "$route_json" | jq --arg d "$domain" '.domain=$d')

    # 预览
    echo
    echo "配置预览:"
    echo "  域名:  $domain"
    echo "  UUID:  $uid"
    echo "  模式:  $net_mode"
    echo "  传输协议: $(echo "$route_json" | jq -r '.transport')"
    echo "  CF→VPS加密: $(echo "$route_json" | jq -r '.tls')"
    echo "  端口:  $(echo "$route_json" | jq -r '.listen_port')"
    [[ "$net_mode" == "nat" ]] && echo "  外部端口: $(echo "$route_json" | jq -r '.cf_port')"
    echo "  路径: $(echo "$route_json" | jq -r '.path')"
    echo
    read -rp "确认部署? (Y/n): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || die "已取消"

    # xray
    local config
    config=$(gen_xray_config "$route_json" "$uid")
    write_xray_config "$config"
    [[ "$INIT_SYSTEM" == "openrc" && ! -f "$XRAY_OPENRC_SCRIPT" ]] && write_openrc_script && ok "OpenRC 服务脚本已创建"
    restart_xray

    # CF
    local public_ip dns_before ssl_before origin_rules_before dns_record_id
    public_ip=$(get_public_ip)
    dns_before=$(cf_get_dns "$zone_id" "$domain" || echo null)
    ssl_before=$(cf_get_ssl "$zone_id")
    origin_rules_before=$(cf_get_origin_rules "$zone_id")

    dns_record_id=$(cf_upsert_dns "$zone_id" "$domain" "$public_ip")
    ok "DNS A 记录: $domain -> $public_ip (已代理)"

    if [[ "$tls_enabled" == "true" ]]; then
        gen_origin_cert "$domain"
        cf_set_ssl "$zone_id" "strict"
        ok "SSL 模式: strict（CF→VPS 加密）"
    else
        cf_set_ssl "$zone_id" "flexible"
        ok "SSL 模式: flexible"
    fi

    apply_origin_rule "$zone_id" "$domain" "$route_json"
    ok "Origin Rule 已创建"

    # 安全规则：关闭可能拦截 WS 的设置
    local security_backup
    security_backup=$(cf_relax_security "$zone_id")

    # 订阅
    local link
    link=$(build_link "$uid" "$domain" "$(echo "$route_json" | jq -r '.path')" "$transport")
    save_links_snapshot "$domain" "$uid" "$link"

    # 状态
    local dns_existed="false"
    [[ "$dns_before" != "null" ]] && dns_existed="true"
    save_state "$(jq -n \
        --arg d "$domain" --arg z "$zone_id" --arg u "$uid" --arg mode "$net_mode" \
        --argjson route "$route_json" \
        --arg drid "$dns_record_id" --argjson dex "$dns_existed" --argjson drec "$dns_before" \
        --arg ssl "$ssl_before" --argjson orbk "$origin_rules_before" \
        --argjson secbk "$security_backup" --arg link "$link" \
        '{domain:$d,zone_id:$z,uuid:$u,net_mode:$mode,route:$route,
          managed_dns_record_id:$drid,dns_backup:{existed:$dex,record:$drec},
          ssl_backup:$ssl,origin_rules_backup:$orbk,security_backup:$secbk,link:$link}')"

    echo
    ok "部署完成"
    print_link "$link"
    echo
    echo "订阅已保存到 $LAST_LINKS_PATH"
}

# ── 2. 卸载 ──────────────────────────────────────────
do_uninstall() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到上次配置"

    local domain; domain=$(echo "$state" | jq -r '.domain')
    local tls_was_enabled; tls_was_enabled=$(echo "$state" | jq -r '.route.tls // false')
    echo "正在卸载: $domain"

    stop_xray; rm -f "$XRAY_CONFIG_PATH"
    ok "xray 已停止"

    if load_cf_account; then
        # 先吊销源证书（如果启用过 TLS）
        if [[ "$tls_was_enabled" == "true" ]]; then
            revoke_origin_cert "$domain"
        fi

        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // ""')
        if [[ -n "$zone_id" ]]; then
            cf_put_origin_rules "$zone_id" "$(echo "$state" | jq '.origin_rules_backup // []')"
            ok "Origin Rules 已恢复"

            local ssl_bk; ssl_bk=$(echo "$state" | jq -r '.ssl_backup // ""')
            [[ -n "$ssl_bk" ]] && cf_set_ssl "$zone_id" "$ssl_bk" && ok "SSL: $ssl_bk"

            local dns_existed record_id
            dns_existed=$(echo "$state" | jq -r '.dns_backup.existed')
            record_id=$(echo "$state" | jq -r '.managed_dns_record_id // ""')
            if [[ "$dns_existed" == "true" ]]; then
                local rp; rp=$(echo "$state" | jq '.dns_backup.record | {type:(.type//"A"),name:(.name//""),content:(.content//""),proxied:(.proxied//false),ttl:(.ttl//1)}')
                cf_call PUT "/zones/${zone_id}/dns_records/${record_id}" "$rp" >/dev/null
                ok "DNS 已恢复"
            elif [[ -n "$record_id" ]]; then
                cf_call DELETE "/zones/${zone_id}/dns_records/${record_id}" "" --no-fail >/dev/null 2>&1 || true
                ok "DNS 已删除"
            fi
            # 恢复安全规则
            local sec_bk; sec_bk=$(echo "$state" | jq '.security_backup // null')
            cf_restore_security "$zone_id" "$sec_bk"
        fi
    else
        echo "无 CF 凭据，跳过恢复"
    fi

    remove_state
    rm -f "$LAST_LINKS_PATH" "$CF_ACCOUNT_PATH"
    ok "已清理订阅快照与 CF 凭据"
    ok "卸载完成"
}

# ── 3. 查看订阅 ──────────────────────────────────────
do_show() {
    if [[ -f "$LAST_LINKS_PATH" ]]; then cat "$LAST_LINKS_PATH"; return; fi
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "无历史订阅"
    echo "域名: $(echo "$state" | jq -r '.domain')"
    echo "UUID: $(echo "$state" | jq -r '.uuid')"
    echo "VLESS订阅 $(echo "$state" | jq -r '.link')"
}

# ── 4. 修改配置 ──────────────────────────────────────
do_modify() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain uid route_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    uid=$(echo "$state" | jq -r '.uuid')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    echo
    echo "当前配置 ($net_mode):"
    echo "  域名: $domain  UUID: $uid"
    echo "  传输协议: $(echo "$route_json" | jq -r '.transport // "ws"')"
    echo "  CF→VPS加密: $(echo "$route_json" | jq -r '.tls // false')"
    echo "  端口: $(echo "$route_json" | jq -r '.listen_port')  CF端口: $(echo "$route_json" | jq -r '.cf_port') 路径: $(echo "$route_json" | jq -r '.path')"
    echo
    echo "  1. 修改 UUID"
    echo "  2. 修改端口"
    echo "  3. 修改路径"
    echo "  4. 修改传输协议"
    echo "  5. 切换 CF→VPS 加密"
    echo "  6. 全部修改"
    echo "  0. 返回"
    echo
    read -rp "请选择 [0-6]: " mc

    local new_uid="$uid" new_route="$route_json" changed=false

    [[ "$mc" =~ ^[0-6]$ ]] || die "无效选项"
    [[ "$mc" == "0" ]] && return

    if [[ "$mc" == "1" || "$mc" == "6" ]]; then
        read -rp "新 UUID(留空=重新生成): " iu
        if [[ -n "$iu" ]]; then
            [[ "$iu" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "UUID 格式不正确"
            new_uid="${iu,,}"
        else
            new_uid=$(gen_uuid)
        fi
        changed=true; ok "UUID: $new_uid"
    fi

    if [[ "$mc" == "2" || "$mc" == "6" ]]; then
        if [[ "$net_mode" == "nat" ]]; then
            local lp cp
            lp=$(echo "$new_route" | jq -r '.listen_port')
            cp=$(echo "$new_route" | jq -r '.cf_port')
            read -rp "内部监听端口(当前=$lp): " new_lp
            read -rp "外部映射端口(当前=$cp): " new_cp
            [[ -n "$new_lp" ]] && { [[ "$new_lp" =~ ^[0-9]+$ ]] || die "无效端口"; lp="$new_lp"; }
            [[ -n "$new_cp" ]] && { [[ "$new_cp" =~ ^[0-9]+$ ]] || die "无效端口"; cp="$new_cp"; }
            new_route=$(echo "$new_route" | jq --argjson lp "$((lp))" --argjson cp "$((cp))" '.listen_port=$lp|.cf_port=$cp')
            changed=true; ok "端口已更新"
        else
            local p; p=$(echo "$new_route" | jq -r '.listen_port')
            read -rp "新端口(当前=$p): " np
            if [[ -n "$np" ]]; then
                [[ "$np" =~ ^[0-9]+$ ]] || die "无效端口: $np"
                new_route=$(echo "$new_route" | jq --argjson p "$((np))" '.listen_port=$p|.cf_port=$p')
                changed=true; ok "端口已更新"
            fi
        fi
    fi

    if [[ "$mc" == "3" || "$mc" == "6" ]]; then
        local cur_path; cur_path=$(echo "$new_route" | jq -r '.path')
        read -rp "新路径(当前=$cur_path，留空=不改): " np
        if [[ -n "$np" ]]; then
            [[ "$np" == /* ]] || np="/${np}"
            new_route=$(echo "$new_route" | jq --arg p "$np" '.path=$p')
            changed=true; ok "路径已更新"
        fi
    fi

    if [[ "$mc" == "4" || "$mc" == "6" ]]; then
        local cur_tr; cur_tr=$(echo "$new_route" | jq -r '.transport // "ws"')
        echo "当前传输协议: $cur_tr"
        new_tr=$(prompt_transport)
        new_route=$(echo "$new_route" | jq --arg t "$new_tr" '.transport=$t')
        changed=true; ok "传输协议: $new_tr"
    fi

    if [[ "$mc" == "5" || "$mc" == "6" ]]; then
        local cur_tls; cur_tls=$(echo "$new_route" | jq -r '.tls // false')
        if [[ "$cur_tls" == "true" ]]; then
            echo "当前: 已启用 CF→VPS 加密"
            read -rp "关闭加密? (y/N): " off_tls
            if [[ "${off_tls,,}" == "y" || "${off_tls,,}" == "yes" ]]; then
                new_route=$(echo "$new_route" | jq '.tls=false')
                changed=true; ok "CF→VPS 加密: 已关闭"
                # 吊销证书（在确认后执行）
                local _revoke_after=true
            fi
        else
            echo "当前: 未启用 CF→VPS 加密"
            read -rp "开启加密? (y/N): " on_tls
            if [[ "${on_tls,,}" == "y" || "${on_tls,,}" == "yes" ]]; then
                new_route=$(echo "$new_route" | jq '.tls=true')
                changed=true; ok "CF→VPS 加密: 已开启"
                # 生成证书（在确认后执行）
                local _gen_cert_after=true
            fi
        fi
    fi

    [[ "$changed" == "true" ]] || { echo "无修改"; return; }

    # 重新注入 domain 到 route JSON（gen_xray_config 需要）
    new_route=$(echo "$new_route" | jq --arg d "$domain" '.domain=$d')

    # 处理 TLS 变更的实际操作
    if [[ "${_gen_cert_after:-}" == "true" ]]; then
        load_cf_account || die "未找到 CF 凭据"
        gen_origin_cert "$domain"
        cf_set_ssl "$(echo "$state" | jq -r '.zone_id')" "strict"
        ok "SSL 模式: strict"
    fi
    if [[ "${_revoke_after:-}" == "true" ]]; then
        load_cf_account || die "未找到 CF 凭据"
        revoke_origin_cert "$domain"
        cf_set_ssl "$(echo "$state" | jq -r '.zone_id')" "flexible"
        ok "SSL 模式: flexible"
    fi

    write_xray_config "$(gen_xray_config "$new_route" "$new_uid")"
    restart_xray

    if load_cf_account; then
        apply_origin_rule "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_route"
        ok "Origin Rule 已更新"
    fi

    local link; link=$(build_link "$new_uid" "$domain" "$(echo "$new_route" | jq -r '.path')" "$(echo "$new_route" | jq -r '.transport // "ws"')")
    save_links_snapshot "$domain" "$new_uid" "$link"
    save_state "$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_route" --arg l "$link" \
        '.uuid=$u|.route=$r|.link=$l')"

    echo; ok "配置已更新"; print_link "$link"
}

# ── 5. 查看当前配置 ──────────────────────────────────
do_show_config() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    echo
    echo "域名:  $(echo "$state" | jq -r '.domain')"
    echo "UUID:  $(echo "$state" | jq -r '.uuid')"
    echo "模式:  $(echo "$state" | jq -r '.net_mode // "direct"')"
    echo "传输协议: $(echo "$state" | jq -r '.route.transport // "ws"')"
    echo "CF→VPS加密: $(echo "$state" | jq -r '.route.tls // false')"
    echo "端口:  $(echo "$state" | jq -r '.route.listen_port')"
    echo "CF端口: $(echo "$state" | jq -r '.route.cf_port')"
    echo "路径: $(echo "$state" | jq -r '.route.path')"
    echo
    echo -n "xray: "; svc_is_active && echo "运行中" || echo "未运行"
    echo
    echo "订阅:"
    print_link "$(echo "$state" | jq -r '.link')"
    echo
}

# ── 6. 更新外部端口（NAT 快捷操作）──────────────────
do_update_ports() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain route_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    echo
    echo "当前端口映射:"
    echo "  监听:$(echo "$route_json" | jq -r '.listen_port') -> 外部:$(echo "$route_json" | jq -r '.cf_port')"
    echo

    if [[ "$net_mode" == "nat" ]]; then
        info "NAT 模式: 只更新外部端口(CF Origin Rules)，xray 监听端口不变"
        echo

        local old_cp; old_cp=$(echo "$route_json" | jq -r '.cf_port')
        read -rp "新外部端口(当前=$old_cp): " ne
        [[ -n "$ne" ]] || die "不能为空"
        [[ "$ne" =~ ^[0-9]+$ ]] || die "无效端口: $ne"
        local new_route; new_route=$(echo "$route_json" | jq --argjson p "$((ne))" '.cf_port=$p')

        echo
        echo "更新预览: 监听:$(echo "$new_route" | jq -r '.listen_port') -> 外部:$(echo "$new_route" | jq -r '.cf_port')"
        read -rp "确认? (Y/n): " confirm
        [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || die "已取消"

        load_cf_account || die "未找到 CF 凭据"
        apply_origin_rule "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_route"
        ok "Origin Rule 已更新"

        # 同时更新 DNS（公网 IP 可能也变了）
        local public_ip; public_ip=$(get_public_ip)
        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id')
        local current_dns; current_dns=$(cf_get_dns "$zone_id" "$domain")
        local current_ip; current_ip=$(echo "$current_dns" | jq -r '.content // ""')
        if [[ "$current_ip" != "$public_ip" ]]; then
            cf_upsert_dns "$zone_id" "$domain" "$public_ip" >/dev/null
            ok "DNS 已更新: $domain -> $public_ip"
        fi

        local uid; uid=$(echo "$state" | jq -r '.uuid')
        local link; link=$(build_link "$uid" "$domain" "$(echo "$new_route" | jq -r '.path')" "$(echo "$new_route" | jq -r '.transport // "ws"')")
        save_links_snapshot "$domain" "$uid" "$link"
        save_state "$(echo "$state" | jq --argjson r "$new_route" --arg l "$link" '.route=$r|.link=$l')"

        echo; ok "外部端口已更新"; print_link "$link"
    else
        info "直连模式: 端口变更需要同时修改 xray 监听，请使用 [4.修改配置]"
    fi
}

# ── 7. 更新 xray ─────────────────────────────────────
do_update_xray() {
    echo "正在检查 xray 版本..."

    # 获取当前版本
    local current_ver=""
    if [[ -f "$XRAY_BINARY" ]]; then
        current_ver=$($XRAY_BINARY version 2>/dev/null | head -1 | grep -oP 'Xray \K[\d.]+' || true)
    fi
    if [[ -z "$current_ver" ]]; then
        echo "当前 xray 未安装或无法获取版本"
        read -rp "是否安装最新版? (Y/n): " confirm
        [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || return
        install_xray
        restart_xray
        return
    fi
    info "当前版本: $current_ver"

    # 获取最新版本
    local latest_ver
    latest_ver=$(curl -sf "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r '.tag_name') || die "获取最新版本失败"
    latest_ver="${latest_ver#v}"
    info "最新版本: $latest_ver"

    if [[ "$current_ver" == "$latest_ver" ]]; then
        ok "已是最新版本，无需更新"
        return
    fi

    echo
    echo "发现新版本: $current_ver -> $latest_ver"
    read -rp "确认更新? (Y/n): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { info "已取消"; return; }

    install_xray
    restart_xray
    ok "xray 已更新至 $latest_ver"
}

# ── 8. 重启 xray ─────────────────────────────────────
do_restart() {
    if ! svc_is_active; then
        echo "xray 当前未运行，正在启动..."
    else
        echo "正在重启 xray..."
    fi
    restart_xray
}

# ── 主入口 ────────────────────────────────────────────
ensure_shortcut() {
    local target="/usr/local/bin/x"
    [[ -f "$target" ]] && return
    cat > "$target" << 'SCEOF'
#!/bin/sh
exec bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/xray-cf-lite/main/xray_cf_lite.sh) "$@"
SCEOF
    chmod +x "$target"
}

main() {
    [[ "$(id -u)" == "0" ]] || die "请使用 root 运行此脚本"
    detect_init
    install_deps
    need_cmd curl; need_cmd jq; need_cmd openssl
    ensure_shortcut

    local state current_domain="" net_mode=""
    state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]]; then
        current_domain=$(echo "$state" | jq -r '.domain // ""')
        net_mode=$(echo "$state" | jq -r '.net_mode // ""')
    fi

    echo
    echo "  xray-cf-lite ($INIT_SYSTEM)"
    echo
    echo "  1. 安装节点"
    echo "  2. 卸载"
    echo "  3. 查看订阅"
    echo "  4. 修改配置(UUID/端口/路径)"
    echo "  5. 查看当前配置"
    echo "  6. 更新外部端口(NAT换端口)"
    echo "  7. 更新 xray"
    echo "  8. 重启 xray"
    [[ -n "$current_domain" ]] && echo "     (当前: $current_domain${net_mode:+ [$net_mode]})"
    echo

    read -rp "请选择 [1-8]: " choice
    case "$choice" in
        1) do_install ;; 2) do_uninstall ;; 3) do_show ;;
        4) do_modify ;; 5) do_show_config ;; 6) do_update_ports ;;
        7) do_update_xray ;;
        8) do_restart ;;
        *) die "无效选项: $choice" ;;
    esac
}

main "$@"