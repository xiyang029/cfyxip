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
XRAY_RELEASES_API="https://api.github.com/repos/XTLS/Xray-core/releases"

XRAY_UPDATE_STATUS=""
XRAY_UPDATE_CURRENT=""
XRAY_UPDATE_LATEST=""


# ── 工具 ──────────────────────────────────────────────
die()     { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()      { printf '\033[32m✓\033[0m %s\n' "$*"; }
info()    { printf '\033[36m·\033[0m %s\n' "$*"; }
warn()    { printf '\033[33m⚠ %s\033[0m\n' "$*"; }
header()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
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

bbr_is_enabled() {
    [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" == "bbr" ]]
}

get_bbr_status() {
    bbr_is_enabled && echo "已启用" || echo "未启用"
}

get_xray_version() {
    [[ -x "$XRAY_BINARY" ]] || return 1
    "$XRAY_BINARY" version 2>/dev/null | sed -n 's/.*Xray \([0-9][0-9.]*\).*/\1/p' | head -1
}

get_latest_xray_version() {
    local release prerelease release_version prerelease_version
    release=$(curl -sf --connect-timeout 5 --max-time 15 \
        -H 'User-Agent: xray-cf-lite' "${XRAY_RELEASES_API}/latest" |
        jq -r '.tag_name // empty' 2>/dev/null || true)
    prerelease=$(curl -sf --connect-timeout 5 --max-time 15 \
        -H 'User-Agent: xray-cf-lite' "${XRAY_RELEASES_API}?per_page=1" |
        jq -r '.[0].tag_name // empty' 2>/dev/null || true)
    release_version="${release#v}"
    prerelease_version="${prerelease#v}"

    if [[ -z "$release_version" ]]; then
        printf '%s\n' "$prerelease_version"
    elif [[ -z "$prerelease_version" ]]; then
        printf '%s\n' "$release_version"
    elif [[ "$(printf '%s\n%s\n' "$release_version" "$prerelease_version" | sort -V | tail -1)" == "$prerelease_version" ]]; then
        printf '%s\n' "$prerelease_version"
    else
        printf '%s\n' "$release_version"
    fi
}

check_xray_update() {
    local current latest status
    current=$(get_xray_version || true)
    latest=$(get_latest_xray_version || true)

    if [[ -z "$latest" ]]; then
        status="版本检测失败"
    elif [[ -z "$current" ]]; then
        status="可安装 v${latest}"
    elif [[ "$current" == "$latest" ]]; then
        status="已是最新 v${current}"
    else
        status="检测到 v${latest}，可更新"
    fi

    XRAY_UPDATE_CURRENT="$current"
    XRAY_UPDATE_LATEST="$latest"
    XRAY_UPDATE_STATUS="$status"
}

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
    fix_origin_cert_permissions
    [[ "$INIT_SYSTEM" == "systemd" ]] && ensure_systemd_restart
    svc_enable
    svc_start || die "xray 重启失败"
    sleep 1
    svc_is_active || die "xray 未正常启动，请查看日志"
    ok "xray 服务已启动"
}

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
CF_TOKEN=""

cf_call() {
    local method="$1" endpoint="$2" data="${3:-}" no_fail="${4:-}"
    local args=(-s -X "$method" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
    [[ "$no_fail" != "--no-fail" ]] && args+=(-f)
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${CF_API}${endpoint}"
}

# ── CF 凭据 ───────────────────────────────────────────
load_cf_account() {
    [[ -f "$CF_ACCOUNT_PATH" ]] || return 1
    CF_TOKEN=$(jq -r '.token // ""' "$CF_ACCOUNT_PATH")
    [[ -n "$CF_TOKEN" ]]
}

save_cf_account() {
    mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
    jq -n --arg t "$CF_TOKEN" '{token:$t}' > "$CF_ACCOUNT_PATH"
    chmod 600 "$CF_ACCOUNT_PATH"
}

cf_verify_credentials() {
    cf_call GET "/accounts" | jq -e '.success == true' &>/dev/null
}

prompt_cf() {
    if load_cf_account; then
        local masked="${CF_TOKEN:0:6}...${CF_TOKEN: -4}"
        read -rp "复用已保存 CF API Token ($masked)? (Y/n): " ans
        if [[ "${ans,,}" =~ ^(|y|yes)$ ]]; then
            if cf_verify_credentials; then
                return 0
            fi
            echo "已保存的 Token 校验失败，请重新输入"
        fi
    fi
    while true; do
        read -rsp "Cloudflare API Token: " CF_TOKEN || die "输入已中断"; echo
        if [[ -z "$CF_TOKEN" ]]; then
            echo "Token 不能为空，请重试"
            continue
        fi
        echo -n "校验凭据... "
        if cf_verify_credentials; then
            echo "通过"
            save_cf_account
            return 0
        fi
        echo "失败：Token 无效，请重新输入（Ctrl+C 退出）"
    done
}

# ── CF DNS / SSL / Origin Rules ───────────────────────
cf_list_zones() {
    cf_call GET "/zones?per_page=100" | jq -r '.result[] | "\(.name) \(.id)"'
}

prompt_select_zone() {
    local zones names i name id
    zones=$(cf_list_zones)
    [[ -z "$zones" ]] && die "CF 账号下没有托管任何域名"

    names=()
    while IFS=' ' read -r name id; do
        names+=("$name|$id")
    done <<< "$zones"

    echo >&2
    header >&2 "═══════════════════════════════════"
    header >&2 "     请选择要绑定的域名"
    header >&2 "═══════════════════════════════════"
    echo >&2
    i=0
    for entry in "${names[@]}"; do
        i=$((i+1))
        echo >&2 "  $i. ${entry%%|*}"
    done
    echo >&2
    while true; do
        read -rp "请输入序号 [1-${#names[@]}]: " sel >&2
        [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#names[@]} )) || { echo >&2 "无效序号，请重新输入"; continue; }
        local selected="${names[$((sel-1))]}"
        local domain="${selected%%|*}"
        local zone_id="${selected##*|}"
        echo >&2
        info >&2 "已选择: $domain"
        echo >&2
        read -rp "使用该域名还是输入子域名? (回车=使用 $domain, 输入子域名前缀): " sub >&2
        if [[ -n "$sub" ]]; then
            sub="${sub#.}"; sub="${sub%.}"
            domain="${sub}.${domain}"
        fi
        echo "$domain|$zone_id"
        return
    done
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

cf_relax_security() {
    local zone_id="$1"
    local sec_level bot_mgmt browser_check

    sec_level=$(cf_get_security_level "$zone_id")
    browser_check=$(cf_get_browser_check "$zone_id")
    bot_mgmt=$(cf_get_bot_management "$zone_id")

    if [[ "$sec_level" != "essentially_off" ]]; then
        cf_set_security_level "$zone_id" "essentially_off"
        ok "Security Level: essentially_off" >&2
    fi

    if [[ "$browser_check" != "off" ]]; then
        cf_set_browser_check "$zone_id" "off"
        ok "Browser Check: off" >&2
    fi

    local sbfm_likely
    sbfm_likely=$(echo "$bot_mgmt" | jq -r '.sbfm_likely_automated // ""')
    if [[ "$sbfm_likely" != "allow" ]]; then
        cf_set_bot_fight_off "$zone_id"
        ok "Bot Fight Mode: 已关闭" >&2
    fi

    # 用 --arg 传字符串，避免 --argjson 解析失败
    # 空字符串或无效 JSON 时降级为 {}
    if [[ -z "$bot_mgmt" || "$bot_mgmt" == "null" ]]; then
        jq -n --arg sl "$sec_level" --arg bc "$browser_check" \
            '{security_level:$sl, browser_check:$bc, bot_management: {}}'
    else
        jq -n --arg sl "$sec_level" --arg bc "$browser_check" --arg bm "$bot_mgmt" \
            '{security_level:$sl, browser_check:$bc, bot_management: ($bm | fromjson)}'
    fi
}

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

build_origin_rule() {
    local domain="$1" route_json="$2"
    # Origin Rule 转发到 VPS 实际监听端口（listen_port），不是 CF 客户端端口（cf_port）
    local port; port=$(echo "$route_json" | jq -r '.listen_port')
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
fix_origin_cert_permissions() {
    [[ -f "$XRAY_CONFIG_DIR/origin.key" ]] || return 0

    local service_user service_group
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        service_user=$(systemctl show xray -p User --value 2>/dev/null || true)
        service_group=$(systemctl show xray -p Group --value 2>/dev/null || true)
    fi
    service_user="${service_user:-root}"
    if [[ -z "$service_group" ]]; then
        service_group=$(id -gn "$service_user" 2>/dev/null || true)
    fi
    service_group="${service_group:-root}"

    if chown "$service_user:$service_group" "$XRAY_CONFIG_DIR/origin.key" 2>/dev/null; then
        chmod 640 "$XRAY_CONFIG_DIR/origin.key"
    else
        warn "无法设置私钥归属，降级使用 644 权限"
        chmod 644 "$XRAY_CONFIG_DIR/origin.key" || die "无法设置源证书私钥权限"
    fi
    chmod 644 "$XRAY_CONFIG_DIR/origin.crt" 2>/dev/null || true
}

gen_origin_cert() {
    local domain="$1"
    info "正在生成 CF 源证书..."
    mkdir -p "$XRAY_CONFIG_DIR"

    # 生成 ECC 私钥
    openssl ecparam -genkey -name prime256v1 -out "$XRAY_CONFIG_DIR/origin.key" 2>/dev/null || die "私钥生成失败"
    ok "私钥已生成: $XRAY_CONFIG_DIR/origin.key"

    # 生成 CSR
    openssl req -new -sha256 -key "$XRAY_CONFIG_DIR/origin.key" -subj "/CN=${domain}" -out /tmp/origin.csr 2>/dev/null || die "CSR 生成失败"
    local csr
    csr=$(awk '{printf "%s\\n", $0}' /tmp/origin.csr)
    rm -f /tmp/origin.csr

    # 通过 CF API 签名
    local resp
    resp=$(curl -s -X POST "${CF_API}/certificates" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"csr\":\"${csr}\",\"hostnames\":[\"${domain}\"],\"request_type\":\"origin-ecc\",\"requested_validity\":365}")
    if ! echo "$resp" | jq -e '.success' &>/dev/null; then
        rm -f "$XRAY_CONFIG_DIR/origin.key"
        die "CF 源证书签名失败: $(echo "$resp" | jq -c '.errors')"
    fi
    echo "$resp" | jq -r '.result.certificate' > "$XRAY_CONFIG_DIR/origin.crt"
    # 设置权限：xray 运行用户需要可读
    fix_origin_cert_permissions
    ok "源证书已签名: $XRAY_CONFIG_DIR/origin.crt"
    ok "有效期: $(echo "$resp" | jq -r '.result.expires_on // "未知"')"
}

revoke_origin_cert() {
    local domain="$1"
    info "正在吊销 CF 源证书..."
    local certs
    certs=$(curl -s -X GET "${CF_API}/certificates" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" 2>/dev/null)
    local cert_id
    cert_id=$(echo "$certs" | jq -r --arg d "$domain" '.result[] | select(.hostnames[] | contains($d)) | .id' 2>/dev/null | head -1)
    if [[ -n "$cert_id" ]]; then
        curl -s -X DELETE "${CF_API}/certificates/${cert_id}" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json" >/dev/null 2>&1 || true
        ok "CF 源证书已吊销"
    else
        info "未找到匹配的源证书"
    fi
    rm -f "$XRAY_CONFIG_DIR/origin.key" "$XRAY_CONFIG_DIR/origin.crt"
    ok "本地证书文件已清理"
}

# ── xray 安装 ─────────────────────────────────────────
install_xray() {
    echo "正在安装 xray-core ..."

    local target_version="${1:-$XRAY_UPDATE_LATEST}"
    [[ -n "$target_version" ]] || target_version=$(get_latest_xray_version)
    [[ -n "$target_version" ]] || die "获取 xray 版本失败"
    target_version="v${target_version#v}"

    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        if curl -fsSL "$XRAY_INSTALL_URL" | bash -s -- install 2>/dev/null; then
            if [[ -f "$XRAY_BINARY" ]]; then
                local installed_version; installed_version=$(get_xray_version || true)
                if [[ "${installed_version#v}" == "${target_version#v}" ]]; then
                    ok "xray-core 安装完成: v${installed_version#v}"
                    return
                fi
                info "官方安装器未安装目标版本，改用 v${target_version#v} 手动更新"
            fi
        fi
    fi

    info "使用手动安装方式"
    local arch
    case "$(uname -m)" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        armv7*)        arch="arm32-v7a" ;;
        *)             die "不支持的架构: $(uname -m)" ;;
    esac

    local ver="$target_version"
    info "xray $ver ($arch)"

    local tmp="/tmp/xray-install-$$"
    mkdir -p "$tmp"
    curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${arch}.zip" || die "下载失败"

    unzip -o "$tmp/xray.zip" xray -d /usr/local/bin/ || die "解压失败"
    chmod +x "$XRAY_BINARY"
    rm -rf "$tmp"

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
    local transport; transport=$(echo "$route_json" | jq -r '.transport // "websocket"')
    local domain; domain=$(echo "$route_json" | jq -r '.domain // ""')
    local tls_enabled; tls_enabled=$(echo "$route_json" | jq -r '.tls // false')

    local security="none" tls_settings="null"
    if [[ "$tls_enabled" == "true" ]]; then
        security="tls"
        tls_settings=$(jq -n --arg d "$domain" '{
            serverName:$d,
            certificates:[{certificateFile:"/usr/local/etc/xray/origin.crt",keyFile:"/usr/local/etc/xray/origin.key"}]
        }')
    fi

    local stream_settings
    case "$transport" in
        websocket)
            stream_settings=$(jq -n --arg p "$path" --arg d "$domain" --arg sec "$security" --argjson tls "$tls_settings" '{
                network:"websocket", security:$sec,
                tlsSettings:$tls,
                wsSettings:{path:$p, headers:{Host:$d}}
            }')
            ;;
        splithttp)
            stream_settings=$(jq -n --arg p "$path" --arg d "$domain" --arg sec "$security" --argjson tls "$tls_settings" '{
                network:"splithttp", security:$sec,
                tlsSettings:$tls,
                xhttpSettings:{host:$d, path:$p, mode:"packet-up"}
            }')
            ;;
        *)
            echo "不支持的传输协议: $transport" >&2; return 1
            ;;
    esac

    jq -n --arg uid "$uid" --arg port "$port" --argjson ss "$stream_settings" '{
        log:{loglevel:"warning"},
        inbounds:[{
            tag:"in-vless",
            listen:"0.0.0.0",
            port: ($port | tonumber),
            protocol:"vless",
            settings:{clients:[{id:$uid,flow:""}],decryption:"none",
                fallbacks:[{dest:443}]
            },
            streamSettings:$ss,
            sniffing:{enabled:true,destOverride:["http","tls"]}
        }],
        outbounds:[{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}],
        routing:{domainStrategy:"IPIfNonMatch",rules:[{type:"field",outboundTag:"block",protocol:["bittorrent"]}]}
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
    local uid="$1" domain="$2" path="$3" transport="$4" cf_port="$5" tls_enabled="$6"
    # 生成原始 VLESS 链接
    local transport_param="ws"
    [[ "$transport" == "splithttp" ]] && transport_param="xhttp"
    local tls_param=""
    [[ "$tls_enabled" == "true" ]] && tls_param="&security=tls&sni=${domain}"
    local vless="vless://${uid}@${domain}:${cf_port}?encryption=none&type=${transport_param}&host=${domain}${tls_param}&path=$(urlencode "$path")#${domain}"
    echo "$vless"
}

# 生成订阅转换链接
build_sub_link() {
    local vless="$1"
    local encoded; encoded=$(urlencode "$vless")
    echo "https://xy.xiyangs.xyz/sub?url=${encoded}"
}

# ── 状态 ──────────────────────────────────────────────
load_state() { [[ -f "$STATE_PATH" ]] && cat "$STATE_PATH"; }
save_state() { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; echo "$1" > "$STATE_PATH"; chmod 600 "$STATE_PATH"; }
remove_state() { rm -f "$STATE_PATH"; }

save_links_snapshot() {
    local domain="$1" uid="$2" link="$3" sub_link="$4"
    { echo "域名: $domain"; echo "UUID: $uid"; echo "VLESS $link"; echo "订阅 $sub_link"; } > "$LAST_LINKS_PATH"
    chmod 600 "$LAST_LINKS_PATH"
}

print_link() {
    echo -e "  \033[1;36m订阅\033[0m  \033[1;37m$1\033[0m"
}

# ── 交互辅助 ─────────────────────────────────────────
prompt_uuid() {
    local uid
    while true; do
        read -rp "UUID(留空=自动生成): " custom_uuid
        if [[ -n "$custom_uuid" ]]; then
            if [[ "$custom_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                uid="${custom_uuid,,}"
                break
            fi
            echo "UUID 格式不正确，请重新输入（格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx）"
        else
            uid=$(gen_uuid)
            break
        fi
    done
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
    while true; do
        read -rp "传输协议(1=WebSocket, 2=XHTTP，留空=WebSocket): " tr_raw
        case "${tr_raw:-1}" in
            1|websocket|ws)           echo "websocket"; break ;;
            2|splithttp|xhttp)        echo "splithttp"; break ;;
            *)                        echo "无效传输协议: $tr_raw，请重新选择" ;;
        esac
    done
}

prompt_tls() {
    read -rp "启用 CF→VPS 加密(源证书)? (Y/n，默认 Y): " tls_raw
    case "${tls_raw,,}" in
        n|no) echo "false" ;;
        *)     echo "true" ;;
    esac
}

# ── 端口检测 ──────────────────────────────────────────
CF_PROXY_PORTS=(443 80 2053 2083 2087 2096 8443)

check_ports_status() {
    local p
    echo >&2
    echo -e "  \033[1;36mCF 可用端口状态:\033[0m" >&2
    for p in "${CF_PROXY_PORTS[@]}"; do
        if ss -tln 2>/dev/null | grep -qE ":$p\s"; then
            echo -e "    \033[31m✗ $p\033[0m  (被占用)" >&2
        else
            echo -e "    \033[32m✓ $p\033[0m  (可用)" >&2
        fi
    done
    echo >&2
}

# ── 生成单条 vless 路由 JSON
build_route() {
    local net_mode="$1" path_prefix="$2" transport="$3" tls_enabled="$4"

    local cf_port=443
    local listen_port
    read -rp "VPS 监听端口 (回车=使用 $cf_port): " listen_port
    [[ -z "$listen_port" ]] && listen_port="$cf_port"
    while ! [[ "$listen_port" =~ ^[0-9]+$ ]]; do
        read -rp "无效端口，请重新输入 VPS 监听端口: " listen_port
        [[ -z "$listen_port" ]] && listen_port="$cf_port"
    done

    if [[ "$net_mode" == "nat" ]]; then
        local ext_port
        while true; do
            read -rp "外部映射端口(对外暴露): " ext_port
            [[ "$ext_port" =~ ^[0-9]+$ ]] && break
            echo "无效端口: $ext_port，请输入数字"
        done
        jq -n --arg p "vless" --argjson lp "$((listen_port))" --argjson cp "$((ext_port))" --arg pa "$path_prefix" --arg tr "$transport" --arg tls "$tls_enabled" \
            '{protocol:$p, listen_port:$lp, cf_port:$cp, path:$pa, transport:$tr, tls: ($tls == "true")}'
    else
        jq -n --arg p "vless" --argjson lp "$((listen_port))" --argjson cp "$((cf_port))" --arg pa "$path_prefix" --arg tr "$transport" --arg tls "$tls_enabled" \
            '{protocol:$p, listen_port:$lp, cf_port:$cp, path:$pa, transport:$tr, tls: ($tls == "true")}'
    fi
}

# ── 1. 安装 ──────────────────────────────────────────
do_install() {
    local state
    state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]]; then
        echo "检测到已有配置 ($(echo "$state" | jq -r '.domain // "?"'))，正在清理旧配置..."
        do_clean_for_reinstall
        ok "旧配置已清理"
    fi

    [[ -f "$XRAY_BINARY" ]] && ok "xray-core 已安装" || install_xray

    local net_mode
    net_mode=$(detect_nat)
    [[ "$net_mode" == "nat" ]] && info "检测到 NAT 环境（内网 IP）" || info "直连环境"

    prompt_cf

    local selected domain zone_id
    selected=$(prompt_select_zone)
    domain="${selected%%|*}"
    zone_id="${selected##*|}"

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
    route_json=$(echo "$route_json" | jq --arg d "$domain" '.domain=$d')

    echo
    header "═══════════════════════════════════"
    header "         配置预览"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m域名:\033[0m    $domain"
    echo -e "  \033[1;36mUUID:\033[0m    $uid"
    echo -e "  \033[1;36m模式:\033[0m    $net_mode"
    echo -e "  \033[1;36m传输协议:\033[0m $(echo "$route_json" | jq -r '.transport')"
    echo -e "  \033[1;36mCF→VPS加密:\033[0m $(echo "$route_json" | jq -r '.tls')"
    echo -e "  \033[1;36m端口:\033[0m    $(echo "$route_json" | jq -r '.listen_port')"
    [[ "$net_mode" == "nat" ]] && echo -e "  \033[1;36m外部端口:\033[0m $(echo "$route_json" | jq -r '.cf_port')"
    echo -e "  \033[1;36m路径:\033[0m    $(echo "$route_json" | jq -r '.path')"
    echo
    header "───────────────────────────────────"
    read -rp "$(echo -e "\033[1;33m确认部署? \033[0m\033[37m(Y/n，默认 Y): \033[0m")" confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { echo "已取消"; return; }

    # 先生成证书（如果有 TLS），再配置 xray，最后启动
    if [[ "$tls_enabled" == "true" ]]; then
        gen_origin_cert "$domain"
    fi

    local config
    config=$(gen_xray_config "$route_json" "$uid")
    write_xray_config "$config"
    [[ "$INIT_SYSTEM" == "openrc" && ! -f "$XRAY_OPENRC_SCRIPT" ]] && write_openrc_script && ok "OpenRC 服务脚本已创建"
    restart_xray

    # CF
    local public_ip dns_before ssl_before origin_rules_before dns_record_id
    public_ip=$(get_public_ip)
    dns_before=$(cf_get_dns "$zone_id" "$domain" || echo null)
    [[ -n "$dns_before" ]] || dns_before="null"
    ssl_before=$(cf_get_ssl "$zone_id")
    origin_rules_before=$(cf_get_origin_rules "$zone_id")

    dns_record_id=$(cf_upsert_dns "$zone_id" "$domain" "$public_ip")
    ok "DNS A 记录: $domain -> $public_ip (已代理)"

    if [[ "$tls_enabled" == "true" ]]; then
        cf_set_ssl "$zone_id" "strict"
        ok "SSL 模式: strict（CF→VPS 加密）"
    else
        cf_set_ssl "$zone_id" "flexible"
        ok "SSL 模式: flexible"
    fi

    apply_origin_rule "$zone_id" "$domain" "$route_json"
    ok "Origin Rule 已创建"

    local security_backup
    security_backup=$(cf_relax_security "$zone_id")

    local link
    link=$(build_link "$uid" "$domain" "$(echo "$route_json" | jq -r '.path')" "$transport" "$(echo "$route_json" | jq -r '.cf_port')" "$tls_enabled")
    local sub_link; sub_link=$(build_sub_link "$link")
    save_links_snapshot "$domain" "$uid" "$link" "$sub_link"

    local dns_existed="false"
    [[ "$dns_before" != "null" ]] && dns_existed="true"
    local state_json
    state_json=$(jq -n \
        --arg d "$domain" --arg z "$zone_id" --arg u "$uid" --arg mode "$net_mode" \
        --argjson route "$route_json" \
        --arg drid "$dns_record_id" --argjson dex "$dns_existed" --argjson drec "$dns_before" \
        --arg ssl "$ssl_before" --argjson orbk "$origin_rules_before" \
        --argjson secbk "$security_backup" --arg link "$link" \
        '{domain:$d,zone_id:$z,uuid:$u,net_mode:$mode,route:$route,
          managed_dns_record_id:$drid,dns_backup:{existed:$dex,record:$drec},
          ssl_backup:$ssl,origin_rules_backup:$orbk,security_backup:$secbk,link:$link}') || \
        die "部署状态保存失败，请检查 JSON 数据"
    save_state "$state_json"

    echo
    header "═══════════════════════════════════"
    ok "部署完成"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m域名:\033[0m    $domain"
    echo -e "  \033[1;36mUUID:\033[0m    $uid"
    echo -e "  \033[1;35mVLESS\033[0m $link"
    echo -e "  \033[1;36m订阅\033[0m  $sub_link"
    echo
    echo -e "  \033[2;37m已保存到 $LAST_LINKS_PATH\033[0m"
}

# ── 2. 卸载节点 ──────────────────────────────────────
# 内部：恢复 CF 侧配置到备份状态
_restore_cf_config() {
    local state="$1" zone_id="$2"
    cf_put_origin_rules "$zone_id" "$(echo "$state" | jq '.origin_rules_backup // []')" 2>/dev/null || true
    local ssl_bk; ssl_bk=$(echo "$state" | jq -r '.ssl_backup // ""')
    [[ -n "$ssl_bk" ]] && cf_set_ssl "$zone_id" "$ssl_bk" 2>/dev/null || true
    local dns_existed record_id
    dns_existed=$(echo "$state" | jq -r '.dns_backup.existed')
    record_id=$(echo "$state" | jq -r '.managed_dns_record_id // ""')
    if [[ "$dns_existed" == "true" && -n "$record_id" ]]; then
        local rp; rp=$(echo "$state" | jq '.dns_backup.record | {type:(.type//"A"),name:(.name//""),content:(.content//""),proxied:(.proxied//false),ttl:(.ttl//1)}')
        cf_call PUT "/zones/${zone_id}/dns_records/${record_id}" "$rp" >/dev/null 2>&1 || true
    elif [[ -n "$record_id" ]]; then
        cf_call DELETE "/zones/${zone_id}/dns_records/${record_id}" "" --no-fail >/dev/null 2>&1 || true
    fi
    local sec_bk; sec_bk=$(echo "$state" | jq '.security_backup // null')
    cf_restore_security "$zone_id" "$sec_bk" 2>/dev/null || true
}

do_uninstall() {
    local state
    state=$(load_state 2>/dev/null || true)
    if [[ -z "$state" ]]; then
        if svc_is_active 2>/dev/null || [[ -f "$XRAY_CONFIG_PATH" ]]; then
            echo "未检测到状态文件，但发现 xray 仍在运行，尝试强制清理..."
            svc_stop
            rm -f "$XRAY_CONFIG_PATH" "$XRAY_CONFIG_DIR/origin.key" "$XRAY_CONFIG_DIR/origin.crt"
            ok "xray 已停止，配置已清理"
            return
        fi
        echo "未检测到部署"
        return
    fi

    local domain; domain=$(echo "$state" | jq -r '.domain')
    local tls_was_enabled; tls_was_enabled=$(echo "$state" | jq -r '.route.tls // false')
    echo "正在卸载: $domain"

    svc_stop; rm -f "$XRAY_CONFIG_PATH"
    ok "xray 已停止"

    if load_cf_account; then
        [[ "$tls_was_enabled" == "true" ]] && revoke_origin_cert "$domain"
        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // ""')
        [[ -n "$zone_id" ]] && _restore_cf_config "$state" "$zone_id"
    else
        echo "无 CF 凭据，跳过恢复"
    fi

    remove_state
    rm -f "$LAST_LINKS_PATH"
    ok "已清理订阅快照"
    ok "卸载完成"
}

# 内部：安装覆盖时清理旧配置（保留 CF 凭证）
do_clean_for_reinstall() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -z "$state" ]] && return 0

    local domain; domain=$(echo "$state" | jq -r '.domain')
    local tls_was_enabled; tls_was_enabled=$(echo "$state" | jq -r '.route.tls // false')
    local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // ""')

    if load_cf_account && [[ -n "$zone_id" ]]; then
        [[ "$tls_was_enabled" == "true" ]] && revoke_origin_cert "$domain"
        _restore_cf_config "$state" "$zone_id"
    fi

    svc_stop 2>/dev/null || true
    rm -f "$XRAY_CONFIG_PATH" "$XRAY_CONFIG_DIR/origin.key" "$XRAY_CONFIG_DIR/origin.crt"
    remove_state
    rm -f "$LAST_LINKS_PATH"
}

# ── 2c. 完全卸载（含凭证）──────────────────────────
do_purge() {
    echo
    header "═══════════════════════════════════"
    header "       完全卸载（含凭证）"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;33m⚠ 此操作将:\033[0m"
    echo -e "  \033[2;37m- 卸载节点（清理 CF 配置）\033[0m"
    echo -e "  \033[2;37m- 删除 CF API Token 凭证\033[0m"
    echo -e "  \033[2;37m- 删除 xray 核心程序\033[0m"
    echo -e "  \033[2;37m- 删除快捷命令 /usr/local/bin/x\033[0m"
    echo
    read -rp "$(echo -e "\033[1;33m确认完全卸载? \033[0m\033[37m(y/N): \033[0m")" confirm
    [[ "${confirm,,}" == "y" || "${confirm,,}" == "yes" ]] || { echo "已取消"; return; }

    do_clean_for_reinstall

    # 删除 xray 二进制、数据、服务
    if svc_is_active 2>/dev/null; then svc_stop; fi
    rm -f "$XRAY_BINARY"
    rm -rf "/usr/local/share/xray"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        rm -f "/etc/systemd/system/xray.service"
        rm -rf "/etc/systemd/system/xray.service.d"
        systemctl daemon-reload &>/dev/null
    elif [[ -f "$XRAY_OPENRC_SCRIPT" ]]; then
        rm -f "$XRAY_OPENRC_SCRIPT"
    fi

    rm -f "$CF_ACCOUNT_PATH" "/usr/local/bin/x"
    ok "CF 凭证已删除"
    ok "快捷命令已删除"
    ok "xray 核心已卸载"
    ok "完全卸载完成"
}

# ── 3. 查看订阅 ──────────────────────────────────────
do_show() {
    if [[ -f "$LAST_LINKS_PATH" ]]; then
        echo
        header "═══════════════════════"
        header "      订阅信息"
        header "═══════════════════════"
        echo
        while IFS= read -r line; do
            case "$line" in
                域名:*) echo -e "  \033[1;36m${line%%:*}\033[0m:${line#*:}" ;;
                UUID:*) echo -e "  \033[1;36m${line%%:*}\033[0m:${line#*:}" ;;
                VLESS*) echo -e "  \033[1;35m${line%% *}\033[0m ${line#* }" ;;
                订阅*)  echo -e "  \033[1;36m${line%% *}\033[0m  ${line#* }" ;;
                *)       echo "  $line" ;;
            esac
        done < "$LAST_LINKS_PATH"
        echo
        return
    fi
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }
    echo
    header "═══════════════════════"
    header "      订阅信息"
    header "═══════════════════════"
    echo
    echo -e "  \033[1;36m域名:\033[0m $(echo "$state" | jq -r '.domain')"
    echo -e "  \033[1;36mUUID:\033[0m $(echo "$state" | jq -r '.uuid')"
    echo -e "  \033[1;35mVLESS\033[0m $(echo "$state" | jq -r '.link')"
    echo
}

# ── 4. 修改配置 ──────────────────────────────────────
do_modify() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local domain uid route_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    uid=$(echo "$state" | jq -r '.uuid')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    echo
    header "═══════════════════════════════════"
    header "    修改配置 ($net_mode)"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m域名:\033[0m    $domain  \033[1;36mUUID:\033[0m $uid"
    echo -e "  \033[1;36m传输协议:\033[0m $(echo "$route_json" | jq -r '.transport // "websocket"')"
    echo -e "  \033[1;36mCF→VPS加密:\033[0m $(echo "$route_json" | jq -r '.tls // false')"
    echo -e "  \033[1;36m端口:\033[0m    $(echo "$route_json" | jq -r '.listen_port')  \033[1;36mCF端口:\033[0m $(echo "$route_json" | jq -r '.cf_port')  \033[1;36m路径:\033[0m $(echo "$route_json" | jq -r '.path')"
    echo
    header "───────────────────────────────────"
    echo -e "  \033[1;32m 1\033[0m. 修改 UUID"
    echo -e "  \033[1;33m 2\033[0m. 修改端口"
    echo -e "  \033[1;34m 3\033[0m. 修改路径"
    echo -e "  \033[1;35m 4\033[0m. 修改传输协议"
    echo -e "  \033[1;36m 5\033[0m. 切换 CF→VPS 加密"
    echo -e "  \033[1;37m 6\033[0m. 全部修改"
    echo -e "  \033[1;31m 0\033[0m. 返回"
    echo
    read -rp "$(echo -e "\033[1;33m请选择 [0-6]: \033[0m")" mc

    local new_uid="$uid" new_route="$route_json" changed=false

    [[ "$mc" =~ ^[0-6]$ ]] || { echo "无效选项"; return; }
    [[ "$mc" == "0" ]] && return

    if [[ "$mc" == "1" || "$mc" == "6" ]]; then
        while true; do
            read -rp "新 UUID(留空=重新生成): " iu
            if [[ -n "$iu" ]]; then
                if [[ "$iu" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                    new_uid="${iu,,}"
                    break
                fi
                echo "UUID 格式不正确，请重新输入（格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx）"
            else
                new_uid=$(gen_uuid)
                break
            fi
        done
        changed=true; ok "UUID: $new_uid"
    fi

    if [[ "$mc" == "2" || "$mc" == "6" ]]; then
        if [[ "$net_mode" == "nat" ]]; then
            local lp cp
            lp=$(echo "$new_route" | jq -r '.listen_port')
            cp=$(echo "$new_route" | jq -r '.cf_port')
            read -rp "内部监听端口(当前=$lp): " new_lp
            read -rp "外部映射端口(当前=$cp): " new_cp
            if [[ -n "$new_lp" ]]; then
                [[ "$new_lp" =~ ^[0-9]+$ ]] && lp="$new_lp" || { echo "无效端口: $new_lp"; return; }
            fi
            if [[ -n "$new_cp" ]]; then
                [[ "$new_cp" =~ ^[0-9]+$ ]] && cp="$new_cp" || { echo "无效端口: $new_cp"; return; }
            fi
            new_route=$(echo "$new_route" | jq --argjson lp "$((lp))" --argjson cp "$((cp))" '.listen_port=$lp|.cf_port=$cp')
            changed=true; ok "端口已更新"
        else
            local p; p=$(echo "$new_route" | jq -r '.listen_port')
            read -rp "新端口(当前=$p): " np
            if [[ -n "$np" ]]; then
                [[ "$np" =~ ^[0-9]+$ ]] || { echo "无效端口: $np"; return; }
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
        local cur_tr; cur_tr=$(echo "$new_route" | jq -r '.transport // "websocket"')
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
                local _revoke_after=true
            fi
        else
            echo "当前: 未启用 CF→VPS 加密"
            read -rp "开启加密? (y/N): " on_tls
            if [[ "${on_tls,,}" == "y" || "${on_tls,,}" == "yes" ]]; then
                new_route=$(echo "$new_route" | jq '.tls=true')
                changed=true; ok "CF→VPS 加密: 已开启"
                local _gen_cert_after=true
            fi
        fi
    fi

    [[ "$changed" == "true" ]] || { echo "无修改"; return; }

    new_route=$(echo "$new_route" | jq --arg d "$domain" '.domain=$d')

    # 处理 TLS 变更的实际操作（在重启 xray 之前）
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

    local link; link=$(build_link "$new_uid" "$domain" "$(echo "$new_route" | jq -r '.path')" "$(echo "$new_route" | jq -r '.transport // "websocket"')" "$(echo "$new_route" | jq -r '.cf_port')" "$(echo "$new_route" | jq -r '.tls')")
    local sub_link; sub_link=$(build_sub_link "$link")
    save_links_snapshot "$domain" "$new_uid" "$link" "$sub_link"
    save_state "$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_route" --arg l "$link" \
        '.uuid=$u|.route=$r|.link=$l')"

    echo; ok "配置已更新"; print_link "$link"
}

# ── 5. 查看当前配置 ──────────────────────────────────
do_show_config() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    echo
    header "═══════════════════════════════════"
    header "         当前配置信息"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m域名:\033[0m    $(echo "$state" | jq -r '.domain')"
    echo -e "  \033[1;36mUUID:\033[0m    $(echo "$state" | jq -r '.uuid')"
    echo -e "  \033[1;36m模式:\033[0m    $(echo "$state" | jq -r '.net_mode // "direct"')"
    echo -e "  \033[1;36m传输协议:\033[0m $(echo "$state" | jq -r '.route.transport // "websocket"')"
    echo -e "  \033[1;36mCF→VPS加密:\033[0m $(echo "$state" | jq -r '.route.tls // false')"
    echo -e "  \033[1;36m端口:\033[0m    $(echo "$state" | jq -r '.route.listen_port')"
    echo -e "  \033[1;36mCF端口:\033[0m  $(echo "$state" | jq -r '.route.cf_port')"
    echo -e "  \033[1;36m路径:\033[0m    $(echo "$state" | jq -r '.route.path')"
    echo
    echo -ne "  \033[1;36mxray:\033[0m    "; svc_is_active && ok "运行中" || warn "未运行"
    echo
    header "───────────────────────────────────"
    echo -e "  \033[1;35m订阅:\033[0m"
    print_link "$(echo "$state" | jq -r '.link')"
    echo
}

# ── 6. 更新外部端口（NAT 快捷操作）──────────────────
do_update_ports() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local domain route_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    if [[ "$net_mode" != "nat" ]]; then
        echo
        header "═══════════════════════════════════"
        header "       更新外部端口"
        header "═══════════════════════════════════"
        echo
        info "直连模式没有外部端口映射，端口变更请使用 [4.修改配置]"
        return
    fi

    echo
    header "═══════════════════════════════════"
    header "       更新外部端口"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m当前端口映射:\033[0m"
    echo -e "  \033[33m监听\033[0m:$(echo "$route_json" | jq -r '.listen_port') \033[1;33m→\033[0m \033[36m外部\033[0m:$(echo "$route_json" | jq -r '.cf_port')"
    echo

    info "NAT 模式: 只更新外部端口 (CF Origin Rules)，xray 监听端口不变"
    echo

    local old_cp; old_cp=$(echo "$route_json" | jq -r '.cf_port')
    read -rp "$(echo -e "\033[1;33m新外部端口(当前=$old_cp): \033[0m")" ne
    [[ -n "$ne" ]] || { echo "不能为空"; return; }
    [[ "$ne" =~ ^[0-9]+$ ]] || { echo "无效端口: $ne"; return; }
    local new_route; new_route=$(echo "$route_json" | jq --argjson p "$((ne))" '.cf_port=$p')

    echo
    header "───────────────────────────────────"
    echo -e "  \033[1;36m更新预览:\033[0m \033[33m监听\033[0m:$(echo "$new_route" | jq -r '.listen_port') \033[1;33m→\033[0m \033[36m外部\033[0m:$(echo "$new_route" | jq -r '.cf_port')"
    header "───────────────────────────────────"
    read -rp "$(echo -e "\033[1;33m确认? \033[0m\033[37m(Y/n): \033[0m")" confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { echo "已取消"; return; }

    load_cf_account || die "未找到 CF 凭据"
    apply_origin_rule "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_route"
    ok "Origin Rule 已更新"

    local public_ip; public_ip=$(get_public_ip)
    local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id')
    local current_dns; current_dns=$(cf_get_dns "$zone_id" "$domain")
    local current_ip; current_ip=$(echo "$current_dns" | jq -r '.content // ""')
    if [[ "$current_ip" != "$public_ip" ]]; then
        cf_upsert_dns "$zone_id" "$domain" "$public_ip" >/dev/null
        ok "DNS 已更新: $domain -> $public_ip"
    fi

    local uid; uid=$(echo "$state" | jq -r '.uuid')
    local link; link=$(build_link "$uid" "$domain" "$(echo "$new_route" | jq -r '.path')" "$(echo "$new_route" | jq -r '.transport // "websocket"')" "$(echo "$new_route" | jq -r '.cf_port')" "$(echo "$new_route" | jq -r '.tls')")
    local sub_link; sub_link=$(build_sub_link "$link")
    save_links_snapshot "$domain" "$uid" "$link" "$sub_link"
    save_state "$(echo "$state" | jq --argjson r "$new_route" --arg l "$link" '.route=$r|.link=$l')"

    echo; ok "外部端口已更新"; print_link "$link"
}

# ── 7. 更新 xray ─────────────────────────────────────
do_update_xray() {
    echo -e "\033[1;34m·\033[0m 使用进入脚本时检测到的版本信息..."

    local current_ver="$XRAY_UPDATE_CURRENT"
    if [[ -z "$current_ver" ]]; then
        warn "当前 xray 未安装或无法获取版本"
        read -rp "$(echo -e "\033[1;33m是否安装最新版? \033[0m\033[37m(Y/n): \033[0m")" confirm
        [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || return
        install_xray "$XRAY_UPDATE_LATEST"
        restart_xray
        XRAY_UPDATE_CURRENT=$(get_xray_version || true)
        XRAY_UPDATE_STATUS="已安装 v${XRAY_UPDATE_CURRENT:-未知}"
        return
    fi
    info "当前版本: $current_ver"

    local latest_ver="$XRAY_UPDATE_LATEST"
    [[ -n "$latest_ver" ]] || die "获取最新版本失败"
    info "最新版本: $latest_ver"

    if [[ "$current_ver" == "$latest_ver" ]]; then
        ok "已是最新版本，无需更新"
        return
    fi

    echo
    echo -e "  \033[1;33m发现新版本:\033[0m \033[31m$current_ver\033[0m \033[1;33m→\033[0m \033[32m$latest_ver\033[0m"
    read -rp "$(echo -e "\033[1;33m确认更新? \033[0m\033[37m(Y/n): \033[0m")" confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { info "已取消"; return; }

    install_xray "$latest_ver"
    restart_xray
    local installed_version; installed_version=$(get_xray_version || true)
    XRAY_UPDATE_CURRENT="$installed_version"
    if [[ "$installed_version" == "$latest_ver" ]]; then
        XRAY_UPDATE_STATUS="已是最新 v${installed_version}"
        ok "xray 已更新至 $installed_version"
    else
        XRAY_UPDATE_STATUS="更新失败，当前 v${installed_version:-未知}"
        warn "xray 实际版本为 ${installed_version:-未知}，目标版本为 $latest_ver"
    fi
    XRAY_UPDATE_LATEST="$latest_ver"
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

# ── 9. 查看日志 ─────────────────────────────────────
do_logs() {
    echo
    header "═══════════════════════════════════"
    header "         xray 运行日志"
    header "═══════════════════════════════════"
    echo
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        journalctl -u xray --no-pager -n 30 --output cat 2>/dev/null || echo "暂无日志"
    else
        cat /var/log/xray.log 2>/dev/null || echo "暂无日志"
    fi
    echo
    read -rp "$(echo -e "\033[1;33m按回车返回\033[0m")"
}

# ── 10. BBR 管理 ─────────────────────────────────────
do_bbr() {
    echo
    header "═══════════════════════════════════"
    header "         BBR 加速管理"
    header "═══════════════════════════════════"
    echo

    local current; current=$(get_bbr_status)
    echo -e "  \033[1;36m当前状态:\033[0m $([[ "$current" == "已启用" ]] && echo "\033[32m$current\033[0m" || echo "\033[31m$current\033[0m")"
    echo

    # 检测是否支持 BBR
    local kernel_ver
    kernel_ver=$(uname -r | grep -oP '^\d+\.\d+')
    if [[ "$(echo "$kernel_ver" | awk -F. '{print $1}')" -lt 4 ]] || \
       { [[ "$(echo "$kernel_ver" | awk -F. '{print $1}')" -eq 4 ]] && [[ "$(echo "$kernel_ver" | awk -F. '{print $2}')" -lt 9 ]]; }; then
        warn "当前内核版本 $(uname -r) 过低，BBR 需要 Linux 4.9+"
        return
    fi

    echo -e "  \033[1;32m 1\033[0m. 开启 BBR"
    echo -e "  \033[1;31m 2\033[0m. 关闭 BBR"
    echo -e "  \033[1;37m 0\033[0m. 返回"
    echo
    read -rp "$(echo -e "\033[1;33m请选择 [0-2]: \033[0m")" bbr_choice

    case "$bbr_choice" in
        1)
            if [[ "$current" == "已启用" ]]; then
                ok "BBR 已开启，无需重复操作"
                return
            fi
            echo "正在开启 BBR..."
            # 写入 sysctl 配置
            mkdir -p /etc/sysctl.d
            cat > /etc/sysctl.d/99-bbr.conf << 'BBREOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
BBREOF
            sysctl -p /etc/sysctl.d/99-bbr.conf &>/dev/null
            # 确认生效
            if bbr_is_enabled; then
                ok "BBR 已开启"
                echo -e "  \033[2;37m当前拥塞控制算法: \033[33m$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')\033[0m"
            else
                # 可能需要加载模块
                modprobe tcp_bbr 2>/dev/null || true
                sysctl -p /etc/sysctl.d/99-bbr.conf &>/dev/null
                if bbr_is_enabled; then
                    ok "BBR 已开启"
                else
                    warn "BBR 模块加载失败，可能需要重启系统"
                fi
            fi
            ;;
        2)
            if [[ "$current" != "已启用" ]]; then
                ok "BBR 未开启，无需关闭"
                return
            fi
            echo "正在关闭 BBR..."
            # 恢复默认的 cubic
            mkdir -p /etc/sysctl.d
            cat > /etc/sysctl.d/99-bbr.conf << 'BBREOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = cubic
BBREOF
            sysctl -p /etc/sysctl.d/99-bbr.conf &>/dev/null
            # 卸载模块（如果没有其他引用）
            modprobe -r tcp_bbr 2>/dev/null || true
            ok "BBR 已关闭（已切换为 cubic）"
            echo -e "  \033[2;37m当前拥塞控制算法: \033[33m$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')\033[0m"
            ;;
        0) return ;;
        *) echo "无效选项" ;;
    esac
}

ensure_shortcut() {
    local target="/usr/local/bin/x"
    local script_path
    script_path="$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")"

    if [[ ! -f "$target" ]] || [[ "$(head -1 "$target" 2>/dev/null)" != "#!/bin/bash" ]]; then
        cat > "$target" << SCEOF
#!/bin/bash
exec bash "$script_path" "\$@"
SCEOF
        chmod +x "$target"
        ok "快捷命令已创建: $target"
    fi
}

main() {
    [[ "$(id -u)" == "0" ]] || die "请使用 root 运行此脚本"
    detect_init
    install_deps
    need_cmd curl; need_cmd jq; need_cmd openssl
    ensure_shortcut
    check_xray_update

    while true; do
        local state current_domain="" net_mode="" transport="" port="" tls_status=""
        state=$(load_state 2>/dev/null || true)
        if [[ -n "$state" ]]; then
            current_domain=$(echo "$state" | jq -r '.domain // ""')
            net_mode=$(echo "$state" | jq -r '.net_mode // ""')
            transport=$(echo "$state" | jq -r '.route.transport // ""')
            port=$(echo "$state" | jq -r '.route.listen_port // ""')
            local tls_val; tls_val=$(echo "$state" | jq -r '.route.tls // false')
            [[ "$tls_val" == "true" ]] && tls_status="TLS" || tls_status=""
        fi

        local bbr_status; bbr_status=$(get_bbr_status)

        echo
        local title="xray-cf ($INIT_SYSTEM)"
        echo -e "  \033[1;36m$title\033[0m"
        local info=""
        if [[ -n "$current_domain" ]]; then
            info+="\033[33m$current_domain\033[0m"
            [[ -n "$transport" ]] && info+=" \033[37m$transport\033[0m"
            [[ -n "$port" ]] && info+=" \033[37m:$port\033[0m"
            [[ -n "$tls_status" ]] && info+=" \033[37m$tls_status\033[0m"
            [[ -n "$net_mode" ]] && info+=" \033[37m[$net_mode]\033[0m"
            info+="  \033[37m|\033[0m  "
        fi
        if svc_is_active; then
            info+="xray \033[32m● 运行中\033[0m"
        else
            info+="xray \033[31m● 已关闭\033[0m"
        fi
        echo -e "     $info"
        if svc_is_active; then
            local ver mem pid uptime
            ver=$(get_xray_version || echo "?")
            if [[ "$INIT_SYSTEM" == "systemd" ]]; then
                mem=$(systemctl show xray -p MemoryCurrent --value 2>/dev/null)
                mem=$(awk -v m="$mem" 'BEGIN{if (m>1048576) printf "%.1f MB", m/1048576; else printf "%.1f KB", m/1024}')
                pid=$(systemctl show xray -p MainPID --value 2>/dev/null)
                uptime=$(systemctl show xray -p ActiveEnterTimestamp --value 2>/dev/null)
                uptime=$(date -d "$uptime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$uptime")
            else
                pid=$(cat /run/xray.pid 2>/dev/null || echo "?")
                mem="N/A"
                uptime="N/A"
            fi
            echo -e "     \033[36mv${ver}\033[0m  \033[33mPID:${pid}\033[0m  \033[35m内存:${mem}\033[0m  \033[37m启动:${uptime}\033[0m"
        fi
        echo
        echo -e "  \033[1;32m 1\033[0m. 安装节点"
        echo -e "  \033[1;31m 2\033[0m. 卸载节点"
        echo -e "  \033[1;34m 3\033[0m. 查看订阅"
        echo -e "  \033[1;33m 4\033[0m. 修改配置 (UUID/端口/路径)"
        echo -e "  \033[1;34m 5\033[0m. 查看当前配置"
        echo -e "  \033[1;33m 6\033[0m. 更新外部端口 (NAT换端口)"
        local update_label="$XRAY_UPDATE_STATUS"
        [[ -n "$update_label" ]] && update_label=" [${update_label}]"
        echo -e "  \033[1;35m 7\033[0m. 更新 xray\033[33m${update_label}\033[0m"
        echo -e "  \033[1;36m 8\033[0m. 查看日志"
        echo -e "  \033[1;36m 9\033[0m. 重启 xray"
        echo -e "  \033[1;31m10\033[0m. 完全卸载（含凭证）"
        local bbr_label="BBR 加速"
        [[ "$bbr_status" == "已启用" ]] && bbr_label+=" (\033[32m$bbr_status\033[0m)" || bbr_label+=" (\033[31m$bbr_status\033[0m)"
        echo -e "  \033[1;32m11\033[0m. $bbr_label"
        echo -e "  \033[1;31m 0\033[0m. 退出"
        echo

        read -rp "$(echo -e "\033[1;33m请选择 [0-11]: \033[0m")" choice
        case "$choice" in
            0) exit 0 ;;
            1) do_install ;; 2) do_uninstall ;; 3) do_show ;;
            4) do_modify ;; 5) do_show_config ;; 6) do_update_ports ;;
            7) do_update_xray ;;
            8) do_logs ;;
            9) do_restart ;;
            10) do_purge ;;
            11) do_bbr ;;
            *) echo "无效选项: $choice，请重新选择"; sleep 1 ;;
        esac
    done
}

main "$@"
