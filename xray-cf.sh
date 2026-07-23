#!/usr/bin/env bash
set -euo pipefail

# ── 常量 ──────────────────────────────────────────────
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="$XRAY_CONFIG_DIR/config.json"
XRAY_BINARY="/usr/local/bin/xray"
SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_CONFIG_PATH="$SINGBOX_CONFIG_DIR/config.json"
SINGBOX_BINARY="/usr/bin/sing-box"
STATE_DIR="/etc/xray-cf-lite"
STATE_PATH="$STATE_DIR/state.json"
CF_ACCOUNT_PATH="$STATE_DIR/cf_account.json"
LAST_LINKS_PATH="$(pwd)/cf_lite_last_links.txt"

CF_API="https://api.cloudflare.com/client/v4"
MANAGED_PREFIX="xray-cf-lite "
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
XRAY_RELEASES_API="https://api.github.com/repos/XTLS/Xray-core/releases"
SINGBOX_INSTALL_URL="https://sing-box.app/install.sh"
SINGBOX_RELEASES_API="https://api.github.com/repos/SagerNet/sing-box/releases"

XRAY_UPDATE_STATUS=""
XRAY_UPDATE_CURRENT=""
XRAY_UPDATE_LATEST=""
SINGBOX_UPDATE_STATUS=""
SINGBOX_UPDATE_CURRENT=""
SINGBOX_UPDATE_LATEST=""

# 当前活动内核: xray | singbox（由 state 或协议推断）
ACTIVE_KERNEL="xray"

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
    curl -sf --connect-timeout 5 --max-time 15 \
        -H 'User-Agent: xray-cf-lite' "${XRAY_RELEASES_API}?per_page=100" |
        jq -r '[.[] | select(.prerelease == true)][0].tag_name // empty' 2>/dev/null |
        sed 's/^v//' || true
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

resolve_singbox_binary() {
    if [[ -x "$SINGBOX_BINARY" ]]; then
        echo "$SINGBOX_BINARY"
        return 0
    fi
    if command -v sing-box &>/dev/null; then
        command -v sing-box
        return 0
    fi
    return 1
}

get_singbox_version() {
    local bin
    bin=$(resolve_singbox_binary) || return 1
    # 输出示例: sing-box version 1.14.0-alpha.50
    "$bin" version 2>/dev/null | sed -n 's/.*version[[:space:]]\+\([0-9][0-9a-zA-Z._-]*\).*/\1/p' | head -1
}

get_latest_singbox_version() {
    # 与 xray 一致：优先取最新 pre-release
    curl -sf --connect-timeout 5 --max-time 15 \
        -H 'User-Agent: xray-cf-lite' "${SINGBOX_RELEASES_API}?per_page=100" |
        jq -r '[.[] | select(.prerelease == true)][0].tag_name // empty' 2>/dev/null |
        sed 's/^v//' || true
}

check_singbox_update() {
    local current latest status
    current=$(get_singbox_version || true)
    latest=$(get_latest_singbox_version || true)

    if [[ -z "$latest" ]]; then
        status="版本检测失败"
    elif [[ -z "$current" ]]; then
        status="可安装 v${latest}"
    elif [[ "$current" == "$latest" ]]; then
        status="已是最新 v${current}"
    else
        status="检测到 v${latest}，可更新"
    fi

    SINGBOX_UPDATE_CURRENT="$current"
    SINGBOX_UPDATE_LATEST="$latest"
    SINGBOX_UPDATE_STATUS="$status"
}

# 协议 → 内核
kernel_for_protocol() {
    case "${1:-}" in
        hy2|hysteria2|tuic) echo "singbox" ;;
        *)                  echo "xray" ;;
    esac
}

# 从 state 推断活动内核
detect_active_kernel() {
    local state protocol kernel
    state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]]; then
        kernel=$(echo "$state" | jq -r '.kernel // empty' 2>/dev/null || true)
        if [[ -n "$kernel" ]]; then
            echo "$kernel"
            return
        fi
        protocol=$(echo "$state" | jq -r '.route.protocol // "vless"' 2>/dev/null || true)
        kernel_for_protocol "$protocol"
        return
    fi
    # 无 state：若仅装了某一内核则用之
    if resolve_singbox_binary &>/dev/null && ! [[ -x "$XRAY_BINARY" ]]; then
        echo "singbox"
    else
        echo "xray"
    fi
}

refresh_active_kernel() {
    ACTIVE_KERNEL=$(detect_active_kernel)
}

is_udp_protocol() {
    case "${1:-}" in
        hy2|hysteria2|tuic) return 0 ;;
        *) return 1 ;;
    esac
}

# ── init 系统检测 ─────────────────────────────────────
require_systemd() {
    if ! command -v systemctl &>/dev/null || ! systemctl --version &>/dev/null 2>&1; then
        die "仅支持 systemd 系统"
    fi
}
# ── 包管理器 ──────────────────────────────────────────
install_deps() {
    local missing=()
    command -v curl    &>/dev/null || missing+=(curl)
    command -v jq      &>/dev/null || missing+=(jq)
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

# ── 服务管理（xray / sing-box 双内核）────────────────
svc_unit() {
    case "${1:-$ACTIVE_KERNEL}" in
        singbox|sing-box) echo "sing-box" ;;
        *)                echo "xray" ;;
    esac
}

svc_enable() {
    local unit; unit=$(svc_unit "${1:-}")
    systemctl enable "$unit" &>/dev/null; true
}
svc_start() {
    local unit; unit=$(svc_unit "${1:-}")
    systemctl restart "$unit"
}
svc_stop() {
    local unit; unit=$(svc_unit "${1:-}")
    systemctl stop "$unit" &>/dev/null
    systemctl disable "$unit" &>/dev/null
    true
}
svc_is_active() {
    local unit; unit=$(svc_unit "${1:-}")
    systemctl is-active "$unit" &>/dev/null
}

ensure_systemd_restart() {
    local unit drop
    unit=$(svc_unit "${1:-}")
    drop="/etc/systemd/system/${unit}.service.d"
    if [[ ! -f "$drop/restart.conf" ]]; then
        mkdir -p "$drop"
        cat > "$drop/restart.conf" << 'SDEOF'
[Service]
Restart=on-failure
RestartSec=1
SDEOF
        systemctl daemon-reload
    fi
}

# 证书权限：兼容 xray 与 sing-box 运行用户
fix_service_cert_permissions() {
    local cert_dir="$1" key_file="$2" crt_file="${3:-}"
    [[ -f "$key_file" ]] || return 0

    local unit service_user service_group
    unit=$(svc_unit "${4:-}")
    service_user=$(systemctl show "$unit" -p User --value 2>/dev/null || true)
    service_group=$(systemctl show "$unit" -p Group --value 2>/dev/null || true)
    service_user="${service_user:-root}"
    if [[ -z "$service_group" ]]; then
        service_group=$(id -gn "$service_user" 2>/dev/null || true)
    fi
    service_group="${service_group:-root}"

    if chown "$service_user:$service_group" "$key_file" 2>/dev/null; then
        chmod 640 "$key_file"
    else
        warn "无法设置私钥归属，降级使用 644 权限"
        chmod 644 "$key_file" || die "无法设置证书私钥权限"
    fi
    [[ -n "$crt_file" && -f "$crt_file" ]] && chmod 644 "$crt_file" 2>/dev/null || true
}

restart_xray() {
    fix_origin_cert_permissions
    ensure_systemd_restart "xray"
    svc_enable "xray"
    svc_start "xray" || die "xray 重启失败"
    sleep 1
    svc_is_active "xray" || die "xray 未正常启动，请查看日志"
    ok "xray 服务已启动"
}

restart_singbox() {
    fix_service_cert_permissions "$SINGBOX_CONFIG_DIR" \
        "$SINGBOX_CONFIG_DIR/server.key" "$SINGBOX_CONFIG_DIR/server.crt" "singbox"
    ensure_systemd_restart "singbox"
    svc_enable "singbox"
    svc_start "singbox" || die "sing-box 重启失败"
    sleep 1
    svc_is_active "singbox" || die "sing-box 未正常启动，请查看日志"
    ok "sing-box 服务已启动"
}

# 按活动内核重启
restart_proxy() {
    case "${1:-$ACTIVE_KERNEL}" in
        singbox|sing-box) restart_singbox ;;
        *)                restart_xray ;;
    esac
}

# 停止另一内核，避免端口/资源冲突
stop_other_kernel() {
    local want="${1:-$ACTIVE_KERNEL}"
    case "$want" in
        singbox|sing-box)
            if systemctl is-active xray &>/dev/null; then
                systemctl stop xray &>/dev/null || true
                info "已停止 xray，切换为 sing-box"
            fi
            ;;
        *)
            if systemctl is-active sing-box &>/dev/null; then
                systemctl stop sing-box &>/dev/null || true
                info "已停止 sing-box，切换为 xray"
            fi
            ;;
    esac
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
    service_user=$(systemctl show xray -p User --value 2>/dev/null || true)
    service_group=$(systemctl show xray -p Group --value 2>/dev/null || true)
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
    info "使用 Xray 官方安装器安装最新预发布版 (--beta)"
    curl -fsSL "$XRAY_INSTALL_URL" | bash -s -- install --beta || die "Xray 官方安装器执行失败"
    [[ -x "$XRAY_BINARY" ]] || die "安装后未找到 xray"
    ok "xray-core 预发布版安装完成: $($XRAY_BINARY version | head -1)"
}

# ── sing-box 安装 ─────────────────────────────────────
install_singbox() {
    echo "正在安装 sing-box ..."
    info "使用官方安装脚本安装最新预发布版 (--beta)"
    curl -fsSL "$SINGBOX_INSTALL_URL" | sh -s -- --beta || die "sing-box 官方安装器执行失败"
    local bin
    bin=$(resolve_singbox_binary) || die "安装后未找到 sing-box（期望 $SINGBOX_BINARY）"
    mkdir -p "$SINGBOX_CONFIG_DIR"
    ok "sing-box 预发布版安装完成: $("$bin" version 2>/dev/null | head -1)"
}

# 为 hy2/tuic 生成自签 TLS 证书（直连 UDP 协议必需）
gen_self_signed_cert() {
    local domain="$1" days="${2:-3650}"
    mkdir -p "$SINGBOX_CONFIG_DIR"
    local key="$SINGBOX_CONFIG_DIR/server.key"
    local crt="$SINGBOX_CONFIG_DIR/server.crt"

    # 已有有效证书则复用
    if [[ -f "$key" && -f "$crt" ]]; then
        if openssl x509 -in "$crt" -noout -checkend 86400 &>/dev/null; then
            local cn
            cn=$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed -n 's/.*CN[[:space:]]*=[[:space:]]*//p' | head -1)
            if [[ -z "$domain" || "$cn" == "$domain" || "$domain" =~ ^[0-9.]+$ ]]; then
                info "复用已有自签证书: $crt"
                fix_service_cert_permissions "$SINGBOX_CONFIG_DIR" "$key" "$crt" "singbox"
                return 0
            fi
        fi
    fi

    local cn="${domain:-localhost}"
    [[ "$cn" =~ ^[0-9.]+$ ]] && cn="localhost"
    info "正在生成自签 TLS 证书 (CN=$cn)..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$key" -out "$crt" -days "$days" -nodes \
        -subj "/CN=${cn}" \
        -addext "subjectAltName=DNS:${cn},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null || \
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$key" -out "$crt" -days "$days" -nodes \
        -subj "/CN=${cn}" 2>/dev/null || die "自签证书生成失败"

    chmod 640 "$key" 2>/dev/null || chmod 600 "$key"
    chmod 644 "$crt"
    fix_service_cert_permissions "$SINGBOX_CONFIG_DIR" "$key" "$crt" "singbox"
    ok "自签证书已生成: $crt"
}

# 生成随机密码（hy2 password / tuic password / obfs）
gen_password() {
    local len="${1:-16}"
    openssl rand -base64 32 2>/dev/null | tr -d '/+=' | head -c "$len"
}
# ── xray 配置生成 ─────────────────────────────────────
gen_xray_config() {
    local route_json="$1" uid="$2"
    local protocol; protocol=$(echo "$route_json" | jq -r '.protocol // "vless"')
    local port; port=$(echo "$route_json" | jq -r '.listen_port')
    local path; path=$(echo "$route_json" | jq -r '.path')
    local transport; transport=$(echo "$route_json" | jq -r '.transport // "websocket"')
    local domain; domain=$(echo "$route_json" | jq -r '.domain // ""')
    local tls_enabled; tls_enabled=$(echo "$route_json" | jq -r '.tls // false')

    if [[ "$protocol" == "reality" ]]; then
        local reality_target reality_server_name reality_private_key reality_short_id reality_path
        reality_target=$(echo "$route_json" | jq -r '.reality_target')
        reality_server_name=$(echo "$route_json" | jq -r '.reality_server_name')
        reality_private_key=$(echo "$route_json" | jq -r '.reality_private_key')
        reality_short_id=$(echo "$route_json" | jq -r '.reality_short_id')
        reality_path=$(echo "$route_json" | jq -r '.path // "/reality"')
        jq -n --arg uid "$uid" --arg port "$port" --arg target "$reality_target" \
            --arg sni "$reality_server_name" --arg private_key "$reality_private_key" \
            --arg short_id "$reality_short_id" --arg path "$reality_path" '{
            log:{loglevel:"warning"},
            inbounds:[{
                tag:"in-vless-reality", listen:"0.0.0.0", port:($port|tonumber), protocol:"vless",
                settings:{clients:[{id:$uid,flow:""}],decryption:"none"},
                streamSettings:{network:"xhttp",xhttpSettings:{path:$path},security:"reality",
                    realitySettings:{target:$target,serverNames:[$sni],privateKey:$private_key,shortIds:[$short_id]}},
                sniffing:{enabled:true,destOverride:["http","tls","quic"]}
            }],
            outbounds:[{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}],
            routing:{domainStrategy:"IPIfNonMatch",rules:[{type:"field",outboundTag:"block",protocol:["bittorrent"]}]}
        }'
        return
    fi

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

# ── sing-box 配置生成（hy2 / tuic）────────────────────
gen_singbox_config() {
    local route_json="$1" uid="$2"
    local protocol port password domain sni
    protocol=$(echo "$route_json" | jq -r '.protocol // "hy2"')
    port=$(echo "$route_json" | jq -r '.listen_port')
    password=$(echo "$route_json" | jq -r '.password // empty')
    domain=$(echo "$route_json" | jq -r '.domain // ""')
    sni=$(echo "$route_json" | jq -r '.sni // empty')
    [[ -n "$sni" ]] || sni="$domain"
    [[ -n "$sni" && ! "$sni" =~ ^[0-9.]+$ ]] || sni="localhost"

    local tls_json
    tls_json=$(jq -n --arg sni "$sni" '{
        enabled: true,
        server_name: $sni,
        certificate_path: "/etc/sing-box/server.crt",
        key_path: "/etc/sing-box/server.key",
        alpn: ["h3"]
    }')

    local inbound
    case "$protocol" in
        hy2|hysteria2)
            local obfs_type obfs_password
            obfs_type=$(echo "$route_json" | jq -r '.obfs_type // ""')
            obfs_password=$(echo "$route_json" | jq -r '.obfs_password // ""')
            [[ -n "$password" ]] || password=$(gen_password 20)

            if [[ -n "$obfs_type" && "$obfs_type" != "none" && -n "$obfs_password" ]]; then
                inbound=$(jq -n --argjson port "$((port))" --arg pwd "$password" \
                    --arg ot "$obfs_type" --arg op "$obfs_password" --argjson tls "$tls_json" '{
                    type: "hysteria2",
                    tag: "hy2-in",
                    listen: "::",
                    listen_port: $port,
                    users: [{name: "user", password: $pwd}],
                    ignore_client_bandwidth: true,
                    obfs: {type: $ot, password: $op},
                    tls: $tls,
                    masquerade: "https://www.cloudflare.com"
                }')
            else
                inbound=$(jq -n --argjson port "$((port))" --arg pwd "$password" --argjson tls "$tls_json" '{
                    type: "hysteria2",
                    tag: "hy2-in",
                    listen: "::",
                    listen_port: $port,
                    users: [{name: "user", password: $pwd}],
                    ignore_client_bandwidth: true,
                    tls: $tls,
                    masquerade: "https://www.cloudflare.com"
                }')
            fi
            ;;
        tuic)
            local cong
            cong=$(echo "$route_json" | jq -r '.congestion_control // "bbr"')
            [[ -n "$password" ]] || password=$(gen_password 16)
            [[ -n "$uid" ]] || uid=$(gen_uuid)
            inbound=$(jq -n --argjson port "$((port))" --arg uuid "$uid" --arg pwd "$password" \
                --arg cc "$cong" --argjson tls "$tls_json" '{
                type: "tuic",
                tag: "tuic-in",
                listen: "::",
                listen_port: $port,
                users: [{name: "user", uuid: $uuid, password: $pwd}],
                congestion_control: $cc,
                zero_rtt_handshake: false,
                tls: $tls
            }')
            ;;
        *)
            echo "sing-box 不支持的协议: $protocol" >&2
            return 1
            ;;
    esac

    jq -n --argjson inbound "$inbound" '{
        log: {level: "warn", timestamp: true},
        inbounds: [$inbound],
        outbounds: [
            {type: "direct", tag: "direct"},
            {type: "block", tag: "block"}
        ],
        route: {
            rules: [
                {protocol: "bittorrent", outbound: "block"}
            ],
            final: "direct",
            auto_detect_interface: true
        }
    }'
}

write_singbox_config() {
    mkdir -p "$SINGBOX_CONFIG_DIR"
    echo "$1" > "$SINGBOX_CONFIG_PATH"
    chmod 644 "$SINGBOX_CONFIG_PATH"
    # 校验配置
    local bin
    if bin=$(resolve_singbox_binary); then
        if ! "$bin" check -c "$SINGBOX_CONFIG_PATH" 2>/tmp/singbox-check.err; then
            warn "sing-box 配置校验警告:"
            cat /tmp/singbox-check.err 2>/dev/null || true
        fi
        rm -f /tmp/singbox-check.err
    fi
    ok "sing-box 配置已写入 $SINGBOX_CONFIG_PATH"
}

write_proxy_config() {
    local kernel="${2:-$ACTIVE_KERNEL}"
    case "$kernel" in
        singbox|sing-box) write_singbox_config "$1" ;;
        *)                write_xray_config "$1" ;;
    esac
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

build_reality_link() {
    local uid="$1" address="$2" port="$3" server_name="$4" public_key="$5" short_id="$6" path="${7:-/reality}" spider_x="${8:-}"
    [[ -n "$spider_x" ]] || spider_x="$(openssl rand -hex 12)"
    [[ "$spider_x" == /* ]] || spider_x="/${spider_x}"
    echo "vless://${uid}@${address}:${port}?encryption=none&security=reality&sni=$(urlencode "$server_name")&fp=chrome&pbk=${public_key}&sid=${short_id}&spx=$(urlencode "$spider_x")&type=xhttp&path=$(urlencode "$path")&mode=auto#Reality-${address}"
}

# Hysteria2 分享链接
# hy2://password@host:port?sni=...&insecure=1&obfs=salamander&obfs-password=...#name
build_hy2_link() {
    local password="$1" address="$2" port="$3" sni="$4" insecure="${5:-1}" obfs_type="${6:-}" obfs_password="${7:-}"
    local name="HY2-${address}"
    local qs="sni=$(urlencode "$sni")&insecure=${insecure}"
    if [[ -n "$obfs_type" && "$obfs_type" != "none" && -n "$obfs_password" ]]; then
        qs+="&obfs=$(urlencode "$obfs_type")&obfs-password=$(urlencode "$obfs_password")"
    fi
    echo "hy2://$(urlencode "$password")@${address}:${port}?${qs}#${name}"
}

# TUIC v5 分享链接
# tuic://uuid:password@host:port?sni=...&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#name
build_tuic_link() {
    local uuid="$1" password="$2" address="$3" port="$4" sni="$5" cong="${6:-bbr}" insecure="${7:-1}"
    local name="TUIC-${address}"
    local qs="sni=$(urlencode "$sni")&congestion_control=${cong}&udp_relay_mode=native&alpn=h3&allow_insecure=${insecure}"
    echo "tuic://${uuid}:$(urlencode "$password")@${address}:${port}?${qs}#${name}"
}

build_protocol_link() {
    local route_json="$1" uid="$2"
    local protocol address port sni password
    protocol=$(echo "$route_json" | jq -r '.protocol // "vless"')
    address=$(echo "$route_json" | jq -r '.domain // empty')
    port=$(echo "$route_json" | jq -r '.listen_port // .cf_port')
    sni=$(echo "$route_json" | jq -r '.sni // empty')
    password=$(echo "$route_json" | jq -r '.password // empty')
    [[ -n "$sni" ]] || sni="$address"
    [[ -n "$sni" && ! "$sni" =~ ^[0-9.]+$ ]] || sni="localhost"

    case "$protocol" in
        hy2|hysteria2)
            build_hy2_link "$password" "$address" "$port" "$sni" "1" \
                "$(echo "$route_json" | jq -r '.obfs_type // ""')" \
                "$(echo "$route_json" | jq -r '.obfs_password // ""')"
            ;;
        tuic)
            build_tuic_link "$uid" "$password" "$address" "$port" "$sni" \
                "$(echo "$route_json" | jq -r '.congestion_control // "bbr"')" "1"
            ;;
        reality)
            build_reality_link "$uid" "$address" "$port" \
                "$(echo "$route_json" | jq -r '.reality_server_name')" \
                "$(echo "$route_json" | jq -r '.reality_public_key')" \
                "$(echo "$route_json" | jq -r '.reality_short_id')" \
                "$(echo "$route_json" | jq -r '.path // "/reality"')"
            ;;
        *)
            build_link "$uid" "$address" \
                "$(echo "$route_json" | jq -r '.path')" \
                "$(echo "$route_json" | jq -r '.transport // "websocket"')" \
                "$(echo "$route_json" | jq -r '.cf_port')" \
                "$(echo "$route_json" | jq -r '.tls // false')"
            ;;
    esac
}
# 生成 CF 域名（不开代理）的 DNS A 记录
cf_upsert_dns_unproxied() {
    local zone_id="$1" domain="$2" ip="$3"
    local payload existing
    payload=$(jq -n --arg n "$domain" --arg c "$ip" '{type:"A",name:$n,content:$c,proxied:false,ttl:120}')
    existing=$(cf_get_dns "$zone_id" "$domain")
    if [[ -n "$existing" ]]; then
        local rid; rid=$(echo "$existing" | jq -r '.id')
        cf_call PUT "/zones/${zone_id}/dns_records/${rid}" "$payload" | jq -r '.result.id'
    else
        cf_call POST "/zones/${zone_id}/dns_records" "$payload" | jq -r '.result.id'
    fi
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
    local domain="$1" uid="$2" link="$3" sub_link="${4:-}" protocol="${5:-}"
    {
        echo "域名: $domain"
        [[ -n "$uid" ]] && echo "UUID: $uid"
        case "$protocol" in
            hy2|hysteria2) echo "HY2  $link" ;;
            tuic)          echo "TUIC $link" ;;
            reality)       echo "VLESS $link" ;;
            *)             echo "VLESS $link" ;;
        esac
        # Reality / hy2 / tuic 直连不走 CDN，不强制生成订阅转换
        [[ -n "$sub_link" ]] && echo "订阅 $sub_link"
    } > "$LAST_LINKS_PATH"
    chmod 600 "$LAST_LINKS_PATH"
}

print_link() {
    echo -e "  \033[1;36m订阅\033[0m  \033[1;37m$1\033[0m"
}

print_vless() {
    echo -e "  \033[1;35mVLESS\033[0m \033[1;37m$1\033[0m"
}

print_share_link() {
    local protocol="$1" link="$2"
    case "$protocol" in
        hy2|hysteria2) echo -e "  \033[1;35mHY2\033[0m   \033[1;37m$link\033[0m" ;;
        tuic)          echo -e "  \033[1;35mTUIC\033[0m  \033[1;37m$link\033[0m" ;;
        *)             print_vless "$link" ;;
    esac
}

protocol_label() {
    case "${1:-}" in
        vless)           echo "CF VLESS" ;;
        reality)         echo "Reality 直连" ;;
        hy2|hysteria2)   echo "Hysteria2 (sing-box)" ;;
        tuic)            echo "TUIC (sing-box)" ;;
        *)               echo "${1:-未知}" ;;
    esac
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

prompt_protocol() {
    while true; do
        echo
        echo -e "  \033[1;32m 1\033[0m. CF VLESS          \033[2;37m(xray + Cloudflare CDN)\033[0m"
        echo -e "  \033[1;32m 2\033[0m. Reality 直连      \033[2;37m(xray + xhttp + Reality)\033[0m"
        echo -e "  \033[1;35m 3\033[0m. Hysteria2 直连    \033[2;37m(sing-box · UDP/QUIC)\033[0m"
        echo -e "  \033[1;35m 4\033[0m. TUIC 直连         \033[2;37m(sing-box · UDP/QUIC)\033[0m"
        echo
        read -rp "节点协议(1-4，留空=CF VLESS): " protocol_raw
        case "${protocol_raw:-1}" in
            1|vless|cf)              echo "vless"; return ;;
            2|reality)               echo "reality"; return ;;
            3|hy2|hysteria2|hysteria) echo "hy2"; return ;;
            4|tuic)                  echo "tuic"; return ;;
            *) echo "无效协议: $protocol_raw，请重新选择" ;;
        esac
    done
}

prompt_hy2_obfs() {
    read -rp "启用 salamander 混淆? (y/N，默认 N): " ans
    case "${ans,,}" in
        y|yes)
            local op
            op=$(gen_password 16)
            read -rp "混淆密码(留空=自动生成): " custom
            [[ -n "$custom" ]] && op="$custom"
            jq -n --arg t "salamander" --arg p "$op" '{obfs_type:$t,obfs_password:$p}'
            ;;
        *)
            jq -n '{obfs_type:"",obfs_password:""}'
            ;;
    esac
}

prompt_tuic_cc() {
    while true; do
        read -rp "拥塞控制(1=bbr, 2=cubic, 3=new_reno，留空=bbr): " raw
        case "${raw:-1}" in
            1|bbr)      echo "bbr"; return ;;
            2|cubic)    echo "cubic"; return ;;
            3|new_reno|newreno) echo "new_reno"; return ;;
            *) echo "无效选项: $raw" ;;
        esac
    done
}
gen_reality_keys() {
    local private_key public_key raw_output
    raw_output=$("$XRAY_BINARY" x25519 2>&1) || {
        warn "xray x25519 命令执行失败"
        return 1
    }
    # 兼容新旧版本；不依赖 IGNORECASE（mawk 不支持），用 tolower() 做大小写无关匹配
    private_key=$(echo "$raw_output" | awk '{
        line = tolower($0)
        if (line ~ /priv/ && line ~ /key/) {
            for (i=1; i<=NF; i++) {
                if (tolower($i) ~ /key/) {
                    gsub(/:$/, "", $i)
                    print $(i+1)
                    exit
                }
            }
        }
    }')
    public_key=$(echo "$raw_output" | awk '{
        line = tolower($0)
        if (line ~ /pub/ && line ~ /key/) {
            for (i=1; i<=NF; i++) {
                if (tolower($i) ~ /key/) {
                    gsub(/:$/, "", $i)
                    print $(i+1)
                    exit
                }
            }
        }
    }')
    if [[ -z "$private_key" || -z "$public_key" ]]; then
        warn "x25519 输出格式无法解析:"
        echo "$raw_output" | head -5
        return 1
    fi
    jq -n --arg private "$private_key" --arg public "$public_key" '{private:$private,public:$public}'
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

do_install_reality() {
    local address port target server_name short_id keys route_json config link state_json net_mode

    address=$(get_public_ip)
    net_mode=$(detect_nat)
    if [[ "$net_mode" == "nat" ]]; then
        warn "检测到 NAT/内网网卡（如 AWS EIP）：公网 IP 未绑定到本机网卡"
        info "请确认云厂商安全组/防火墙已放行 Reality 监听端口入站"
    fi
    local uid; uid=$(prompt_uuid)

    read -rp "Reality 监听端口 (回车=443): " port
    port="${port:-443}"
    while ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); do
        read -rp "无效端口，请重新输入 Reality 监听端口: " port
    done

    echo -e "  \033[2;37m提示: 避免使用 Microsoft/Google 等被 GFW 重点监控的域名作为伪装目标\033[0m"
    read -rp "Reality 伪装目标 (回车=www.cloudflare.com:443): " target
    target="${target:-www.cloudflare.com:443}"
    target="${target#http://}"; target="${target#https://}"; target="${target%%/*}"
    [[ "$target" == *:* ]] || target="${target}:443"
    server_name="${target%%:*}"
    read -rp "Reality SNI (回车=${server_name}): " sni_input
    server_name="${sni_input:-$server_name}"
    [[ "$server_name" =~ ^[A-Za-z0-9.-]+$ ]] || die "SNI 格式不正确"

    keys=$(gen_reality_keys) || die "Reality 密钥生成失败，请确认 xray 支持 x25519"
    short_id=$(openssl rand -hex 8) || die "Short ID 生成失败"
    local path_prefix; path_prefix=$(prompt_path_prefix "${uid:0:8}")
    local spider_x; spider_x="$(openssl rand -hex 12)"

    local pub_key; pub_key=$(echo "$keys" | jq -r '.public')
    local priv_key; priv_key=$(echo "$keys" | jq -r '.private')

    # ── 可选绑定 CF 域名（不开代理）──
    local cf_domain="" cf_zone_id="" cf_dns_record_id=""
    echo
    read -rp "绑定 CF 域名隐藏 IP? (Y/n，默认 N): " bind_cf
    if [[ "${bind_cf,,}" == "y" || "${bind_cf,,}" == "yes" ]]; then
        if ! load_cf_account; then
            echo "需要 CF 凭据以创建 DNS 记录"
            prompt_cf
        fi
        local selected_zone
        selected_zone=$(prompt_select_zone)
        cf_domain="${selected_zone%%|*}"
        cf_zone_id="${selected_zone##*|}"
        cf_dns_record_id=$(cf_upsert_dns_unproxied "$cf_zone_id" "$cf_domain" "$address")
        ok "DNS A 记录已创建: $cf_domain -> $address（不开代理）"
    fi

    local display_domain="${cf_domain:-$address}"
    route_json=$(jq -n --arg p "reality" --argjson lp "$((port))" --arg t "$target" \
        --arg s "$server_name" --arg pk "$priv_key" --arg pub "$pub_key" \
        --arg sid "$short_id" --arg pa "$path_prefix" --arg d "$display_domain" \
        --arg cf "$cf_domain" --arg zid "$cf_zone_id" \
        '{protocol:$p,domain:$d,listen_port:$lp,cf_port:$lp,path:$pa,transport:"xhttp",tls:false,
        reality_target:$t,reality_server_name:$s,reality_private_key:$pk,reality_public_key:$pub,reality_short_id:$sid,
        cf_domain:$cf,cf_zone_id:$zid}')

    echo
    header "═══════════════════════════════════"
    header "       Reality 直连配置预览"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m节点地址:\033[0m $display_domain"
    [[ -n "$cf_domain" ]] && echo -e "  \033[1;36m源站 IP:\033[0m  $address"
    echo -e "  \033[1;36m网络模式:\033[0m  $net_mode"
    echo -e "  \033[1;36mUUID:\033[0m      $uid"
    echo -e "  \033[1;36m监听端口:\033[0m  $port"
    echo -e "  \033[1;36m伪装目标:\033[0m  $target"
    echo -e "  \033[1;36mSNI:\033[0m       $server_name"
    echo -e "  \033[1;36mXHTTP 路径:\033[0m  $path_prefix"
    echo
    read -rp "确认部署 Reality 直连? (Y/n，默认 Y): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { echo "已取消"; return; }

    ACTIVE_KERNEL="xray"
    stop_other_kernel "xray"
    config=$(gen_xray_config "$route_json" "$uid")
    write_xray_config "$config"
    restart_xray

    link=$(build_reality_link "$uid" "$display_domain" "$port" "$server_name" \
        "$pub_key" "$short_id" "$path_prefix" "$spider_x")
    save_links_snapshot "$display_domain" "$uid" "$link" "" "reality"
    state_json=$(jq -n --arg d "$display_domain" --arg u "$uid" --arg mode "$net_mode" \
        --argjson route "$route_json" --arg link "$link" --arg k "xray" \
        '{domain:$d,uuid:$u,net_mode:$mode,kernel:$k,route:$route,link:$link}')
    save_state "$state_json"

    echo
    header "═══════════════════════════════════"
    ok "Reality 直连部署完成"
    if [[ "$net_mode" == "nat" ]]; then
        warn "NAT 环境请确认安全组已放行 TCP $port → 本机 $port"
    fi
    print_vless "$link"
    echo -e "  \033[2;37m已保存到 $LAST_LINKS_PATH\033[0m"
}

# ── Hysteria2 / TUIC 直连（sing-box）─────────────────
do_install_udp() {
    local protocol="$1"  # hy2 | tuic
    local address port password uid route_json config link state_json net_mode
    local sni display_domain cf_domain="" cf_zone_id=""
    local obfs_json obfs_type="" obfs_password="" cong="bbr"

    address=$(get_public_ip)
    net_mode=$(detect_nat)
    if [[ "$net_mode" == "nat" ]]; then
        warn "检测到 NAT/内网网卡（如 AWS EIP）：公网 IP 未绑定到本机网卡"
        info "请确认云厂商安全组/防火墙已放行 UDP 监听端口入站"
    fi

    ACTIVE_KERNEL="singbox"
    if ! resolve_singbox_binary &>/dev/null; then
        install_singbox
    else
        ok "sing-box 已安装: $(get_singbox_version || echo '?')"
    fi

    if [[ "$protocol" == "tuic" ]]; then
        uid=$(prompt_uuid)
        password=$(gen_password 16)
        read -rp "TUIC 密码(留空=自动生成): " custom_pwd
        [[ -n "$custom_pwd" ]] && password="$custom_pwd"
        cong=$(prompt_tuic_cc)
    else
        uid=""
        password=$(gen_password 20)
        read -rp "Hysteria2 密码(留空=自动生成): " custom_pwd
        [[ -n "$custom_pwd" ]] && password="$custom_pwd"
        obfs_json=$(prompt_hy2_obfs)
        obfs_type=$(echo "$obfs_json" | jq -r '.obfs_type // ""')
        obfs_password=$(echo "$obfs_json" | jq -r '.obfs_password // ""')
    fi

    read -rp "监听端口 (回车=443): " port
    port="${port:-443}"
    while ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); do
        read -rp "无效端口，请重新输入监听端口: " port
    done

    # 可选绑定 CF 域名（不开代理，仅 DNS）
    echo
    read -rp "绑定 CF 域名隐藏 IP? (y/N，默认 N): " bind_cf
    if [[ "${bind_cf,,}" == "y" || "${bind_cf,,}" == "yes" ]]; then
        if ! load_cf_account; then
            echo "需要 CF 凭据以创建 DNS 记录"
            prompt_cf
        fi
        local selected_zone
        selected_zone=$(prompt_select_zone)
        cf_domain="${selected_zone%%|*}"
        cf_zone_id="${selected_zone##*|}"
        cf_upsert_dns_unproxied "$cf_zone_id" "$cf_domain" "$address" >/dev/null
        ok "DNS A 记录已创建: $cf_domain -> $address（不开代理）"
    fi

    display_domain="${cf_domain:-$address}"
    sni="$display_domain"
    [[ "$sni" =~ ^[0-9.]+$ ]] && sni="localhost"
    read -rp "TLS SNI (回车=${sni}): " sni_input
    sni="${sni_input:-$sni}"

    route_json=$(jq -n \
        --arg p "$protocol" --argjson lp "$((port))" --arg d "$display_domain" \
        --arg sni "$sni" --arg pwd "$password" --arg cf "$cf_domain" --arg zid "$cf_zone_id" \
        --arg ot "$obfs_type" --arg op "$obfs_password" --arg cc "$cong" \
        '{
            protocol:$p, domain:$d, listen_port:$lp, cf_port:$lp,
            sni:$sni, password:$pwd,
            obfs_type:$ot, obfs_password:$op,
            congestion_control:$cc,
            cf_domain:$cf, cf_zone_id:$zid,
            transport:"udp", tls:true
        }')

    echo
    header "═══════════════════════════════════"
    header "    $(protocol_label "$protocol") 配置预览"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m内核:\033[0m      sing-box"
    echo -e "  \033[1;36m节点地址:\033[0m  $display_domain"
    [[ -n "$cf_domain" ]] && echo -e "  \033[1;36m源站 IP:\033[0m   $address"
    echo -e "  \033[1;36m网络模式:\033[0m  $net_mode"
    [[ "$protocol" == "tuic" ]] && echo -e "  \033[1;36mUUID:\033[0m      $uid"
    echo -e "  \033[1;36m密码:\033[0m      $password"
    echo -e "  \033[1;36m监听端口:\033[0m  UDP $port"
    echo -e "  \033[1;36mSNI:\033[0m       $sni"
    if [[ "$protocol" == "hy2" && -n "$obfs_type" ]]; then
        echo -e "  \033[1;36m混淆:\033[0m      $obfs_type / $obfs_password"
    fi
    if [[ "$protocol" == "tuic" ]]; then
        echo -e "  \033[1;36m拥塞控制:\033[0m  $cong"
    fi
    echo -e "  \033[2;37m证书: 自签 TLS（客户端需 insecure/allow_insecure）\033[0m"
    echo
    read -rp "确认部署 $(protocol_label "$protocol")? (Y/n，默认 Y): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { echo "已取消"; return; }

    gen_self_signed_cert "$sni"
    stop_other_kernel "singbox"
    config=$(gen_singbox_config "$route_json" "${uid:-}")
    write_singbox_config "$config"
    restart_singbox

    link=$(build_protocol_link "$route_json" "${uid:-}")
    save_links_snapshot "$display_domain" "${uid:-}" "$link" "" "$protocol"
    state_json=$(jq -n \
        --arg d "$display_domain" --arg u "${uid:-}" --arg mode "$net_mode" \
        --argjson route "$route_json" --arg link "$link" --arg k "singbox" \
        '{domain:$d,uuid:$u,net_mode:$mode,kernel:$k,route:$route,link:$link}')
    save_state "$state_json"
    ACTIVE_KERNEL="singbox"

    echo
    header "═══════════════════════════════════"
    ok "$(protocol_label "$protocol") 部署完成"
    if [[ "$net_mode" == "nat" ]]; then
        warn "NAT 环境请确认安全组已放行 UDP $port → 本机 $port"
    fi
    print_share_link "$protocol" "$link"
    echo -e "  \033[2;37m已保存到 $LAST_LINKS_PATH\033[0m"
    echo -e "  \033[2;37m提示: 客户端需开启 insecure / allowInsecure（自签证书）\033[0m"
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

    local net_mode
    net_mode=$(detect_nat)
    [[ "$net_mode" == "nat" ]] && info "检测到 NAT 环境（内网 IP）" || info "直连环境"

    local protocol
    protocol=$(prompt_protocol)

    if [[ "$protocol" == "reality" ]]; then
        [[ -f "$XRAY_BINARY" ]] && ok "xray-core 已安装" || install_xray
        ACTIVE_KERNEL="xray"
        do_install_reality
        return
    fi

    if is_udp_protocol "$protocol"; then
        do_install_udp "$protocol"
        return
    fi

    # CF VLESS → xray
    [[ -f "$XRAY_BINARY" ]] && ok "xray-core 已安装" || install_xray
    ACTIVE_KERNEL="xray"

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

    ACTIVE_KERNEL="xray"
    stop_other_kernel "xray"
    local config
    config=$(gen_xray_config "$route_json" "$uid")
    write_xray_config "$config"
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
    save_links_snapshot "$domain" "$uid" "$link" "$sub_link" "vless"

    local dns_existed="false"
    [[ "$dns_before" != "null" ]] && dns_existed="true"
    local state_json
    state_json=$(jq -n \
        --arg d "$domain" --arg z "$zone_id" --arg u "$uid" --arg mode "$net_mode" \
        --argjson route "$route_json" \
        --arg drid "$dns_record_id" --argjson dex "$dns_existed" --argjson drec "$dns_before" \
        --arg ssl "$ssl_before" --argjson orbk "$origin_rules_before" \
        --argjson secbk "$security_backup" --arg link "$link" --arg k "xray" \
        '{domain:$d,zone_id:$z,uuid:$u,net_mode:$mode,kernel:$k,route:$route,
          managed_dns_record_id:$drid,dns_backup:{existed:$dex,record:$drec},
          ssl_backup:$ssl,origin_rules_backup:$orbk,security_backup:$secbk,link:$link}') || \
        die "部署状态保存失败，请检查 JSON 数据"
    save_state "$state_json"
    stop_other_kernel "xray"

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
    local state kernel protocol
    state=$(load_state 2>/dev/null || true)
    if [[ -z "$state" ]]; then
        local cleaned=false
        if systemctl is-active xray &>/dev/null || [[ -f "$XRAY_CONFIG_PATH" ]]; then
            systemctl stop xray &>/dev/null || true
            rm -f "$XRAY_CONFIG_PATH" "$XRAY_CONFIG_DIR/origin.key" "$XRAY_CONFIG_DIR/origin.crt"
            ok "xray 已停止，配置已清理"
            cleaned=true
        fi
        if systemctl is-active sing-box &>/dev/null || [[ -f "$SINGBOX_CONFIG_PATH" ]]; then
            systemctl stop sing-box &>/dev/null || true
            rm -f "$SINGBOX_CONFIG_PATH" "$SINGBOX_CONFIG_DIR/server.key" "$SINGBOX_CONFIG_DIR/server.crt"
            ok "sing-box 已停止，配置已清理"
            cleaned=true
        fi
        [[ "$cleaned" == "true" ]] && return
        echo "未检测到部署"
        return
    fi

    local domain; domain=$(echo "$state" | jq -r '.domain')
    protocol=$(echo "$state" | jq -r '.route.protocol // "vless"')
    kernel=$(echo "$state" | jq -r '.kernel // empty')
    [[ -n "$kernel" ]] || kernel=$(kernel_for_protocol "$protocol")
    local tls_was_enabled; tls_was_enabled=$(echo "$state" | jq -r '.route.tls // false')
    local has_zone; has_zone=$(echo "$state" | jq -r '.zone_id // empty')
    echo "正在卸载: $domain ($(protocol_label "$protocol") / $kernel)"

    case "$kernel" in
        singbox|sing-box)
            svc_stop "singbox"
            rm -f "$SINGBOX_CONFIG_PATH" "$SINGBOX_CONFIG_DIR/server.key" "$SINGBOX_CONFIG_DIR/server.crt"
            ok "sing-box 已停止"
            ;;
        *)
            svc_stop "xray"
            rm -f "$XRAY_CONFIG_PATH"
            ok "xray 已停止"
            ;;
    esac

    if load_cf_account; then
        # 仅 CF 代理模式需要吊销源证书；直连 hy2/tuic/reality 自签或 Reality 无 CF 源证书
        if [[ "$protocol" == "vless" && "$tls_was_enabled" == "true" ]]; then
            revoke_origin_cert "$domain"
        fi
        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // .route.cf_zone_id // ""')
        if [[ -n "$has_zone" ]]; then
            _restore_cf_config "$state" "$zone_id"
        fi
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
    local state kernel protocol
    state=$(load_state 2>/dev/null || true)
    [[ -z "$state" ]] && return 0

    local domain; domain=$(echo "$state" | jq -r '.domain')
    protocol=$(echo "$state" | jq -r '.route.protocol // "vless"')
    kernel=$(echo "$state" | jq -r '.kernel // empty')
    [[ -n "$kernel" ]] || kernel=$(kernel_for_protocol "$protocol")
    local tls_was_enabled; tls_was_enabled=$(echo "$state" | jq -r '.route.tls // false')
    local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // ""')

    if load_cf_account && [[ -n "$zone_id" ]]; then
        if [[ "$protocol" == "vless" && "$tls_was_enabled" == "true" ]]; then
            revoke_origin_cert "$domain"
        fi
        _restore_cf_config "$state" "$zone_id"
    fi

    svc_stop "xray" 2>/dev/null || true
    svc_stop "singbox" 2>/dev/null || true
    rm -f "$XRAY_CONFIG_PATH" "$XRAY_CONFIG_DIR/origin.key" "$XRAY_CONFIG_DIR/origin.crt"
    rm -f "$SINGBOX_CONFIG_PATH" "$SINGBOX_CONFIG_DIR/server.key" "$SINGBOX_CONFIG_DIR/server.crt"
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
    echo -e "  \033[2;37m- 删除 xray / sing-box 核心程序\033[0m"
    echo -e "  \033[2;37m- 删除快捷命令 /usr/local/bin/x\033[0m"
    echo
    read -rp "$(echo -e "\033[1;33m确认完全卸载? \033[0m\033[37m(y/N): \033[0m")" confirm
    [[ "${confirm,,}" == "y" || "${confirm,,}" == "yes" ]] || { echo "已取消"; return; }

    do_clean_for_reinstall

    # 删除 xray
    systemctl stop xray &>/dev/null || true
    systemctl disable xray &>/dev/null || true
    rm -f "$XRAY_BINARY"
    rm -rf "/usr/local/share/xray" "$XRAY_CONFIG_DIR"
    rm -f "/etc/systemd/system/xray.service"
    rm -rf "/etc/systemd/system/xray.service.d"

    # 删除 sing-box（尽量用包管理器，失败则手动清理）
    systemctl stop sing-box &>/dev/null || true
    systemctl disable sing-box &>/dev/null || true
    if command -v dpkg &>/dev/null && dpkg -l sing-box &>/dev/null 2>&1; then
        dpkg -r sing-box &>/dev/null || true
    elif command -v rpm &>/dev/null && rpm -q sing-box &>/dev/null 2>&1; then
        rpm -e sing-box &>/dev/null || true
    else
        local sb
        sb=$(resolve_singbox_binary 2>/dev/null || true)
        [[ -n "$sb" ]] && rm -f "$sb"
    fi
    rm -rf "$SINGBOX_CONFIG_DIR"
    rm -rf "/etc/systemd/system/sing-box.service.d"
    systemctl daemon-reload &>/dev/null

    rm -f "$CF_ACCOUNT_PATH" "/usr/local/bin/x"
    ok "CF 凭证已删除"
    ok "快捷命令已删除"
    ok "xray / sing-box 核心已卸载"
    ok "完全卸载完成"
}

# ── 3. 查看订阅 ──────────────────────────────────────
do_show() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local protocol kernel
    protocol=$(echo "$state" | jq -r '.route.protocol // "vless"')
    kernel=$(echo "$state" | jq -r '.kernel // empty')
    [[ -n "$kernel" ]] || kernel=$(kernel_for_protocol "$protocol")
    echo
    header "═══════════════════════"
    header "      订阅信息"
    header "═══════════════════════"
    echo
    echo -e "  \033[1;36m协议:\033[0m $(protocol_label "$protocol")"
    echo -e "  \033[1;36m内核:\033[0m $kernel"
    if [[ "$protocol" == "reality" ]] || is_udp_protocol "$protocol"; then
        local cf_domain; cf_domain=$(echo "$state" | jq -r '.route.cf_domain // ""')
        echo -e "  \033[1;36m节点地址:\033[0m $(echo "$state" | jq -r '.domain')"
        [[ -n "$cf_domain" ]] && echo -e "  \033[1;36m绑定域名:\033[0m $cf_domain"
    else
        echo -e "  \033[1;36m域名:\033[0m $(echo "$state" | jq -r '.domain')"
    fi
    local uuid; uuid=$(echo "$state" | jq -r '.uuid // empty')
    [[ -n "$uuid" ]] && echo -e "  \033[1;36mUUID:\033[0m $uuid"
    if is_udp_protocol "$protocol"; then
        echo -e "  \033[1;36m密码:\033[0m $(echo "$state" | jq -r '.route.password // ""')"
    fi
    print_share_link "$protocol" "$(echo "$state" | jq -r '.link')"
    if [[ "$protocol" == "vless" ]]; then
        print_link "$(build_sub_link "$(echo "$state" | jq -r '.link')")"
    fi
    echo
}
# ── 4. 修改配置 ──────────────────────────────────────
# hy2 / tuic 修改
do_modify_udp() {
    local state="$1" protocol="$2"
    local domain uid route_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    uid=$(echo "$state" | jq -r '.uuid // empty')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')
    ACTIVE_KERNEL="singbox"

    echo
    header "═══════════════════════════════════"
    header "  修改 $(protocol_label "$protocol") ($net_mode)"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m节点地址:\033[0m $domain"
    [[ -n "$uid" ]] && echo -e "  \033[1;36mUUID:\033[0m     $uid"
    echo -e "  \033[1;36m密码:\033[0m     $(echo "$route_json" | jq -r '.password // ""')"
    echo -e "  \033[1;36m端口:\033[0m     UDP $(echo "$route_json" | jq -r '.listen_port')"
    echo -e "  \033[1;36mSNI:\033[0m      $(echo "$route_json" | jq -r '.sni // ""')"
    if [[ "$protocol" == "hy2" ]]; then
        local ot; ot=$(echo "$route_json" | jq -r '.obfs_type // ""')
        [[ -n "$ot" ]] && echo -e "  \033[1;36m混淆:\033[0m     $ot / $(echo "$route_json" | jq -r '.obfs_password // ""')"
    fi
    if [[ "$protocol" == "tuic" ]]; then
        echo -e "  \033[1;36m拥塞控制:\033[0m $(echo "$route_json" | jq -r '.congestion_control // "bbr"')"
    fi
    echo
    header "───────────────────────────────────"
    echo -e "  \033[1;32m 1\033[0m. 修改密码"
    if [[ "$protocol" == "tuic" ]]; then
        echo -e "  \033[1;33m 2\033[0m. 修改 UUID"
        echo -e "  \033[1;34m 3\033[0m. 修改端口"
        echo -e "  \033[1;35m 4\033[0m. 修改 SNI"
        echo -e "  \033[1;36m 5\033[0m. 修改拥塞控制"
        echo -e "  \033[1;36m 6\033[0m. 绑定/更换 CF 域名"
        echo -e "  \033[1;31m 7\033[0m. 取消 CF 域名绑定"
        echo -e "  \033[1;37m 8\033[0m. 全部修改"
    else
        echo -e "  \033[1;33m 2\033[0m. 修改端口"
        echo -e "  \033[1;34m 3\033[0m. 修改 SNI"
        echo -e "  \033[1;35m 4\033[0m. 修改混淆"
        echo -e "  \033[1;36m 5\033[0m. 绑定/更换 CF 域名"
        echo -e "  \033[1;31m 6\033[0m. 取消 CF 域名绑定"
        echo -e "  \033[1;37m 7\033[0m. 全部修改"
    fi
    echo -e "  \033[1;31m 0\033[0m. 返回"
    echo
    read -rp "$(echo -e "\033[1;33m请选择: \033[0m")" mc
    [[ "$mc" == "0" || -z "$mc" ]] && return

    local new_uid="$uid" new_route="$route_json" changed=false
    local all_choice; all_choice=$([[ "$protocol" == "tuic" ]] && echo 8 || echo 7)

    # 密码
    if [[ "$mc" == "1" || "$mc" == "$all_choice" ]]; then
        local np; np=$(gen_password 16)
        read -rp "新密码(留空=自动生成): " custom
        [[ -n "$custom" ]] && np="$custom"
        new_route=$(echo "$new_route" | jq --arg p "$np" '.password=$p')
        changed=true; ok "密码: $np"
    fi

    # TUIC UUID
    if [[ "$protocol" == "tuic" ]] && [[ "$mc" == "2" || "$mc" == "$all_choice" ]]; then
        while true; do
            read -rp "新 UUID(留空=重新生成): " iu
            if [[ -n "$iu" ]]; then
                if [[ "$iu" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                    new_uid="${iu,,}"; break
                fi
                echo "UUID 格式不正确"
            else
                new_uid=$(gen_uuid); break
            fi
        done
        changed=true; ok "UUID: $new_uid"
    fi

    # 端口
    local port_choice=2
    [[ "$protocol" == "tuic" ]] && port_choice=3
    if [[ "$mc" == "$port_choice" || "$mc" == "$all_choice" ]]; then
        local p; p=$(echo "$new_route" | jq -r '.listen_port')
        read -rp "新端口(当前=$p): " np
        if [[ -n "$np" ]]; then
            [[ "$np" =~ ^[0-9]+$ ]] || { echo "无效端口"; return; }
            new_route=$(echo "$new_route" | jq --argjson p "$((np))" '.listen_port=$p|.cf_port=$p')
            changed=true; ok "端口: $np"
        fi
    fi

    # SNI
    local sni_choice=3
    [[ "$protocol" == "tuic" ]] && sni_choice=4
    if [[ "$mc" == "$sni_choice" || "$mc" == "$all_choice" ]]; then
        local cur_sni; cur_sni=$(echo "$new_route" | jq -r '.sni // "localhost"')
        read -rp "新 SNI(当前=$cur_sni，留空=不改): " ns
        if [[ -n "$ns" ]]; then
            new_route=$(echo "$new_route" | jq --arg s "$ns" '.sni=$s')
            changed=true; ok "SNI: $ns"
            gen_self_signed_cert "$ns"
        fi
    fi

    # hy2 混淆
    if [[ "$protocol" == "hy2" ]] && [[ "$mc" == "4" || "$mc" == "$all_choice" ]]; then
        local oj
        oj=$(prompt_hy2_obfs)
        new_route=$(echo "$new_route" | jq --argjson o "$oj" \
            '.obfs_type=$o.obfs_type|.obfs_password=$o.obfs_password')
        changed=true; ok "混淆已更新"
    fi

    # tuic 拥塞控制
    if [[ "$protocol" == "tuic" ]] && [[ "$mc" == "5" || "$mc" == "$all_choice" ]]; then
        local cc; cc=$(prompt_tuic_cc)
        new_route=$(echo "$new_route" | jq --arg c "$cc" '.congestion_control=$c')
        changed=true; ok "拥塞控制: $cc"
    fi

    # 绑定 CF 域名
    local bind_choice=5
    [[ "$protocol" == "tuic" ]] && bind_choice=6
    if [[ "$mc" == "$bind_choice" || "$mc" == "$all_choice" ]]; then
        if ! load_cf_account; then echo "需要 CF 凭据"; prompt_cf; fi
        local selected_zone zone_domain new_zone_id raw_ip
        selected_zone=$(prompt_select_zone)
        zone_domain="${selected_zone%%|*}"; new_zone_id="${selected_zone##*|}"
        raw_ip=$(get_public_ip)
        cf_upsert_dns_unproxied "$new_zone_id" "$zone_domain" "$raw_ip" >/dev/null
        ok "DNS A 记录: $zone_domain -> $raw_ip（不开代理）"
        new_route=$(echo "$new_route" | jq --arg d "$zone_domain" --arg cf "$zone_domain" --arg zid "$new_zone_id" \
            '.domain=$d|.cf_domain=$cf|.cf_zone_id=$zid')
        changed=true
    fi

    # 取消 CF 域名
    local unbind_choice=6
    [[ "$protocol" == "tuic" ]] && unbind_choice=7
    if [[ "$mc" == "$unbind_choice" ]]; then
        local raw_ip; raw_ip=$(get_public_ip)
        new_route=$(echo "$new_route" | jq --arg d "$raw_ip" '.domain=$d|.cf_domain=""|.cf_zone_id=""')
        changed=true; ok "已取消绑定，恢复 IP: $raw_ip"
    fi

    [[ "$changed" == "true" ]] || { echo "无修改"; return; }

    write_singbox_config "$(gen_singbox_config "$new_route" "$new_uid")"
    restart_singbox

    local new_domain link
    new_domain=$(echo "$new_route" | jq -r '.domain')
    link=$(build_protocol_link "$new_route" "$new_uid")
    save_links_snapshot "$new_domain" "$new_uid" "$link" "" "$protocol"
    save_state "$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_route" --arg l "$link" --arg k "singbox" \
        '.uuid=$u|.route=$r|.link=$l|.kernel=$k')"
    echo; ok "配置已更新"; print_share_link "$protocol" "$link"
}

do_modify() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local domain uid route_json net_mode protocol
    domain=$(echo "$state" | jq -r '.domain')
    uid=$(echo "$state" | jq -r '.uuid')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')
    protocol=$(echo "$route_json" | jq -r '.protocol // "vless"')

    if is_udp_protocol "$protocol"; then
        do_modify_udp "$state" "$protocol"
        return
    fi

    echo
    header "═══════════════════════════════════"
    header "    修改配置 ($net_mode)"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m节点地址:\033[0m $domain  \033[1;36mUUID:\033[0m $uid"
    if [[ "$protocol" == "reality" ]]; then
        local cf_domain; cf_domain=$(echo "$route_json" | jq -r '.cf_domain // ""')
        echo -e "  \033[1;36m协议:\033[0m    Reality  \033[1;36mSNI:\033[0m $(echo "$route_json" | jq -r '.reality_server_name')"
        echo -e "  \033[1;36m伪装目标:\033[0m  $(echo "$route_json" | jq -r '.reality_target')"
        [[ -n "$cf_domain" ]] && echo -e "  \033[1;36m绑定域名:\033[0m $cf_domain"
    else
        echo -e "  \033[1;36m传输协议:\033[0m $(echo "$route_json" | jq -r '.transport // "websocket"')"
        echo -e "  \033[1;36mCF→VPS加密:\033[0m $(echo "$route_json" | jq -r '.tls // false')"
    fi
    echo -e "  \033[1;36m端口:\033[0m    $(echo "$route_json" | jq -r '.listen_port')"
    echo -e "  \033[1;36m路径:\033[0m  $(echo "$route_json" | jq -r '.path // "/reality"')"
    echo
    header "───────────────────────────────────"
    echo -e "  \033[1;32m 1\033[0m. 修改 UUID"
    echo -e "  \033[1;33m 2\033[0m. 修改端口"
    echo -e "  \033[1;34m 3\033[0m. 修改路径"
    if [[ "$protocol" == "reality" ]]; then
        echo -e "  \033[1;35m 4\033[0m. 修改 Reality 伪装目标/SNI"
        echo -e "  \033[1;36m 5\033[0m. 绑定/更换 CF 域名（不开代理）"
        echo -e "  \033[1;31m 6\033[0m. 取消 CF 域名绑定"
        echo -e "  \033[1;37m 7\033[0m. 重新生成 Reality 密钥"
        echo -e "  \033[1;38m 8\033[0m. 全部修改"
    else
        echo -e "  \033[1;35m 4\033[0m. 修改传输协议"
        echo -e "  \033[1;36m 5\033[0m. 切换 CF→VPS 加密"
        echo -e "  \033[1;37m 6\033[0m. 全部修改"
    fi
    echo -e "  \033[1;31m 0\033[0m. 返回"
    echo
    read -rp "$(echo -e "\033[1;33m请选择 [0-8]: \033[0m")" mc

	    local new_uid="$uid" new_route="$route_json" changed=false
	    local max_choice=8
	    [[ "$protocol" != "reality" ]] && max_choice=6

	    [[ "$mc" =~ ^[0-8]$ ]] || { echo "无效选项"; return; }
	    [[ "$mc" == "0" ]] && return

    # ── 1. UUID ──
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

    # ── 2. 端口 ──
    if [[ "$mc" == "2" || "$mc" == "6" ]]; then
        local p; p=$(echo "$new_route" | jq -r '.listen_port')
        read -rp "新端口(当前=$p): " np
        if [[ -n "$np" ]]; then
            [[ "$np" =~ ^[0-9]+$ ]] || { echo "无效端口: $np"; return; }
            if [[ "$protocol" == "reality" ]]; then
                new_route=$(echo "$new_route" | jq --argjson p "$((np))" '.listen_port=$p|.cf_port=$p')
            else
                new_route=$(echo "$new_route" | jq --argjson p "$((np))" '.listen_port=$p|.cf_port=$p')
            fi
            changed=true; ok "端口已更新: $np"
        fi
    fi

    # ── 3. 路径 ──
    if [[ "$mc" == "3" || "$mc" == "6" ]]; then
        local cur_path; cur_path=$(echo "$new_route" | jq -r '.path // "/reality"')
        read -rp "新路径(当前=$cur_path，留空=不改): " np
        if [[ -n "$np" ]]; then
            [[ "$np" == /* ]] || np="/${np}"
            new_route=$(echo "$new_route" | jq --arg p "$np" '.path=$p')
            changed=true; ok "路径已更新"
        fi
    fi

    # ── Reality 专属选项 ──
    if [[ "$protocol" == "reality" ]]; then
        # ── 4. Reality 伪装目标/SNI ──
        if [[ "$mc" == "4" || "$mc" == "8" ]]; then
            local cur_target cur_sni
            cur_target=$(echo "$new_route" | jq -r '.reality_target')
            cur_sni=$(echo "$new_route" | jq -r '.reality_server_name')
            read -rp "伪装目标(当前=$cur_target，留空=不改): " new_target
            if [[ -n "$new_target" ]]; then
                new_target="${new_target#http://}"; new_target="${new_target#https://}"; new_target="${new_target%%/*}"
                [[ "$new_target" == *:* ]] || new_target="${new_target}:443"
                local new_sni="${new_target%%:*}"
                read -rp "SNI(当前=$cur_sni，留空=使用新伪装目标域名): " sni_input
                new_sni="${sni_input:-$new_sni}"
                new_route=$(echo "$new_route" | jq --arg t "$new_target" --arg s "$new_sni" \
                    '.reality_target=$t|.reality_server_name=$s')
                changed=true; ok "伪装目标: $new_target  SNI: $new_sni"
            fi
        fi

        # ── 5. 绑定/更换 CF 域名（不开代理）──
        if [[ "$mc" == "5" || "$mc" == "8" ]]; then
            local cur_cf_domain; cur_cf_domain=$(echo "$new_route" | jq -r '.cf_domain // ""')
            if [[ -n "$cur_cf_domain" ]]; then
                echo "当前绑定域名: $cur_cf_domain"
                read -rp "更换域名? (Y/n，默认 N): " change_yn
                if [[ "${change_yn,,}" == "y" || "${change_yn,,}" == "yes" ]]; then
                    if ! load_cf_account; then echo "需要 CF 凭据以创建 DNS 记录"; prompt_cf; fi
                    local selected_zone
                    selected_zone=$(prompt_select_zone)
                    local zone_domain="${selected_zone%%|*}"
                    local new_zone_id="${selected_zone##*|}"
                    local raw_ip; raw_ip=$(get_public_ip)
                    cf_upsert_dns_unproxied "$new_zone_id" "$zone_domain" "$raw_ip" >/dev/null
                    ok "DNS A 记录已创建: $zone_domain -> $raw_ip（不开代理）"
                    new_route=$(echo "$new_route" | jq --arg d "$zone_domain" --arg cf "$zone_domain" --arg zid "$new_zone_id" \
                        '.domain=$d|.cf_domain=$cf|.cf_zone_id=$zid')
                    changed=true; ok "更换域名: $zone_domain"
                fi
            else
                echo "当前未绑定域名"
                read -rp "绑定 CF 域名隐藏 IP? (Y/n，默认 N): " bind_yn
                if [[ "${bind_yn,,}" == "y" || "${bind_yn,,}" == "yes" ]]; then
                    if ! load_cf_account; then echo "需要 CF 凭据以创建 DNS 记录"; prompt_cf; fi
                    local selected_zone
                    selected_zone=$(prompt_select_zone)
                    local zone_domain="${selected_zone%%|*}"
                    local new_zone_id="${selected_zone##*|}"
                    local raw_ip; raw_ip=$(get_public_ip)
                    cf_upsert_dns_unproxied "$new_zone_id" "$zone_domain" "$raw_ip" >/dev/null
                    ok "DNS A 记录已创建: $zone_domain -> $raw_ip（不开代理）"
                    new_route=$(echo "$new_route" | jq --arg d "$zone_domain" --arg cf "$zone_domain" --arg zid "$new_zone_id" \
                        '.domain=$d|.cf_domain=$cf|.cf_zone_id=$zid')
                    changed=true; ok "绑定域名: $zone_domain"
                fi
            fi
        fi

        # ── 6. 取消 CF 域名绑定 ──
        if [[ "$mc" == "6" ]]; then
            local cur_cf_domain; cur_cf_domain=$(echo "$new_route" | jq -r '.cf_domain // ""')
            if [[ -n "$cur_cf_domain" ]]; then
                local raw_ip; raw_ip=$(get_public_ip)
                new_route=$(echo "$new_route" | jq --arg d "$raw_ip" '.domain=$d|.cf_domain=""|.cf_zone_id=""')
                changed=true; ok "已取消 CF 域名绑定，恢复为 IP: $raw_ip"
            else
                echo "当前未绑定 CF 域名，无需取消"
            fi
        fi

        # ── 7. 重新生成 Reality 密钥 ──
        if [[ "$mc" == "7" || "$mc" == "8" ]]; then
            local keys new_private_key new_public_key new_short_id
            keys=$(gen_reality_keys) || die "Reality 密钥生成失败"
            new_private_key=$(echo "$keys" | jq -r '.private')
            new_public_key=$(echo "$keys" | jq -r '.public')
            new_short_id=$(openssl rand -hex 8)
            new_route=$(echo "$new_route" | jq --arg pk "$new_private_key" --arg pub "$new_public_key" --arg sid "$new_short_id" \
                '.reality_private_key=$pk|.reality_public_key=$pub|.reality_short_id=$sid')
            changed=true; ok "Reality 密钥已重新生成"
        fi
    else
        # ── CF VLESS 选项 ──
        # ── 4. 传输协议 ──
        if [[ "$mc" == "4" || "$mc" == "6" ]]; then
            local cur_tr; cur_tr=$(echo "$new_route" | jq -r '.transport // "websocket"')
            echo "当前传输协议: $cur_tr"
            new_tr=$(prompt_transport)
            new_route=$(echo "$new_route" | jq --arg t "$new_tr" '.transport=$t')
            changed=true; ok "传输协议: $new_tr"
        fi

        # ── 5. CF→VPS 加密 ──
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
    fi

    [[ "$changed" == "true" ]] || { echo "无修改"; return; }

    # 处理 TLS 变更的实际操作（仅 CF VLESS 模式）
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

    if [[ "$protocol" != "reality" ]] && load_cf_account; then
        apply_origin_rule "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_route"
        ok "Origin Rule 已更新"
    fi

    local new_domain; new_domain=$(echo "$new_route" | jq -r '.domain')
    local link
    if [[ "$protocol" == "reality" ]]; then
        local _path _spider_x
        _path=$(echo "$new_route" | jq -r '.path // "/reality"')
        _spider_x="$(openssl rand -hex 12)"
        link=$(build_reality_link "$new_uid" "$new_domain" "$(echo "$new_route" | jq -r '.listen_port')" \
            "$(echo "$new_route" | jq -r '.reality_server_name')" \
            "$(echo "$new_route" | jq -r '.reality_public_key')" \
            "$(echo "$new_route" | jq -r '.reality_short_id')" \
            "$_path" "$_spider_x")
        save_links_snapshot "$new_domain" "$new_uid" "$link" "" "reality"
        save_state "$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_route" --arg l "$link" --arg k "xray" \
            '.uuid=$u|.route=$r|.link=$l|.kernel=$k')"
        echo; ok "配置已更新"; print_vless "$link"
    else
        link=$(build_link "$new_uid" "$new_domain" "$(echo "$new_route" | jq -r '.path')" "$(echo "$new_route" | jq -r '.transport // "websocket"')" "$(echo "$new_route" | jq -r '.cf_port')" "$(echo "$new_route" | jq -r '.tls')")
        local sub_link; sub_link=$(build_sub_link "$link")
        save_links_snapshot "$new_domain" "$new_uid" "$link" "$sub_link" "vless"
        save_state "$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_route" --arg l "$link" --arg k "xray" \
            '.uuid=$u|.route=$r|.link=$l|.kernel=$k')"
        echo; ok "配置已更新"; print_link "$sub_link"
    fi
}

# ── 5. 查看当前配置 ──────────────────────────────────
do_show_config() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local domain protocol kernel
    domain=$(echo "$state" | jq -r '.domain')
    protocol=$(echo "$state" | jq -r '.route.protocol // "vless"')
    kernel=$(echo "$state" | jq -r '.kernel // empty')
    [[ -n "$kernel" ]] || kernel=$(kernel_for_protocol "$protocol")
    ACTIVE_KERNEL="$kernel"

    echo
    header "═══════════════════════════════════"
    header "         当前配置信息"
    header "═══════════════════════════════════"
    echo
    echo -e "  \033[1;36m协议:\033[0m    $(protocol_label "$protocol")"
    echo -e "  \033[1;36m内核:\033[0m    $kernel"
    if [[ "$protocol" == "reality" ]] || is_udp_protocol "$protocol"; then
        local cf_domain; cf_domain=$(echo "$state" | jq -r '.route.cf_domain // ""')
        echo -e "  \033[1;36m节点地址:\033[0m $domain"
        [[ -n "$cf_domain" ]] && echo -e "  \033[1;36m绑定域名:\033[0m $cf_domain"
    else
        echo -e "  \033[1;36m域名:\033[0m    $domain"
    fi
    local uuid; uuid=$(echo "$state" | jq -r '.uuid // empty')
    [[ -n "$uuid" ]] && echo -e "  \033[1;36mUUID:\033[0m    $uuid"
    echo -e "  \033[1;36m模式:\033[0m    $(echo "$state" | jq -r '.net_mode // "direct"')"
    if is_udp_protocol "$protocol"; then
        echo -e "  \033[1;36m密码:\033[0m    $(echo "$state" | jq -r '.route.password // ""')"
        echo -e "  \033[1;36m端口:\033[0m    UDP $(echo "$state" | jq -r '.route.listen_port')"
        echo -e "  \033[1;36mSNI:\033[0m     $(echo "$state" | jq -r '.route.sni // ""')"
        if [[ "$protocol" == "hy2" ]]; then
            local ot; ot=$(echo "$state" | jq -r '.route.obfs_type // ""')
            [[ -n "$ot" ]] && echo -e "  \033[1;36m混淆:\033[0m    $ot / $(echo "$state" | jq -r '.route.obfs_password // ""')"
        fi
        if [[ "$protocol" == "tuic" ]]; then
            echo -e "  \033[1;36m拥塞控制:\033[0m $(echo "$state" | jq -r '.route.congestion_control // "bbr"')"
        fi
    else
        echo -e "  \033[1;36m传输协议:\033[0m $(echo "$state" | jq -r '.route.transport // "websocket"')"
        echo -e "  \033[1;36mCF→VPS加密:\033[0m $(echo "$state" | jq -r '.route.tls // false')"
        echo -e "  \033[1;36m端口:\033[0m    $(echo "$state" | jq -r '.route.listen_port')"
        if [[ "$protocol" == "reality" ]]; then
            echo -e "  \033[1;36mReality SNI:\033[0m $(echo "$state" | jq -r '.route.reality_server_name')"
            echo -e "  \033[1;36m伪装目标:\033[0m  $(echo "$state" | jq -r '.route.reality_target')"
        else
            echo -e "  \033[1;36mCF端口:\033[0m  $(echo "$state" | jq -r '.route.cf_port')"
        fi
        echo -e "  \033[1;36m路径:\033[0m    $(echo "$state" | jq -r '.route.path // "/reality"')"
    fi
    echo
    local unit; unit=$(svc_unit "$kernel")
    echo -ne "  \033[1;36m$unit:\033[0m    "
    svc_is_active "$kernel" && ok "运行中" || warn "未运行"
    echo
    header "───────────────────────────────────"
    print_share_link "$protocol" "$(echo "$state" | jq -r '.link')"
    if [[ "$protocol" == "vless" ]]; then
        print_link "$(build_sub_link "$(echo "$state" | jq -r '.link')")"
    fi
    echo
}
# ── 6. 更新外部端口（NAT 快捷操作）──────────────────
do_update_ports() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || { echo "未检测到部署"; return; }

    local domain route_json net_mode protocol
    domain=$(echo "$state" | jq -r '.domain')
    route_json=$(echo "$state" | jq '.route')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')
    protocol=$(echo "$route_json" | jq -r '.protocol // "vless"')

    if is_udp_protocol "$protocol" || [[ "$protocol" == "reality" ]]; then
        echo
        info "当前为 $(protocol_label "$protocol") 直连模式，无 CF Origin 外部端口映射"
        info "端口变更请使用 [4.修改配置]"
        return
    fi

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

    echo; ok "外部端口已更新"; print_link "$sub_link"
}

# ── 7. 更新内核（xray / sing-box）───────────────────
do_update_core() {
    refresh_active_kernel
    local kernel="$ACTIVE_KERNEL"
    local unit name current_ver latest_ver

    # 若当前部署是 sing-box，优先更新 sing-box；否则更新 xray
    # 同时提供切换选择
    echo
    echo -e "  \033[1;32m 1\033[0m. 更新 xray     \033[33m[${XRAY_UPDATE_STATUS:-检测中}]\033[0m"
    echo -e "  \033[1;35m 2\033[0m. 更新 sing-box \033[33m[${SINGBOX_UPDATE_STATUS:-检测中}]\033[0m"
    echo -e "  \033[1;37m 0\033[0m. 返回"
    echo
    local def=1
    [[ "$kernel" == "singbox" ]] && def=2
    read -rp "$(echo -e "\033[1;33m请选择 [默认 $def]: \033[0m")" choice
    choice="${choice:-$def}"

    case "$choice" in
        1)
            name="xray"; unit="xray"
            current_ver="$XRAY_UPDATE_CURRENT"
            latest_ver="$XRAY_UPDATE_LATEST"
            if [[ -z "$current_ver" ]]; then
                warn "当前 xray 未安装或无法获取版本"
                read -rp "是否安装最新预发布版? (Y/n): " confirm
                [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || return
                install_xray
                [[ -f "$XRAY_CONFIG_PATH" ]] && restart_xray
                XRAY_UPDATE_CURRENT=$(get_xray_version || true)
                XRAY_UPDATE_STATUS="已安装 v${XRAY_UPDATE_CURRENT:-未知}"
                return
            fi
            info "当前版本: $current_ver"
            [[ -n "$latest_ver" ]] || die "获取最新版本失败"
            info "最新预发布: $latest_ver"
            if [[ "$current_ver" == "$latest_ver" ]]; then
                ok "已是最新版本，无需更新"; return
            fi
            echo -e "  \033[1;33m发现新版本:\033[0m \033[31m$current_ver\033[0m → \033[32m$latest_ver\033[0m"
            read -rp "确认更新? (Y/n): " confirm
            [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { info "已取消"; return; }
            install_xray
            [[ -f "$XRAY_CONFIG_PATH" ]] && restart_xray
            XRAY_UPDATE_CURRENT=$(get_xray_version || true)
            XRAY_UPDATE_LATEST="$latest_ver"
            if [[ "$XRAY_UPDATE_CURRENT" == "$latest_ver" ]]; then
                XRAY_UPDATE_STATUS="已是最新 v${XRAY_UPDATE_CURRENT}"
                ok "xray 已更新至 $XRAY_UPDATE_CURRENT"
            else
                XRAY_UPDATE_STATUS="当前 v${XRAY_UPDATE_CURRENT:-未知}"
                warn "实际版本 ${XRAY_UPDATE_CURRENT:-未知}，目标 $latest_ver"
            fi
            ;;
        2)
            name="sing-box"; unit="sing-box"
            current_ver="$SINGBOX_UPDATE_CURRENT"
            latest_ver="$SINGBOX_UPDATE_LATEST"
            if [[ -z "$current_ver" ]]; then
                warn "当前 sing-box 未安装或无法获取版本"
                read -rp "是否安装最新预发布版? (Y/n): " confirm
                [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || return
                install_singbox
                [[ -f "$SINGBOX_CONFIG_PATH" ]] && restart_singbox
                SINGBOX_UPDATE_CURRENT=$(get_singbox_version || true)
                SINGBOX_UPDATE_STATUS="已安装 v${SINGBOX_UPDATE_CURRENT:-未知}"
                return
            fi
            info "当前版本: $current_ver"
            [[ -n "$latest_ver" ]] || die "获取最新版本失败"
            info "最新预发布: $latest_ver"
            if [[ "$current_ver" == "$latest_ver" ]]; then
                ok "已是最新版本，无需更新"; return
            fi
            echo -e "  \033[1;33m发现新版本:\033[0m \033[31m$current_ver\033[0m → \033[32m$latest_ver\033[0m"
            read -rp "确认更新? (Y/n): " confirm
            [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || { info "已取消"; return; }
            install_singbox
            [[ -f "$SINGBOX_CONFIG_PATH" ]] && restart_singbox
            SINGBOX_UPDATE_CURRENT=$(get_singbox_version || true)
            SINGBOX_UPDATE_LATEST="$latest_ver"
            if [[ "$SINGBOX_UPDATE_CURRENT" == "$latest_ver" ]]; then
                SINGBOX_UPDATE_STATUS="已是最新 v${SINGBOX_UPDATE_CURRENT}"
                ok "sing-box 已更新至 $SINGBOX_UPDATE_CURRENT"
            else
                SINGBOX_UPDATE_STATUS="当前 v${SINGBOX_UPDATE_CURRENT:-未知}"
                warn "实际版本 ${SINGBOX_UPDATE_CURRENT:-未知}，目标 $latest_ver"
            fi
            ;;
        0) return ;;
        *) echo "无效选项" ;;
    esac
}

# 兼容旧菜单名
do_update_xray() { do_update_core; }

# ── 8. 重启代理内核 ──────────────────────────────────
do_restart() {
    refresh_active_kernel
    local unit; unit=$(svc_unit)
    if ! svc_is_active; then
        echo "$unit 当前未运行，正在启动..."
    else
        echo "正在重启 $unit..."
    fi
    restart_proxy
}

# ── 9. 查看日志 ─────────────────────────────────────
do_logs() {
    refresh_active_kernel
    local unit; unit=$(svc_unit)
    echo
    header "═══════════════════════════════════"
    header "       $unit 运行日志"
    header "═══════════════════════════════════"
    echo
    journalctl -u "$unit" --no-pager -n 30 --output cat 2>/dev/null || echo "暂无日志"
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
    require_systemd
    install_deps
    need_cmd curl; need_cmd jq; need_cmd openssl
    ensure_shortcut
    check_xray_update
    check_singbox_update
    refresh_active_kernel

    while true; do
        local state current_domain="" net_mode="" transport="" port="" tls_status="" protocol="" kernel=""
        state=$(load_state 2>/dev/null || true)
        refresh_active_kernel
        if [[ -n "$state" ]]; then
            current_domain=$(echo "$state" | jq -r '.domain // ""')
            net_mode=$(echo "$state" | jq -r '.net_mode // ""')
            transport=$(echo "$state" | jq -r '.route.transport // ""')
            port=$(echo "$state" | jq -r '.route.listen_port // ""')
            protocol=$(echo "$state" | jq -r '.route.protocol // "vless"')
            kernel=$(echo "$state" | jq -r '.kernel // empty')
            [[ -n "$kernel" ]] || kernel=$(kernel_for_protocol "$protocol")
            local tls_val; tls_val=$(echo "$state" | jq -r '.route.tls // false')
            [[ "$tls_val" == "true" ]] && tls_status="TLS" || tls_status=""
            if is_udp_protocol "$protocol"; then
                transport="udp"
                tls_status="TLS"
            fi
        fi

        local bbr_status; bbr_status=$(get_bbr_status)
        local unit; unit=$(svc_unit)

        echo
        echo -e "  \033[1;36mxray-cf\033[0m  \033[2;37m(+sing-box)\033[0m"
        local info=""
        if [[ -n "$current_domain" ]]; then
            info+="\033[33m$current_domain\033[0m"
            [[ -n "$protocol" ]] && info+=" \033[35m$(protocol_label "$protocol")\033[0m"
            [[ -n "$transport" ]] && info+=" \033[37m$transport\033[0m"
            [[ -n "$port" ]] && info+=" \033[37m:$port\033[0m"
            [[ -n "$tls_status" ]] && info+=" \033[37m$tls_status\033[0m"
            [[ -n "$net_mode" ]] && info+=" \033[37m[$net_mode]\033[0m"
            info+="  \033[37m|\033[0m  "
        fi
        if svc_is_active; then
            info+="$unit \033[32m● 运行中\033[0m"
        else
            local has_bin=false
            case "$ACTIVE_KERNEL" in
                singbox)
                    resolve_singbox_binary &>/dev/null && has_bin=true
                    ;;
                *)
                    [[ -x "$XRAY_BINARY" ]] && has_bin=true
                    ;;
            esac
            if [[ "$has_bin" == "true" ]]; then
                info+="$unit \033[31m● 已关闭\033[0m"
            else
                info+="$unit \033[31m● 未安装\033[0m"
            fi
        fi
        echo -e "     $info"
        if svc_is_active; then
            local ver mem pid uptime
            if [[ "$ACTIVE_KERNEL" == "singbox" ]]; then
                ver=$(get_singbox_version || echo "?")
            else
                ver=$(get_xray_version || echo "?")
            fi
            mem=$(systemctl show "$unit" -p MemoryCurrent --value 2>/dev/null)
            mem=$(awk -v m="$mem" 'BEGIN{if (m+0==0) print "?"; else if (m>1048576) printf "%.1f MB", m/1048576; else printf "%.1f KB", m/1024}')
            pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null)
            uptime=$(systemctl show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null)
            uptime=$(date -d "$uptime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$uptime")
            echo -e "     \033[36mv${ver}\033[0m  \033[33mPID:${pid}\033[0m  \033[35m内存:${mem}\033[0m  \033[37m启动:${uptime}\033[0m"
        fi
        echo
        echo -e "  \033[1;32m 1\033[0m. 安装节点 \033[2;37m(VLESS/Reality/HY2/TUIC)\033[0m"
        echo -e "  \033[1;31m 2\033[0m. 卸载节点"
        echo -e "  \033[1;34m 3\033[0m. 查看订阅"
        echo -e "  \033[1;33m 4\033[0m. 修改配置"
        echo -e "  \033[1;34m 5\033[0m. 查看当前配置"
        echo -e "  \033[1;33m 6\033[0m. 更新外部端口 (NAT换端口)"
        local update_label=""
        if [[ "$ACTIVE_KERNEL" == "singbox" ]]; then
            update_label="$SINGBOX_UPDATE_STATUS"
            [[ -n "$update_label" ]] && update_label=" [sing-box: ${update_label}]"
            echo -e "  \033[1;35m 7\033[0m. 更新内核\033[33m${update_label}\033[0m"
        else
            update_label="$XRAY_UPDATE_STATUS"
            [[ -n "$update_label" ]] && update_label=" [xray: ${update_label}]"
            echo -e "  \033[1;35m 7\033[0m. 更新内核\033[33m${update_label}\033[0m"
        fi
        echo -e "  \033[1;36m 8\033[0m. 查看日志"
        echo -e "  \033[1;36m 9\033[0m. 重启服务"
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
            7) do_update_core ;;
            8) do_logs ;;
            9) do_restart ;;
            10) do_purge ;;
            11) do_bbr ;;
            *) echo "无效选项: $choice，请重新选择"; sleep 1 ;;
        esac
    done
}
main "$@"
