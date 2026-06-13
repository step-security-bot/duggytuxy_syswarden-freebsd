configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (FreeBSD Mode)..."

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS & FILTERS ---
        log "INFO" "Purging legacy definitions to prevent rule conflicts..."
        if [[ -d /usr/local/etc/fail2ban/jail.d ]]; then
            rm -rf /usr/local/etc/fail2ban/jail.d
        fi
        mkdir -p /usr/local/etc/fail2ban/jail.d
        chmod 755 /usr/local/etc/fail2ban/jail.d
        rm -f /usr/local/etc/fail2ban/filter.d/syswarden-*.conf 2>/dev/null || true
        log "INFO" "Purged fail2ban/jail.d/ and old filters entirely to enforce absolute Zero Trust."

        if [[ -f /usr/local/etc/fail2ban/jail.local ]] && [[ ! -f /usr/local/etc/fail2ban/jail.local.bak ]]; then
            cp /usr/local/etc/fail2ban/jail.local /usr/local/etc/fail2ban/jail.local.bak
        fi

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/usr/local/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
dbpurgeage = 691200
EOF

        # 2. Firewall Backend & OS Optimization (Zero Trust AllPorts)
        export SYSW_F2B_ACTION="pf"
        export SYSW_F2B_ACTION_ALLPORTS="pf"
        export SYSW_OS_BACKEND="auto"

        # 3. Dynamic Whitelist Array Construction
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"

        local public_ip
        public_ip=$(ifconfig | grep -E 'inet [0-9.]+' | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi

        local all_local_ips
        all_local_ips=$(ifconfig | awk '/inet / {print $2}' | grep -v '127.0.0.1' | tr '\n' ' ' || true)
        if [[ -n "$all_local_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $all_local_ips"; fi

        local local_subnets
        local_subnets=$(netstat -rn | awk '/link#/{print $1}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi

        if [[ -f /etc/resolv.conf ]]; then
            local dns_ips
            dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi

        # Synchronize Fail2ban memory with the global Zero Trust whitelist to prevent rule shadowing
        if [[ -f "$WHITELIST_FILE" ]]; then
            local global_whitelisted_ips
            global_whitelisted_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            if [[ -n "$global_whitelisted_ips" ]]; then
                f2b_ignoreip="$f2b_ignoreip $global_whitelisted_ips"
                log "INFO" "Synchronized Fail2ban ignoreip with global whitelist."
            fi
        fi

        # --- WEBHOOK ACTION SCRIPT DEPLOYMENT ---
        if [[ "${SYSWARDEN_ENABLE_WEBHOOK:-n}" == "y" ]]; then
            log "INFO" "Deploying secure Webhook dispatcher for Fail2ban..."

            cat <<'EOF_SCRIPT' >/etc/syswarden/syswarden-webhook.sh
#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN SECURE WEBHOOK DISPATCHER
# ==============================================================================
set -euo pipefail

JAIL_NAME="${1:-Unknown}"
IP_ADDRESS="${2:-0.0.0.0}"
FAILURES="${3:-0}"

if [[ -f /etc/syswarden.conf ]]; then
    source /etc/syswarden.conf
else
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SERVER_NAME=$(hostname)

send_discord() {
    local url="$1"
    local payload
    payload=$(cat <<JSON
{
  "content": null,
  "embeds": [
    {
      "title": "SysWarden Alert: IP Blocked",
      "description": "A malicious IP has been banned by Fail2ban Layer 7.\nServer : ${SERVER_NAME}\nJail : ${JAIL_NAME}\nTarget IP : ${IP_ADDRESS}\nFailures : ${FAILURES}",
      "color": 16711680,
      "timestamp": "${TIMESTAMP}"
    }
  ]
}
JSON
)
    curl -s --proto =https --tlsv1.2 -X POST -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null || true
}

send_teams() {
    local url="$1"
    local payload
    payload=$(cat <<JSON
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "FF0000",
  "summary": "SysWarden Alert",
  "sections": [{
    "activityTitle": "SysWarden Alert: IP Blocked",
    "activitySubtitle": "Layer 7 Application Firewall",
    "facts": [
      { "name": "Server:", "value": "${SERVER_NAME}" },
      { "name": "Jail:", "value": "${JAIL_NAME}" },
      { "name": "Target IP:", "value": "${IP_ADDRESS}" },
      { "name": "Failures:", "value": "${FAILURES}" }
    ],
    "markdown": true
  }]
}
JSON
)
    curl -s --proto =https --tlsv1.2 -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null || true
}

if [[ -n "${SYSWARDEN_WEBHOOK_URL_DISCORD:-}" ]]; then
    send_discord "$SYSWARDEN_WEBHOOK_URL_DISCORD"
fi

if [[ -n "${SYSWARDEN_WEBHOOK_URL_TEAMS:-}" ]]; then
    send_teams "$SYSWARDEN_WEBHOOK_URL_TEAMS"
fi

exit 0
EOF_SCRIPT
            chmod 700 /etc/syswarden/syswarden-webhook.sh
            chown root:wheel /etc/syswarden/syswarden-webhook.sh

            cat <<'EOF_ACTION' >/usr/local/etc/fail2ban/action.d/syswarden-webhook.conf
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /etc/syswarden/syswarden-webhook.sh <name> <ip> <failures>
actionunban = 
EOF_ACTION
        fi

        # --- L7 PERSISTENCE SCRIPT DEPLOYMENT ---
        log "INFO" "Deploying secure L7 behavioral persistence subsystem..."
        cat <<'EOF_PERSIST' >/etc/syswarden/syswarden-persistence.sh
#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN L7 BEHAVIORAL BANS PERSISTENCE DISPATCHER (FREEBSD PF)
# ==============================================================================
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ACTION="${1:-}"
IP_ADDRESS="${2:-}"
JAIL_NAME="${3:-Unknown}"

if [[ -z "$ACTION" ]] || [[ -z "$IP_ADDRESS" ]]; then
    exit 1
fi

CONF_FILE="/etc/syswarden.conf"
F2B_BLOCKLIST="/var/db/fail2ban/syswarden_f2b_blocklist.txt"
F2B_EXPIRY="/var/db/fail2ban/syswarden_f2b_expiry.txt"
LOCK_FILE="/var/db/fail2ban/syswarden_persistence.lock"
SET_NAME="syswarden_blacklist"

mkdir -p /var/db/fail2ban

exec_with_lock() {
    exec 9>"$LOCK_FILE"
    flock -x 9
    "$@"
    exec 9>&-
}

inject_into_kernel() {
    local ip="$1"
    pfctl -t "$SET_NAME" -T add "$ip" >/dev/null 2>&1 || true
}

handle_ban() {
    if [[ ! -f "$F2B_BLOCKLIST" ]]; then
        touch "$F2B_BLOCKLIST"
        chmod 600 "$F2B_BLOCKLIST"
    fi
    if ! grep -qFx "$IP_ADDRESS" "$F2B_BLOCKLIST"; then
        echo "$IP_ADDRESS" >> "$F2B_BLOCKLIST"
    fi

    inject_into_kernel "$IP_ADDRESS"

    if [[ -f "$F2B_EXPIRY" ]]; then
        local tmp_exp
        tmp_exp=$(mktemp -t fail2ban)
        grep -v "^${IP_ADDRESS};" "$F2B_EXPIRY" > "$tmp_exp" || true
        mv "$tmp_exp" "$F2B_EXPIRY"
        chmod 600 "$F2B_EXPIRY"
    fi
}

handle_unban() {
    local expiry_time
    expiry_time=$(( $(date +%s) + 2592000 )) 

    if [[ ! -f "$F2B_EXPIRY" ]]; then
        touch "$F2B_EXPIRY"
        chmod 600 "$F2B_EXPIRY"
    fi

    local tmp_exp
    tmp_exp=$(mktemp -t fail2ban)
    grep -v "^${IP_ADDRESS};" "$F2B_EXPIRY" > "$tmp_exp" || true
    echo "${IP_ADDRESS};${expiry_time}" >> "$tmp_exp"
    mv "$tmp_exp" "$F2B_EXPIRY"
    chmod 600 "$F2B_EXPIRY"

    if [[ ! -f "$F2B_BLOCKLIST" ]]; then
        touch "$F2B_BLOCKLIST"
        chmod 600 "$F2B_BLOCKLIST"
    fi
    if ! grep -qFx "$IP_ADDRESS" "$F2B_BLOCKLIST"; then
        echo "$IP_ADDRESS" >> "$F2B_BLOCKLIST"
    fi

    inject_into_kernel "$IP_ADDRESS"
}

purge_expired_bans() {
    if [[ ! -f "$F2B_EXPIRY" ]] || [[ ! -s "$F2B_EXPIRY" ]]; then
        return
    fi

    local current_time
    current_time=$(date +%s)
    local tmp_exp ip exp
    
    tmp_exp=$(mktemp -t fail2ban)
    chmod 600 "$tmp_exp"
    
    local expired_ips=()

    while IFS=';' read -r ip exp || [[ -n "$ip" ]]; do
        [[ -z "$ip" || -z "$exp" ]] && continue
        if (( current_time >= exp )); then
            expired_ips+=("$ip")
            pfctl -t "$SET_NAME" -T delete "$ip" >/dev/null 2>&1 || true
        else
            echo "${ip};${exp}" >> "$tmp_exp"
        fi
    done < "$F2B_EXPIRY"
    
    mv "$tmp_exp" "$F2B_EXPIRY"
    chmod 600 "$F2B_EXPIRY"

    if (( ${#expired_ips[@]} > 0 )); then
        if [[ -f "$F2B_BLOCKLIST" ]]; then
            local tmp_bl tmp_expired_file
            tmp_bl=$(mktemp -t fail2ban)
            tmp_expired_file=$(mktemp -t fail2ban)
            
            for e_ip in "${expired_ips[@]}"; do
                echo "$e_ip" >> "$tmp_expired_file"
            done
            
            grep -vFxf "$tmp_expired_file" "$F2B_BLOCKLIST" > "$tmp_bl" || true
            mv "$tmp_bl" "$F2B_BLOCKLIST"
            chmod 600 "$F2B_BLOCKLIST"
            rm -f "$tmp_expired_file"
        fi
    fi
}

case "$ACTION" in
    ban)
        exec_with_lock purge_expired_bans
        exec_with_lock handle_ban
        ;;
    unban)
        exec_with_lock purge_expired_bans
        exec_with_lock handle_unban
        ;;
esac

exit 0
EOF_PERSIST
        chmod 700 /etc/syswarden/syswarden-persistence.sh
        chown root:wheel /etc/syswarden/syswarden-persistence.sh

        mkdir -p /var/db/fail2ban
        if [[ -f "/var/db/fail2ban/syswarden_f2b_blocklist.txt" ]]; then
            chmod 600 /var/db/fail2ban/syswarden_f2b_blocklist.txt
            chown root:wheel /var/db/fail2ban/syswarden_f2b_blocklist.txt
        fi

        if [[ -f "/var/db/fail2ban/syswarden_f2b_expiry.txt" ]]; then
            chmod 600 /var/db/fail2ban/syswarden_f2b_expiry.txt
            chown root:wheel /var/db/fail2ban/syswarden_f2b_expiry.txt
        fi

        cat <<'EOF_PERSIST_ACTION' >/usr/local/etc/fail2ban/action.d/syswarden-persistence.conf
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /etc/syswarden/syswarden-persistence.sh ban <ip> <name>
actionunban = /etc/syswarden/syswarden-persistence.sh unban <ip> <name>
EOF_PERSIST_ACTION

        SYSW_DEFAULT_ACTION="%(banaction)s"
        if [[ "${SYSWARDEN_ENABLE_WEBHOOK:-n}" == "y" ]]; then
            SYSW_DEFAULT_ACTION+=$'\n          syswarden-webhook'
        fi
        SYSW_DEFAULT_ACTION+=$'\n          syswarden-persistence'

        # 4. Generate Core jail.local (Defaults & SSH)
        cat <<EOF >/usr/local/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
usedns = no
banaction = $SYSW_F2B_ACTION
action = $SYSW_DEFAULT_ACTION

[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $SYSW_F2B_ACTION
maxretry = 3
findtime = 1w
bantime  = 4w

[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-ssh}
logpath = /var/log/auth.log
backend = $SYSW_OS_BACKEND
banaction = $SYSW_F2B_ACTION_ALLPORTS
findtime = 24h
maxretry = 2
EOF

        # Recidive Filter
        if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
failregex = fail2ban\.actions.*NOTICE\s+\[[^\]]+\]\s+(?:Ban|Found)\s+<HOST>
ignoreregex = fail2ban\.actions.*NOTICE\s+\[[^\]]+\]\s+(?:Restore )?(?:Unban|unban)\s+<HOST>
EOF
        fi

        # 5. GLOBAL VARIABLES DETECTION (For Jail Modules)
        export SYSW_APACHE_ACCESS=""
        if [[ -f "/var/log/apache2/access.log" ]]; then
            SYSW_APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/access_log" ]]; then SYSW_APACHE_ACCESS="/var/log/httpd/access_log"; fi

        export SYSW_RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "$SYSW_APACHE_ACCESS"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_RCE_LOGS" ]]; then
                    SYSW_RCE_LOGS="$log_file"
                else SYSW_RCE_LOGS+=$'\n          '"$log_file"; fi
            fi
        done

        export SYSW_MODSEC_ACTIVE=0
        export SYSW_MODSEC_LOGS=""
        if [[ ! -f "/var/log/modsec_audit.log" ]]; then
            touch /var/log/modsec_audit.log
            chmod 640 /var/log/modsec_audit.log
            chown root:wheel /var/log/modsec_audit.log 2>/dev/null || true
        fi

        for log_file in "/var/log/nginx/error.log" "/var/log/apache2/error.log" "/var/log/httpd/error_log" "/var/log/modsec_audit.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_MODSEC_LOGS" ]]; then
                    SYSW_MODSEC_LOGS="$log_file"
                else SYSW_MODSEC_LOGS+=$'\n          '"$log_file"; fi
            fi
        done
        if [[ -n "$SYSW_MODSEC_LOGS" ]] && [[ -d "/usr/local/etc/modsecurity" ]] && [[ -f "/usr/local/etc/modsecurity/main.conf" ]]; then
            export SYSW_MODSEC_ACTIVE=1
        fi

        log "INFO" "Applying Layer 7 Application Firewall Rules (Fail2ban)..."

        if command -v discover_web_apps >/dev/null 2>&1; then
            discover_web_apps
        fi

        log "INFO" "Executing modular jail definitions..."
        local jail_functions
        jail_functions=$(compgen -A function | grep '^syswarden_jail_' || true)
        if [[ -n "$jail_functions" ]]; then
            for func in $jail_functions; do
                "$func"
            done
        else
            log "WARN" "No external jail modules loaded. Only SSH and Recidive are active."
        fi

        log "INFO" "Sanitizing multi-line logpath arrays for strict ConfigParser alignment..."
        sed -i '' -E 's|[[:space:]]+(/var/log/[^[:space:]]+)|\n          \1|g' /usr/local/etc/fail2ban/jail.local /usr/local/etc/fail2ban/jail.d/*.conf /usr/local/etc/fail2ban/jail.d/*.local 2>/dev/null || true

        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
            chown root:wheel /var/log/fail2ban.log 2>/dev/null || true
        fi

        log "INFO" "Reloading/Starting Fail2ban service..."
        sysrc fail2ban_enable=YES >/dev/null 2>&1
        if service fail2ban onestatus >/dev/null 2>&1; then
            fail2ban-client reload >/dev/null 2>&1 || true
        else
            service fail2ban start >/dev/null 2>&1 || true
        fi

        for _ in {1..10}; do
            if fail2ban-client ping >/dev/null 2>&1; then break; fi
            sleep 1
        done
    fi
}
