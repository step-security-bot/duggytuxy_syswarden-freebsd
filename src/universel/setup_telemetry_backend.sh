setup_telemetry_backend() {
    log "INFO" "Installation of the advanced telemetry engine (Backend) for FreeBSD..."

    local BIN_PATH="/usr/local/bin/syswarden-telemetry.sh"
    local UI_DIR="/etc/syswarden/ui"

    # 1. Writing the Telemetry Bash script
    cat <<'EOF' >"$BIN_PATH"
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

trap 'wait' EXIT

LOCK_DIR="/var/run/syswarden"
mkdir -p "$LOCK_DIR"
chmod 700 "$LOCK_DIR"

exec 9>"$LOCK_DIR/telemetry.lock"
if ! flock -n 9; then
    exit 0
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

SYSWARDEN_DIR="/etc/syswarden"
UI_DIR="/etc/syswarden/ui"
TMP_FILE="$UI_DIR/data.json.tmp"
DATA_FILE="$UI_DIR/data.json"

mkdir -p "$UI_DIR"

if ! command -v jq >/dev/null; then
    pkg install -y jq >/dev/null 2>&1 || true
fi

# --- System Metrics Gathering ---
SYS_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SYS_HOSTNAME=$(hostname)

# FreeBSD uptime
BOOT_TIME=$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')
CURRENT_TIME=$(date +%s)
UPTIME_SEC=$((CURRENT_TIME - BOOT_TIME))
SYS_UPTIME=$(awk -v t=$UPTIME_SEC 'BEGIN {d=int(t/86400); h=int((t%86400)/3600); m=int((t%3600)/60); if(d>0) printf "%dd %dh %dm", d, h, m; else printf "%dh %dm", h, m}')

# FreeBSD loadavg -> output: { 0.00 0.01 0.00 }
SYS_LOAD=$(sysctl -n vm.loadavg | tr -d '{}' | awk '{print $1", "$2", "$3}')

# FreeBSD memory
REAL_MEM=$(sysctl -n hw.physmem)
SYS_RAM_TOTAL=$((REAL_MEM / 1024 / 1024))
FREE_MEM=$(sysctl -n vm.stats.vm.v_free_count)
PAGE_SIZE=$(sysctl -n hw.pagesize)
FREE_MEM_MB=$((FREE_MEM * PAGE_SIZE / 1024 / 1024))
SYS_RAM_USED=$((SYS_RAM_TOTAL - FREE_MEM_MB))

# --- System Storage Gathering (Root) ---
SYS_DISK_USED=$(df -m / 2>/dev/null | awk 'NR==2 {print $3}' || echo 0)
SYS_DISK_TOTAL=$(df -m / 2>/dev/null | awk 'NR==2 {print $2}' || echo 1)

SYS_CORES=$(sysctl -n hw.ncpu || echo "1")
SYS_ARCH=$(uname -m 2>/dev/null || echo "Unknown")
SYS_OS=$(uname -sr 2>/dev/null || echo "FreeBSD")
SYS_CPU=$(sysctl -n hw.model || echo "Unknown")

# --- Layer 3 Metrics ---
L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

# --- System Services Tracking (Universal Pgrep) ---
SRV_F2B=$(pgrep -f fail2ban-server >/dev/null && echo "active" || echo "offline")
SRV_CRON=$(pgrep -f "cron" >/dev/null && echo "active" || echo "offline")

if pgrep "nginx" >/dev/null 2>&1; then
    WEB_NAME="nginx (worker)"
    WEB_PATH=$(command -v nginx || echo "/usr/local/sbin/nginx")
    WEB_STATUS="active"
elif pgrep "httpd" >/dev/null 2>&1 || pgrep "apache2" >/dev/null 2>&1; then
    WEB_NAME="apache (worker)"
    WEB_PATH=$(command -v httpd || command -v apache2 || echo "/usr/local/sbin/httpd")
    WEB_STATUS="active"
elif command -v nginx >/dev/null 2>&1; then
    WEB_NAME="nginx (worker)"
    WEB_PATH=$(command -v nginx)
    WEB_STATUS="offline"
elif command -v httpd >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1; then
    WEB_NAME="apache (worker)"
    WEB_PATH=$(command -v httpd || command -v apache2)
    WEB_STATUS="offline"
else
    WEB_NAME="web-server (none)"
    WEB_PATH="none"
    WEB_STATUS="skipped"
fi

if [[ -f "/usr/local/etc/fail2ban/filter.d/syswarden-modsec.conf" ]] || [[ -d "/usr/local/etc/modsecurity" ]]; then
    if [[ "$WEB_STATUS" == "active" ]]; then
        SRV_MODSEC="active"
    elif [[ "$WEB_STATUS" == "skipped" ]]; then
        SRV_MODSEC="skipped"
    else
        SRV_MODSEC="offline"
    fi
else
    SRV_MODSEC="skipped"
fi

if [[ -f "/usr/local/bin/syswarden_reporter.py" ]]; then
    if pgrep -f "syswarden_reporter" >/dev/null; then
        SRV_REP="active"
    else
        SRV_REP="offline"
    fi
else
    SRV_REP="skipped"
fi

FW_NAME="Unknown Firewall"
FW_PATH="unknown"
FW_STATUS="offline"

if command -v pf >/dev/null 2>&1 && pfctl -s info 2>/dev/null | grep -qw "Enabled"; then
    FW_NAME="pf (Packet Filter)"
    FW_PATH=$(command -v pfctl)
    FW_STATUS="active"
fi

SERVICES_JSON=$(jq -n \
  --arg f2b "$SRV_F2B" --arg crn "$SRV_CRON" --arg web_name "$WEB_NAME" --arg web_path "$WEB_PATH" --arg web_status "$WEB_STATUS" --arg rep "$SRV_REP" \
  --arg fw_name "$FW_NAME" --arg fw_path "$FW_PATH" --arg fw_status "$FW_STATUS" --arg modsec "$SRV_MODSEC" \
  '[
    {"name":"fail2ban-server","path":"/usr/local/bin/fail2ban-server","status":$f2b},
    {"name":$fw_name,"path":$fw_path,"status":$fw_status},
    {"name":$web_name,"path":$web_path,"status":$web_status},
    {"name":"modsecurity (waf)","path":"web-server-module","status":$modsec},
    {"name":"cron/crond","path":"/usr/sbin/cron","status":$crn},
    {"name":"syswarden-reporter","path":"/usr/local/bin/syswarden_reporter.py","status":$rep},
    {"name":"syswarden-telemetry","path":"/usr/local/bin/syswarden-telemetry.sh","status":"active"}
  ]')

PORTS_JSON="[]"
if command -v sockstat >/dev/null; then
    while IFS= read -r line; do
        user=$(echo "$line" | awk '{print $1}')
        proto=$(echo "$line" | awk '{print $2}' | tr 'a-z' 'A-Z')
        local_addr=$(echo "$line" | awk '{print $6}')
        
        [[ -z "$proto" || -z "$local_addr" ]] && continue
        [[ "$proto" != "TCP" && "$proto" != "UDP" && "$proto" != "TCP4" && "$proto" != "UDP4" && "$proto" != "TCP6" && "$proto" != "UDP6" ]] && continue
        
        state="LISTEN"
        
        port="${local_addr##*:}"
        ip="${local_addr%:*}"
        
        if [[ "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
            ip="0.0.0.0 (Any)"
            PORTS_JSON=$(echo "$PORTS_JSON" | jq --arg ip "$ip" --arg s "$state" --arg po "$port" --arg pt "$proto" '. + [{"ip": $ip, "state": $s, "port": $po, "protocol": $pt}]')
        fi
    done <<< "$(sockstat -l -46 2>/dev/null | awk 'NR>1' || true)"
fi

L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"
BANNED_IPS_JSON="[]"
ACTIVE_BANNED_IPS=" "

R_EXP=0; R_BF=0; R_REC=0; R_DOS=0; R_ABU=0

if command -v fail2ban-client >/dev/null && timeout 2 fail2ban-client ping >/dev/null 2>&1; then
    JAIL_LIST=$(timeout 2 fail2ban-client status 2>/dev/null | awk -F'Jail list:[ \t]*' '/Jail list:/ {print $2}' | tr -d ' ' | tr ',' '\n' || true)
    
    for JAIL in $JAIL_LIST; do
        [[ -z "$JAIL" ]] && continue
        L7_ACTIVE_JAILS=$((L7_ACTIVE_JAILS + 1))
        
        STATUS_OUT=$(timeout 3 fail2ban-client status "$JAIL" 2>/dev/null || echo "")
        
        if [[ -n "$STATUS_OUT" ]]; then
            BANNED_COUNT=$(echo "$STATUS_OUT" | grep -i 'Currently banned:' | head -n 1 | grep -oE '[0-9]+' || echo "0")
            BANNED_COUNT=${BANNED_COUNT:-0}
            L7_TOTAL_BANNED=$((L7_TOTAL_BANNED + BANNED_COUNT))
            
            if [[ "$BANNED_COUNT" -gt 0 ]]; then
                MITRE_ID="T1499" # Default
                MITRE_NAME="Endpoint DoS"
                
                case "${JAIL,,}" in
                    *webshell*) MITRE_ID="T1505.003"; MITRE_NAME="Server Software Component: Web Shell" ;;
                    *revshell*|*rce*) MITRE_ID="T1059"; MITRE_NAME="Command and Scripting Interpreter" ;;
                    *sqli*|*xss*|*lfi*|*ssti*|*jndi*|*haproxy*|*modsec*) MITRE_ID="T1190"; MITRE_NAME="Exploit Public-Facing Application" ;;
                    *homoglyph*) MITRE_ID="T1027"; MITRE_NAME="Obfuscated Files or Information" ;;
                    *privesc*|*auditd*) MITRE_ID="T1068"; MITRE_NAME="Exploitation for Privilege Escalation" ;;
                    *secretshunter*|*hunter*|*ssrf*|*idor*) MITRE_ID="T1552"; MITRE_NAME="Unsecured Credentials / Cloud Discovery" ;;
                    *proxy-abuse*|*squid*) MITRE_ID="T1090"; MITRE_NAME="Connection Proxy" ;;
                    *portscan*) MITRE_ID="T1046"; MITRE_NAME="Network Service Discovery" ;;
                    *scanner*|*bot*|*mapper*|*enum*|*tls*|*honeypot*) MITRE_ID="T1595"; MITRE_NAME="Active Scanning / TLS Fuzzing" ;;
                    *flood*|*dos*) MITRE_ID="T1498.001"; MITRE_NAME="Direct Network Flood" ;;
                    *slowloris*) MITRE_ID="T1498.002"; MITRE_NAME="Resource Exhaustion Flood" ;;
                    *wireguard*|*openvpn*) MITRE_ID="T1136"; MITRE_NAME="External Remote Services" ;;
                    *ssh*|*auth*|*telnet*|*ftp*|*mail*|*postfix*|*dovecot*|*mysql*|*mariadb*|*redis*|*rabbitmq*|*zabbix*|*grafana*|*vaultwarden*|*sso*|*odoo*|*prestashop*|*atlassian*|*jenkins*|*gitlab*|*proxmox*|*cockpit*|*nextcloud*) MITRE_ID="T1110"; MITRE_NAME="Brute Force / Password Guessing" ;;
                    *recidive*) MITRE_ID="T1133"; MITRE_NAME="External Remote Services / Repeat Offender" ;;
                esac
                MITRE_PAYLOAD="${MITRE_ID}: ${MITRE_NAME}"

                JAILS_JSON=$(echo "$JAILS_JSON" | jq --arg n "$JAIL" --argjson c "$BANNED_COUNT" --arg ttp "$MITRE_PAYLOAD" '. + [{"name": $n, "count": $c, "mitre": $ttp}]')
                
                if [[ "$JAIL" =~ (sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi|modsec|homoglyph) ]]; then R_EXP=$((R_EXP + BANNED_COUNT))
                elif [[ "$JAIL" =~ (ssh|auth|privesc|prestashop) ]]; then R_BF=$((R_BF + BANNED_COUNT))
                elif [[ "$JAIL" =~ (scan|bot|mapper|enum|hunter|tls|honeypot) ]]; then R_REC=$((R_REC + BANNED_COUNT))
                elif [[ "$JAIL" =~ (flood|slowloris) ]]; then R_DOS=$((R_DOS + BANNED_COUNT))
                else R_ABU=$((R_ABU + BANNED_COUNT)); fi
                
                BANNED_IPS=$(echo "$STATUS_OUT" | grep -i 'Banned IP list:' | head -n 1 | sed 's/.*Banned IP list://I' | tr -d ',' | tr -s ' \t' '\n' | grep -vE '^\s*$' | tail -n 50 || true)
                for IP in $BANNED_IPS; do
                    if [[ -n "$IP" ]]; then
                        L7_PAYLOAD=""
                        if [[ "$JAIL" =~ (recidive) ]]; then
                            L7_PAYLOAD="Repeat Offender (Recidive Module)"
                        else
                            LOG_TARGETS="/var/log/kern-firewall.log* /var/log/kern.log* /var/log/messages* /var/log/nginx/*.log* /var/log/apache2/*.log* /var/log/httpd/*log* /var/log/auth-syswarden.log* /var/log/secure* /var/log/auth.log* /var/log/maillog* /var/log/mail.log* /var/log/daemon.log* /var/log/audit/audit.log*"
                            
                            OIFS="$IFS"
                            IFS=$' \n\t'
                            
                            SORTED_TARGETS=$(ls -1t $LOG_TARGETS 2>/dev/null || true)
                            IFS="$OIFS"
                            
                            L7_PAYLOAD=""
                            
                            if [[ -f "$DATA_FILE" ]]; then
                                CACHE_PAYLOAD=$(jq -r --arg ip "$IP" --arg j "$JAIL" '.layer7.banned_ips[]? | select(.ip == $ip and .jail == $j) | .payload' "$DATA_FILE" 2>/dev/null | head -n 1 || true)
                                if [[ "$CACHE_PAYLOAD" != "null" ]] && [[ -n "$CACHE_PAYLOAD" ]] && [[ "$CACHE_PAYLOAD" != *"Payload context unavailable"* ]] && [[ "$CACHE_PAYLOAD" != *"Manual ban"* ]]; then
                                    L7_PAYLOAD="$CACHE_PAYLOAD"
                                fi
                            fi
                            
                            if [[ -z "$L7_PAYLOAD" ]] && [[ -n "$SORTED_TARGETS" ]]; then
                                while IFS= read -r log_file; do
                                    [[ ! -f "$log_file" ]] && continue
                                    
                                    MATCH=$(timeout 2 zgrep -h -a -F "$IP" "$log_file" 2>/dev/null | grep -vEi '(syswarden_reporter|fail2ban-server|closed keepalive connection|client closed connection|connection reset by peer|ssl_do_handshake|connection timed out|invalid request while reading|without "Host" header)' | awk '!/\[SysWarden-(GEO|ASN)\]/ && !(/\[SysWarden-BLOCK\]/ && !/\[Catch-All\]/)' | tail -n 1 | LC_ALL=C tr -c '\40-\176' '.' || true)
                                    
                                    if [[ -n "$MATCH" ]]; then
                                        L7_PAYLOAD="$MATCH"
                                        break
                                    fi
                                done <<< "$SORTED_TARGETS"
                            fi
                        fi
                        
                        L7_PAYLOAD=$(echo "$L7_PAYLOAD" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)

                        if [[ -z "$L7_PAYLOAD" ]] && [[ -f "$DATA_FILE" ]]; then
                            CACHE_PAYLOAD=$(jq -r --arg ip "$IP" --arg j "$JAIL" '.layer7.banned_ips[]? | select(.ip == $ip and .jail == $j) | .payload' "$DATA_FILE" 2>/dev/null | head -n 1 || true)
                            if [[ "$CACHE_PAYLOAD" != "null" ]] && [[ -n "$CACHE_PAYLOAD" ]] && [[ "$CACHE_PAYLOAD" != *"Payload context unavailable"* ]] && [[ "$CACHE_PAYLOAD" != *"Manual ban"* ]]; then
                                L7_PAYLOAD="$CACHE_PAYLOAD"
                            fi
                        fi
                        
                        if [[ -z "$L7_PAYLOAD" ]]; then
                            L7_PAYLOAD="Payload context unavailable (Manual ban via CLI or absolute log purge)"
                        fi
                        
                        P_CLEAN=$(printf '%s' "$L7_PAYLOAD" | LC_ALL=C tr -c '\40-\176' '.')
                        
                        BANNED_IPS_JSON=$(echo "$BANNED_IPS_JSON" | jq --arg ip "$IP" --arg j "$JAIL" --arg p "$P_CLEAN" --arg ttp "$MITRE_PAYLOAD" '. + [{"ip": $ip, "jail": $j, "payload": $p, "mitre": $ttp}]')
                        ACTIVE_BANNED_IPS+="${IP} "
                    fi
                done
            fi
        fi
    done
fi

TOP_ATTACKERS_JSON="[]"
TOP_STATS=""

OSINT_CACHE="$UI_DIR/osint_cache.txt"
[[ ! -f "$OSINT_CACHE" ]] && touch "$OSINT_CACHE"

declare -A CACHE_COUNTRY
declare -A CACHE_ASN
declare -A CACHE_ISP
while IFS='|' read -r c_ip c_ctry c_asn c_isp; do
    [[ -z "$c_ip" || "$c_ip" == "null" ]] && continue
    CACHE_COUNTRY["$c_ip"]="$c_ctry"
    CACHE_ASN["$c_ip"]="$c_asn"
    CACHE_ISP["$c_ip"]="${c_isp:-N/A}"
done < "$OSINT_CACHE"

TOP_STATS=$(zcat -f $(ls -1t /var/log/fail2ban.log* 2>/dev/null | head -n 4) 2>/dev/null | grep -aE "\] Ban " | sed -E 's/.*\[([^]]+)\].*Ban ([0-9.]+)/\2 \1/' | sort | uniq -c | sort -nr || true)

if [[ -n "$TOP_STATS" ]]; then
    TOP_COUNT=0
    SEEN_IPS=" "
    while IFS=" " read -r count ip jail; do
        if [[ -n "$ip" && -n "$count" ]]; then
            if [[ "$ACTIVE_BANNED_IPS" != *" $ip "* ]]; then
                continue
            fi
            
            if [[ "$SEEN_IPS" == *" $ip "* ]]; then
                continue
            fi
            SEEN_IPS+="$ip "
            
            if (( TOP_COUNT >= 5 )); then break; fi

            PORT="Unknown"
            EXACT_PORT=$(timeout 2 grep -h -F "$ip" /var/log/kern-firewall.log /var/log/kern.log /var/log/messages 2>/dev/null | grep -oE 'DPT=[0-9]+' | cut -d= -f2 | sort | uniq -c | sort -nr | awk 'NR==1 {print $2}' || true)
            
            if [[ -n "$EXACT_PORT" ]]; then
                PORT="$EXACT_PORT"
            else
                case "${jail,,}" in
                    *ssh*) PORT="22" ;;
                    *http*|*web*|*nginx*|*apache*|*prestashop*|*sqli*|*xss*|*lfi*|*tls*) PORT="443" ;;
                    *ftp*) PORT="21" ;;
                    *mail*|*postfix*|*exim*|*dovecot*) PORT="25/143" ;;
                    *mysql*|*mariadb*) PORT="3306" ;;
                    *recidive*) PORT="Multiple" ;;
                    *scan*|*portscan*|*syswarden*) PORT="Network" ;;
                    *) PORT="Unknown" ;;
                esac
            fi
            
            COUNTRY="${CACHE_COUNTRY["$ip"]:-N/A}"
            ASN="${CACHE_ASN["$ip"]:-N/A}"
            ISP="${CACHE_ISP["$ip"]:-N/A}"
            
            if [[ "$COUNTRY" == "N/A" || "$COUNTRY" == "null" ]]; then
                IP_INFO=$(timeout 1.5 curl -s "https://ipwho.is/${ip}" 2>/dev/null || true)
                COUNTRY=$(echo "$IP_INFO" | jq -r '.country_code // "N/A"' 2>/dev/null || echo "N/A")
                
                ASN_NUM=$(echo "$IP_INFO" | jq -r '.connection.asn // "N/A"' 2>/dev/null || echo "N/A")
                if [[ "$ASN_NUM" != "N/A" && "$ASN_NUM" != "null" ]]; then
                    ASN="AS${ASN_NUM}"
                else
                    ASN="N/A"
                fi
                
                ISP=$(echo "$IP_INFO" | jq -r '.connection.isp // "N/A"' 2>/dev/null || echo "N/A")
                
                if [[ "$COUNTRY" != "N/A" && "$COUNTRY" != "null" ]]; then
                    CACHE_COUNTRY["$ip"]="$COUNTRY"
                    CACHE_ASN["$ip"]="$ASN"
                    CACHE_ISP["$ip"]="$ISP"
                    echo "${ip}|${COUNTRY}|${ASN}|${ISP}" >> "$OSINT_CACHE"
                fi
            fi
            
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --arg p "$PORT" --arg ctry "$COUNTRY" --arg asn "$ASN" --arg isp "$ISP" '. + [{"ip": $ip, "port": $p, "country": $ctry, "asn": $asn, "isp": $isp}]')
            TOP_COUNT=$((TOP_COUNT + 1))
        fi
    done <<< "$TOP_STATS"
fi

WHITELIST_COUNT=0
WL_JSON="[]"

if [[ -f "$SYSWARDEN_DIR/whitelist.txt" ]]; then
    WHITELIST_COUNT=$(grep -cvE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    WL_IPS=$(grep -vE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    for IP in $WL_IPS; do
        if [[ -n "$IP" ]]; then
            WL_JSON=$(echo "$WL_JSON" | jq --arg ip "$IP" '. + [$ip]')
        fi
    done
fi

RADAR_JSON=$(jq -n --argjson e "$R_EXP" --argjson b "$R_BF" --argjson r "$R_REC" --argjson d "$R_DOS" --argjson a "$R_ABU" '[$e, $b, $r, $d, $a]')

jq -n \
  --arg ts "$SYS_TIMESTAMP" \
  --arg host "$SYS_HOSTNAME" \
  --arg up "$SYS_UPTIME" \
  --arg load "$SYS_LOAD" \
  --argjson ru "$SYS_RAM_USED" \
  --argjson rt "$SYS_RAM_TOTAL" \
  --argjson du "$SYS_DISK_USED" \
  --argjson dt "$SYS_DISK_TOTAL" \
  --arg cores "$SYS_CORES" \
  --arg arch "$SYS_ARCH" \
  --arg os "$SYS_OS" \
  --arg cpu "$SYS_CPU" \
  --argjson lg "$L3_GLOBAL" \
  --argjson lgeo "$L3_GEOIP" \
  --argjson lasn "$L3_ASN" \
  --argjson ltb "$L7_TOTAL_BANNED" \
  --argjson laj "$L7_ACTIVE_JAILS" \
  --argjson jj "$JAILS_JSON" \
  --argjson bip "$BANNED_IPS_JSON" \
  --argjson top "$TOP_ATTACKERS_JSON" \
  --argjson wlc "$WHITELIST_COUNT" \
  --argjson wlip "$WL_JSON" \
  --argjson srv "$SERVICES_JSON" \
  --argjson pts "$PORTS_JSON" \
  --argjson rad "$RADAR_JSON" \
'{
  timestamp: $ts,
  system: { hostname: $host, uptime: $up, load_average: $load, ram_used_mb: $ru, ram_total_mb: $rt, disk_used_mb: $du, disk_total_mb: $dt, services: $srv, cores: $cores, arch: $arch, os: $os, cpu_model: $cpu, ports: $pts },
  layer3: { global_blocked: $lg, geoip_blocked: $lgeo, asn_blocked: $lasn },
  layer7: { total_banned: $ltb, active_jails: $laj, jails_data: $jj, banned_ips: $bip, top_attackers: $top, risk_radar: $rad },
  whitelist: { active_ips: $wlc, ips: $wlip }
}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$DATA_FILE"
chown root:wheel "$DATA_FILE" 2>/dev/null || true
chmod 600 "$DATA_FILE"
EOF

    chmod +x "$BIN_PATH"

    if ! crontab -l 2>/dev/null | grep "$BIN_PATH" >/dev/null; then
        (
            crontab -l 2>/dev/null || true
            echo "* * * * * $BIN_PATH >/dev/null 2>&1"
        ) | crontab -
    fi

    if ! "$BIN_PATH"; then
        log "WARN" "Initial telemetry run failed, but script will continue."
    fi
}
