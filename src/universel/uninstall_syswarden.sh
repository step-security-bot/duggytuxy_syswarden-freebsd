uninstall_syswarden() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "CRITICAL: uninstall_syswarden() must be executed as root."
        exit 1
    fi

    echo -e "\n${RED}=== Uninstalling SysWarden (FreeBSD Mode) ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation (Scorched Earth)..."

    local os_log
    local filter
    local rule
    local handle
    local user_dir
    local profile_file
    local rm_wazuh="N"
    local active_jails
    local user
    local grp
    local members

    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null        source "$CONF_FILE"
    fi

    log "INFO" "Sending SIGTERM to gracefully shutdown background processes..."
    pkill -15 -f "^/bin/sh.*syswarden-telemetry" 2>/dev/null || true
    pkill -15 -f "syswarden_reporter.py" 2>/dev/null || true
    pkill -15 -f "syswarden-ui-server.py" 2>/dev/null || true
    pkill -15 -f "syswarden-ui-sync" 2>/dev/null || true
    sleep 2

    log "INFO" "Executing Scorched Earth (SIGKILL) on surviving orphans..."
    pkill -9 -f "^/bin/sh.*syswarden-telemetry" 2>/dev/null || true
    pkill -9 -f "syswarden_reporter.py" 2>/dev/null || true
    pkill -9 -f "syswarden-ui-server.py" 2>/dev/null || true
    pkill -9 -f "syswarden-ui-sync" 2>/dev/null || true

    log "INFO" "Removing SysWarden Reporter..."
    sysrc syswarden_reporter_enable=NO >/dev/null 2>&1 || true
    service syswarden_reporter stop >/dev/null 2>&1 || true
    rm -f /usr/local/etc/rc.d/syswarden_reporter /usr/local/bin/syswarden_reporter.py

    log "INFO" "Removing IPSet Restorer Service..."
    sysrc syswarden_ipset_enable=NO >/dev/null 2>&1 || true
    service syswarden_ipset stop >/dev/null 2>&1 || true
    rm -f /usr/local/etc/rc.d/syswarden_ipset /etc/syswarden/ipsets.save

    log "INFO" "Removing UI Dashboard Service & Audit Tools..."
    sysrc syswarden_ui_enable=NO >/dev/null 2>&1 || true
    service syswarden_ui stop >/dev/null 2>&1 || true
    rm -f /usr/local/etc/rc.d/syswarden_ui /usr/local/bin/syswarden-telemetry.sh /usr/local/bin/syswarden-ui-server.py /usr/local/bin/syswarden-ui-sync.sh
    rm -f /usr/local/bin/syswarden-dashboard /usr/local/bin/syswarden-tui
    rm -rf /etc/syswarden/ui
    rm -f /var/log/syswarden-audit.log

    log "INFO" "Removing HA Cluster Sync Engine..."
    rm -f /usr/local/bin/syswarden-sync.sh
    if crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
        crontab -l 2>/dev/null | grep -v "syswarden-sync" | crontab -
    fi

    rm -rf /var/log/syswarden 2>/dev/null || true
    rm -rf /opt/syswarden 2>/dev/null || true

    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        log "INFO" "Stopping and removing SysWarden WireGuard VPN..."
        service wireguard stop >/dev/null 2>&1 || true
        sysrc wireguard_enable=NO >/dev/null 2>&1 || true
        rm -f /usr/local/etc/wireguard/wg0.conf
        rm -rf /usr/local/etc/wireguard/clients
        if [[ -d /usr/local/etc/wireguard ]] && [[ -z "$(ls -A /usr/local/etc/wireguard 2>/dev/null)" ]]; then
            rmdir /usr/local/etc/wireguard 2>/dev/null || true
        fi
        sed -i '' '/net.inet.ip.forwarding=1/d' /etc/sysctl.conf 2>/dev/null || true
    fi

    log "INFO" "Removing Maintenance Tasks..."
    if grep -q "syswarden" /etc/crontab 2>/dev/null; then
        sed -i '' '/syswarden/d' /etc/crontab
    fi

    log "INFO" "Cleaning Firewall Rules..."
    if [[ -f "/etc/pf.conf" ]]; then
        sed -i '' '\|include "/etc/syswarden/pf-syswarden.conf"|d' /etc/pf.conf
        pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
    fi

    log "INFO" "Executing Scorched Earth purge on Fail2ban memory and logs..."
    service fail2ban stop >/dev/null 2>&1 || true

    rm -f /var/db/fail2ban/fail2ban.sqlite3
    if [[ -f /var/log/fail2ban.log ]]; then
        : >/var/log/fail2ban.log
    fi
    rm -f /var/log/fail2ban.log.*

    for os_log in "/var/log/messages" "/var/log/auth.log"; do
        if [[ -f "$os_log" ]]; then
            sed -i '' '/\] Ban /d' "$os_log" 2>/dev/null || true
            sed -i '' '/\] Restore Ban /d' "$os_log" 2>/dev/null || true
        fi
    done

    rm -rf /etc/syswarden/ui/data.json
    rm -rf /var/log/syswarden/* 2>/dev/null || true

    for filter in nginx-scanner mariadb-auth mongodb-guard syswarden-privesc syswarden-portscan \
        syswarden-revshell syswarden-aibots syswarden-badbots syswarden-httpflood syswarden-slowloris syswarden-webshell \
        syswarden-sqli-xss syswarden-secretshunter syswarden-ssrf syswarden-jndi-ssti syswarden-apimapper \
        syswarden-modsec syswarden-tls-guard syswarden-apache-tls \
        syswarden-lfi-advanced syswarden-vaultwarden syswarden-sso syswarden-silent-scanner syswarden-cms-honeypot syswarden-recidive syswarden-generic-auth \
        syswarden-proxy-abuse syswarden-jenkins syswarden-gitlab syswarden-redis syswarden-rabbitmq \
        syswarden-idor-enum syswarden-odoo syswarden-prestashop syswarden-atlassian \
        wordpress-auth drupal-auth nextcloud openvpn-custom gitea-custom cockpit-custom proxmox-custom \
        haproxy-guard phpmyadmin-custom squid-custom dovecot-custom laravel-auth grafana-auth zabbix-auth wireguard; do
        rm -f "/usr/local/etc/fail2ban/filter.d/${filter}.conf"
    done
    rm -f /usr/local/etc/fail2ban/action.d/syswarden-webhook.conf
    rm -f /usr/local/etc/fail2ban/action.d/syswarden-persistence.conf
    rm -f /var/db/fail2ban/syswarden_f2b_blocklist.txt
    rm -f /var/db/fail2ban/syswarden_f2b_expiry.txt
    rm -f /var/db/fail2ban/syswarden_persistence.lock
    rm -f /usr/local/etc/fail2ban/jail.local
    rm -f /usr/local/etc/fail2ban/fail2ban.local

    if [[ "${FAIL2BAN_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Fail2ban (installed by SysWarden)..."
        pkg remove -y fail2ban 2>/dev/null || true
    else
        log "INFO" "Restoring default Fail2ban configuration..."
        if [[ -f /usr/local/etc/fail2ban/jail.local.bak ]]; then
            mv /usr/local/etc/fail2ban/jail.local.bak /usr/local/etc/fail2ban/jail.local
        fi
        service fail2ban restart >/dev/null 2>&1 || true
    fi

    if pkg info wazuh-agent >/dev/null 2>&1; then
        if [[ "${MODE:-}" == "auto" ]]; then
            log "INFO" "Auto Mode: Skipping Wazuh Agent uninstallation."
            rm_wazuh="N"
        else
            read -r -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        fi

        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            service wazuh-agent stop >/dev/null 2>&1 || true
            sysrc wazuh_agent_enable=NO >/dev/null 2>&1 || true
            pkg remove -y wazuh-agent
        fi
    fi

    log "INFO" "Reverting OS Hardening & Log Routing..."

    rm -f /usr/local/etc/syslog.d/syswarden.conf 2>/dev/null || true
    service syslogd restart >/dev/null 2>&1 || true

    rm -f /var/log/kern-firewall.log 2>/dev/null || true
    rm -f /var/log/auth-syswarden.log 2>/dev/null || true

    for user_dir in /home/* /usr/home/*; do
        if [[ -d "$user_dir" ]]; then
            for profile_file in "$user_dir/.profile" "$user_dir/.shrc" "$user_dir/.cshrc" "$user_dir/.login"; do
                if [[ -f "$profile_file" ]]; then chflags noschg "$profile_file" 2>/dev/null || true; fi
            done
        fi
    done

    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i '' 's/^[[:space:]]*AllowTcpForwarding[[:space:]]*no/#AllowTcpForwarding yes/' /etc/ssh/sshd_config
        service sshd restart >/dev/null 2>&1 || true
    fi

    if [[ -f /var/cron/allow ]] && [[ "$(cat /var/cron/allow)" == "root" ]]; then rm -f /var/cron/allow; fi

    if [[ -f "$SYSWARDEN_DIR/group_backup.txt" ]]; then
        while IFS=':' read -r grp members; do
            for user in $(echo "$members" | tr ',' ' '); do
                if [[ -n "$user" ]] && id "$user" >/dev/null 2>&1; then pw groupmod "$grp" -m "$user" 2>/dev/null || true; fi
            done
        done <"$SYSWARDEN_DIR/group_backup.txt"
    fi

    log "INFO" "Reverting CIS Benchmark Level 2 configurations..."

    if [[ -f "/etc/sysctl.conf" ]]; then
        sed -i '' '/# --- SysWarden: CIS Level 2 Kernel Hardening (FreeBSD) ---/,$d' /etc/sysctl.conf
        /etc/rc.d/sysctl reload >/dev/null 2>&1 || true
    fi

    if [[ -f "/etc/ssh/sshd_config" ]]; then
        sed -i '' 's/^[[:space:]]*X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config 2>/dev/null || true
        sed -i '' 's/^[[:space:]]*MaxAuthTries.*/MaxAuthTries 6/' /etc/ssh/sshd_config 2>/dev/null || true
        sed -i '' 's/^[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 0/' /etc/ssh/sshd_config 2>/dev/null || true
        sed -i '' 's/^[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config 2>/dev/null || true
        service sshd reload >/dev/null 2>&1 || true
    fi

    if [[ -d "/var/cron" ]]; then
        chmod 755 "/var/cron" 2>/dev/null || true
    fi
    if [[ -f "/etc/crontab" ]]; then
        chmod 644 "/etc/crontab" 2>/dev/null || true
    fi

    rm -rf "$SYSWARDEN_DIR"
    rm -f "$LOG_FILE"
    rm -f /etc/syswarden.conf
    find /usr/local/bin -maxdepth 1 -type f -name "syswarden*" -delete 2>/dev/null || true

    log "INFO" "Cleanup complete."
    echo -e "${GREEN}Uninstallation complete (Scorched Earth).${NC}"
    echo -e "${YELLOW}[i] A reboot is recommended to ensure all network routes are completely flushed.${NC}"
    exit 0
}
