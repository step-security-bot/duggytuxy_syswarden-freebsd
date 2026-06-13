syswarden_jail_zabbix() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service zabbix-server onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/zabbix/zabbix_server.log" ]]; then
        return 0
    fi

    log "INFO" "Zabbix daemon and logs detected. Enabling Zabbix Jail."

    # Create Filter for Zabbix Server Login Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/zabbix-auth.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/zabbix-auth.conf
[Definition]
failregex = ^.*?failed login of user .*? from <HOST>.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/zabbix.conf
[zabbix-auth]
enabled  = true
port     = http,https,10050,10051
filter   = zabbix-auth
logpath  = /var/log/zabbix/zabbix_server.log
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
