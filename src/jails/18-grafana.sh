syswarden_jail_grafana() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service grafana-server onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/grafana/grafana.log" ]]; then
        return 0
    fi

    log "INFO" "Grafana daemon and logs detected. Enabling Grafana Jail."

    # Create Filter for Grafana Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/grafana-auth.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/grafana-auth.conf
[Definition]
failregex = ^.*(?:msg="Invalid username or password"|status=401).*remote_addr=<HOST>.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/grafana.conf
[grafana-auth]
enabled  = true
port     = 3000,http,https
filter   = grafana-auth
logpath  = /var/log/grafana/grafana.log
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
