syswarden_jail_vaultwarden() {
    # 1. Fail-Fast: Verify native daemon or process execution at the absolute top
    if ! service vaultwarden onestatus >/dev/null 2>&1 2>/dev/null && ! pgrep -x "vaultwarden" >/dev/null 2>&1; then
        return 0
    fi

    local VW_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/vaultwarden/vaultwarden.log" ]]; then
        VW_LOG="/var/log/vaultwarden/vaultwarden.log"
    elif [[ -f "/vw-data/vaultwarden.log" ]]; then
        VW_LOG="/vw-data/vaultwarden.log"
    elif [[ -f "/opt/vaultwarden/vaultwarden.log" ]]; then
        VW_LOG="/opt/vaultwarden/vaultwarden.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$VW_LOG" ]]; then
        return 0
    fi

    log "INFO" "Vaultwarden daemon and logs detected. Enabling Vaultwarden Guard."

    # Create Filter for Vaultwarden Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-vaultwarden.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-vaultwarden.conf
[Definition]
failregex = ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Invalid password.*from <HOST>.*\s*$
            ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Client IP: <HOST>.*\s*$
            ^.*\[(?:ERROR|WARN)\].*Failed login attempt.*from <HOST>.*\s*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-vaultwarden.conf
[syswarden-vaultwarden]
enabled  = true
port     = http,https,80,443,8080
filter   = syswarden-vaultwarden
logpath  = $VW_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
