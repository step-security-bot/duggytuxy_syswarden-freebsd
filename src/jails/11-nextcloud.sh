syswarden_jail_nextcloud() {
    # 1. Fail-Fast: Surgical check against discovery engine state (Zero I/O overhead)
    if [[ "${SYSW_HAS_NEXTCLOUD:-false}" != "true" ]]; then
        return 0
    fi

    local NC_LOG=""

    # 2. Check common paths for Nextcloud log file
    for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
        if [[ -f "$path" ]]; then
            NC_LOG="$path"
            break
        fi
    done

    # 3. Fail-Fast: Ensure specific application logs exist
    if [[ -z "$NC_LOG" ]]; then
        return 0
    fi

    log "INFO" "Nextcloud instance and logs detected. Enabling Nextcloud Jail."

    # Create Filter (Supports both JSON and Legacy text logs)
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
failregex = ^.*?Login failed: .*? \(Remote IP: '<HOST>'\).*$
ignoreregex = 
EOF
    fi

    cat <<EOF >/usr/local/etc/fail2ban/jail.d/nextcloud.conf
[nextcloud]
enabled  = true
port     = http,https
filter   = nextcloud
logpath  = $NC_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
