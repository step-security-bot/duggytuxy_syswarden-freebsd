syswarden_jail_laravel() {
    # 1. Fail-Fast: Surgical check against discovery engine state (Zero I/O overhead)
    if [[ "${SYSW_HAS_LARAVEL:-false}" != "true" ]]; then
        return 0
    fi

    local LARAVEL_LOG=""

    # 2. Check standard Laravel log paths
    for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
        if [[ -f "$path" ]]; then
            LARAVEL_LOG="$path"
            break
        fi
    done

    # 3. Fallback: search in standard web roots (max depth 4)
    # This I/O intensive command ONLY runs if the discovery engine mathematically proved Laravel's presence.
    if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
        LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1 || true)
    fi

    # 4. Fail-Fast: Ensure specific application logs exist
    if [[ -z "$LARAVEL_LOG" ]]; then
        return 0
    fi

    log "INFO" "Laravel framework and logs detected. Enabling Laravel Jail."

    # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/laravel-auth.conf
[Definition]
failregex = ^\[.*\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/laravel.conf
[laravel-auth]
enabled  = true
port     = http,https
filter   = laravel-auth
logpath  = $LARAVEL_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
