syswarden_jail_redis() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service redis-server onestatus >/dev/null 2>&1 2>/dev/null && ! service redis onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local REDIS_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/redis/redis-server.log" ]]; then
        REDIS_LOG="/var/log/redis/redis-server.log"
    elif [[ -f "/var/log/redis/redis.log" ]]; then
        REDIS_LOG="/var/log/redis/redis.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$REDIS_LOG" ]]; then
        return 0
    fi

    log "INFO" "Redis daemon and logs detected. Enabling Redis Guard."

    # Create Filter for Redis Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-redis.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-redis.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? [Aa]uthentication failed.*$
            ^.*? Client <HOST>:\d+ disconnected, .*? [Aa]uthentication.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-redis.conf
[syswarden-redis]
enabled  = true
port     = 6379
filter   = syswarden-redis
logpath  = $REDIS_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
}
