syswarden_jail_rabbitmq() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service rabbitmq-server onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local RABBIT_LOG=""

    # 2. Dynamic log path discovery (RabbitMQ logs often include the @hostname)
    if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
        # Take the most recent if multiple exist, or use the wildcard for Fail2ban
        RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
    elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then
        RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$RABBIT_LOG" ]]; then
        return 0
    fi

    log "INFO" "RabbitMQ daemon and logs detected. Enabling RabbitMQ Guard."

    # Create Filter for RabbitMQ (AMQP & Management Plugin)
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-rabbitmq.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-rabbitmq.conf
[Definition]
failregex = ^.*?HTTP access denied: .*? from <HOST>.*$
            ^.*?AMQP connection <HOST>:\d+ .*? failed: .*?authentication failure.*$
            ^.*?<HOST>:\d+ .*? (?:invalid credentials|authentication failed).*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-rabbitmq.conf
[syswarden-rabbitmq]
enabled  = true
port     = 5672,15672
filter   = syswarden-rabbitmq
logpath  = $RABBIT_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
}
