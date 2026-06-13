syswarden_jail_mongodb() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service mongod onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/mongodb/mongod.log" ]]; then
        return 0
    fi

    log "INFO" "MongoDB daemon and logs detected. Enabling Mongo Jail."

    # Create strict Filter for Auth failures & Unauthorized commands
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/mongodb-guard.conf
[Definition]
failregex = ^.*? (?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).*? (?:<HOST>|remote:\s*<HOST>:\d+)
ignoreregex = 
EOF
    fi

    cat <<EOF >/usr/local/etc/fail2ban/jail.d/mongodb.conf
[mongodb-guard]
enabled  = true
port     = 27017
filter   = mongodb-guard
logpath  = /var/log/mongodb/mongod.log
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
