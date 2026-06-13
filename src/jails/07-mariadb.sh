syswarden_jail_mariadb() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service mariadb onestatus >/dev/null 2>&1 2>/dev/null && ! service mysql onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local MARIADB_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/mysql/error.log" ]]; then
        MARIADB_LOG="/var/log/mysql/error.log"
    elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then
        MARIADB_LOG="/var/log/mariadb/mariadb.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$MARIADB_LOG" ]]; then
        return 0
    fi

    log "INFO" "MariaDB/MySQL daemon and logs detected. Enabling MariaDB Jail."

    # Create Filter for Authentication Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/mariadb-auth.conf
[Definition]
failregex = ^.*? \[?(?:Note|Warning|ERROR)\]? [Aa]ccess denied for user .*?@'<HOST>'(?: \(using password: (?:YES|NO)\))?
ignoreregex = 
EOF
    fi

    cat <<EOF >/usr/local/etc/fail2ban/jail.d/mariadb.conf
[mariadb-auth]
enabled  = true
port     = 3306
filter   = mariadb-auth
logpath  = $MARIADB_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
