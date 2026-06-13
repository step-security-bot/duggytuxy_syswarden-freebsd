syswarden_jail_odoo() {
    # 1. Fail-Fast: Verify native daemon or process execution at the absolute top
    if ! service odoo onestatus >/dev/null 2>&1 2>/dev/null &&
        ! service odoo-server onestatus >/dev/null 2>&1 2>/dev/null &&
        ! pgrep -x "odoo" >/dev/null 2>&1 &&
        ! pgrep -x "odoo-bin" >/dev/null 2>&1; then
        return 0
    fi

    local ODOO_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/odoo/odoo-server.log" ]]; then
        ODOO_LOG="/var/log/odoo/odoo-server.log"
    elif [[ -f "/var/log/odoo/odoo.log" ]]; then
        ODOO_LOG="/var/log/odoo/odoo.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$ODOO_LOG" ]]; then
        return 0
    fi

    log "INFO" "Odoo ERP daemon and logs detected. Enabling Odoo Guard."

    # Create Filter for Odoo Authentication Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-odoo.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-odoo.conf
[Definition]
failregex = ^.*? \d+ INFO \S+ odoo\.addons\.base\.models\.res_users: Login failed for db:.*? login:.*? from <HOST>.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-odoo.conf
[syswarden-odoo]
enabled  = true
port     = http,https,8069
filter   = syswarden-odoo
logpath  = $ODOO_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
}
