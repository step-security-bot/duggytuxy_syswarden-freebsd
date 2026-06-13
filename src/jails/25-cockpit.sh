syswarden_jail_cockpit() {
    # 1. Fail-Fast: Verify native socket execution or config presence at the absolute top
    if ! service cockpit onestatus >/dev/null 2>&1.socket 2>/dev/null && [[ ! -d "/etc/cockpit" ]]; then
        return 0
    fi

    local COCKPIT_LOG=""
    local JAIL_BACKEND="${SYSW_OS_BACKEND:-auto}"

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/secure" ]]; then
        COCKPIT_LOG="/var/log/messages"
    fi

    if [[ -z "$COCKPIT_LOG" ]]; then
        return 0
    fi

    log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."

    # Force overwrite on deployment to ensure filter updates are applied during upgrades
    cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
# Purified ultra-compatible patterns matching both syslog files and syslog streams
failregex = pam_unix\(cockpit:auth\): authentication failure;.* rhost=(?:::ffff:)?<HOST>
            (?:authentication failed|invalid user).*?from (?:::ffff:)?<HOST>
ignoreregex = 
EOF

    # 4. Generate jail configuration depending on the selected backend engine
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/cockpit.conf
[cockpit-custom]
enabled  = true
port     = 9090
filter   = cockpit-custom
logpath  = $COCKPIT_LOG
backend  = $JAIL_BACKEND
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
}
