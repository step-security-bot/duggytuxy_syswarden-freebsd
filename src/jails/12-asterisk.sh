syswarden_jail_asterisk() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service asterisk onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local ASTERISK_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/asterisk/messages" ]]; then
        ASTERISK_LOG="/var/log/asterisk/messages"
    elif [[ -f "/var/log/asterisk/full" ]]; then
        ASTERISK_LOG="/var/log/asterisk/full"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$ASTERISK_LOG" ]]; then
        return 0
    fi

    log "INFO" "Asterisk daemon and logs detected. Enabling VoIP Jail."

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/asterisk.conf
[asterisk]
enabled  = true
filter   = asterisk
port     = 5060,5061
logpath  = $ASTERISK_LOG
maxretry = 5
bantime  = 24h
EOF
}
