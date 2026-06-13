syswarden_jail_postfix() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service postfix onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local POSTFIX_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/mail.log" ]]; then
        POSTFIX_LOG="/var/log/mail.log"
    elif [[ -f "/var/log/maillog" ]]; then
        POSTFIX_LOG="/var/log/maillog"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$POSTFIX_LOG" ]]; then
        return 0
    fi

    log "INFO" "Postfix daemon and logs detected. Enabling SMTP Jails."

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/postfix.conf
[postfix]
enabled  = true
mode     = aggressive
port     = smtp,465,submission
logpath  = $POSTFIX_LOG
backend  = auto

[postfix-sasl]
enabled  = true
port     = smtp,465,submission
logpath  = $POSTFIX_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
