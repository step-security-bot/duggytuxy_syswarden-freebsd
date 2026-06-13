syswarden_jail_auditd() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service auditd onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local AUDIT_LOG="/var/log/audit/audit.log"

    # 2. Fail-Fast: Ensure audit logs exist to prevent Fail2ban crash
    if [[ ! -f "$AUDIT_LOG" ]]; then
        return 0
    fi

    log "INFO" "Auditd daemon and logs detected. Enabling System Integrity Guard."

    # Create Filter for Auditd failure events
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-auditd.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-auditd.conf
[syswarden-auditd]
enabled  = true
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
bantime  = 24h
EOF
}
