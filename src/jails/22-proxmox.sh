syswarden_jail_proxmox() {
    # 1. Fail-Fast: Verify hypervisor API daemon at the absolute top
    if ! service pveproxy onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local PVE_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/daemon.log" ]]; then
        PVE_LOG="/var/log/daemon.log"
    elif [[ -f "/var/log/messages" ]]; then
        PVE_LOG="/var/log/messages"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$PVE_LOG" ]]; then
        return 0
    fi

    log "INFO" "Proxmox VE hypervisor and logs detected. Enabling PVE Jail."

    # Filter for Proxmox Web GUI Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/proxmox-custom.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/proxmox-custom.conf
[Definition]
failregex = ^.*pvedaemon\[\d+\]: authentication failure; rhost=<HOST> user=.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/proxmox.conf
[proxmox-custom]
enabled  = true
port     = https,8006
filter   = proxmox-custom
logpath  = $PVE_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
