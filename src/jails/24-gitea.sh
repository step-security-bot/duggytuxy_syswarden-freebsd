syswarden_jail_gitea() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service gitea onestatus >/dev/null 2>&1 2>/dev/null && ! service forgejo onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local GITEA_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/gitea/gitea.log" ]]; then
        GITEA_LOG="/var/log/gitea/gitea.log"
    elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then
        GITEA_LOG="/var/log/forgejo/forgejo.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$GITEA_LOG" ]]; then
        return 0
    fi

    log "INFO" "Gitea/Forgejo daemon and logs detected. Enabling Git Server Jail."

    # Filter for Git Web UI Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/gitea-custom.conf
[Definition]
failregex = ^.*?Failed authentication attempt for .*? from <HOST>:.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/gitea.conf
[gitea-custom]
enabled  = true
port     = http,https,3000
filter   = gitea-custom
logpath  = $GITEA_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
