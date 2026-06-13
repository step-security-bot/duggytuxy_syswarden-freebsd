syswarden_jail_sso() {
    # 1. Fail-Fast: Verify native daemon or process execution at the absolute top
    # Accounts for both bare-metal FreeBSD services and containerized processes
    if ! service authelia onestatus >/dev/null 2>&1 2>/dev/null &&
        ! service authentik onestatus >/dev/null 2>&1 2>/dev/null &&
        ! pgrep -x "authelia" >/dev/null 2>&1 &&
        ! pgrep -f "authentik" >/dev/null 2>&1; then
        return 0
    fi

    local SSO_LOG=""

    # 2. Dynamic log path discovery (Flattened structure)
    if [[ -f "/var/log/authelia/authelia.log" ]]; then
        SSO_LOG="/var/log/authelia/authelia.log"
    elif [[ -f "/var/log/authentik/authentik.log" ]]; then
        SSO_LOG="/var/log/authentik/authentik.log"
    elif [[ -f "/opt/authelia/authelia.log" ]]; then
        SSO_LOG="/opt/authelia/authelia.log"
    elif [[ -f "/opt/authentik/authentik.log" ]]; then
        SSO_LOG="/opt/authentik/authentik.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$SSO_LOG" ]]; then
        return 0
    fi

    log "INFO" "SSO (Authelia/Authentik) processes and logs detected. Enabling IAM Guard."

    # Create Filter for Identity and Access Management credential stuffing
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-sso.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-sso.conf
[Definition]
failregex = ^.*(?:level=error|level=\"error\").*msg=\"Authentication failed\".*remote_ip=\"<HOST>\".*$
            ^.*(?:\"event\":\"Failed login\"|event=\'Failed login\').*(?:\"client_ip\":\"<HOST>\"|\"remote_ip\":\"<HOST>\").*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-sso.conf
[syswarden-sso]
enabled  = true
port     = http,https
filter   = syswarden-sso
logpath  = $SSO_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
