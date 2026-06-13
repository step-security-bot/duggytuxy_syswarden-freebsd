syswarden_jail_apache_tls() {
    # 1. Fail-Fast: Verify native daemon or process execution at the absolute top
    if ! command -v apache2 >/dev/null 2>&1 &&
        ! command -v httpd >/dev/null 2>&1 &&
        ! pgrep -x "apache2" >/dev/null 2>&1 &&
        ! pgrep -x "httpd" >/dev/null 2>&1; then
        return 0
    fi

    local APACHE_ERR_LOG=""

    # 2. Dynamic log path discovery based on OS family
    if [[ -f "/var/log/apache2/error.log" ]]; then
        APACHE_ERR_LOG="/var/log/httpd-error.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$APACHE_ERR_LOG" ]]; then
        return 0
    fi

    log "INFO" "Apache daemon and error logs detected. Enabling mod_ssl Protocol Guard."

    # Create Filter for Apache mod_ssl TLS Handshake failures, SNI mismatch, and mTLS bypass attempts
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-apache-tls.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-apache-tls.conf
[Definition]
# [DEVSECOPS FIX] Targets mod_ssl specific error codes (AH02033 for SNI bypass, AH02261/AH02008 for handshake/cert failures)
failregex = ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH\d+: .*?(?:certificate verify failed|SSL Library Error|handshake failed|SSL_accept failed|peer closed connection).*$
            ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] SSL Library Error: .*$
            ^.*? \[core:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH02033: No hostname was provided via SNI.*$
            ^.*? \[ssl:(?:error|warn)\].*? \[client <HOST>(?::\d+)?\] AH02039: Certificate Verification: Error.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-apache-tls.conf
[syswarden-apache-tls]
enabled  = true
port     = https,443,8443
filter   = syswarden-apache-tls
logpath  = $APACHE_ERR_LOG
backend  = auto
# Policy: 10 SSL errors in 1 minute indicates active TLS Fuzzing or massive direct IP scanning.
maxretry = 10
findtime = 60
bantime  = 24h
EOF
}
