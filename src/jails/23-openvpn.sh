syswarden_jail_openvpn() {
    # 1. Fail-Fast: Verify process or daemon execution at the absolute top
    if ! pgrep -x "openvpn" >/dev/null 2>&1 && ! service openvpn onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local OVPN_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
        OVPN_LOG="/var/log/openvpn/openvpn.log"
    elif [[ -f "/var/log/openvpn.log" ]]; then
        OVPN_LOG="/var/log/openvpn.log"
    elif [[ -f "/var/log/messages" ]]; then
        OVPN_LOG="/var/log/messages"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$OVPN_LOG" ]]; then
        return 0
    fi

    log "INFO" "OpenVPN daemon and logs detected. Enabling OpenVPN Jail."

    # Filter for OpenVPN TLS Handshake & Verification Errors
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/openvpn-custom.conf
[Definition]
failregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/openvpn.conf
[openvpn-custom]
enabled  = true
port     = 1194
protocol = udp
filter   = openvpn-custom
logpath  = $OVPN_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
