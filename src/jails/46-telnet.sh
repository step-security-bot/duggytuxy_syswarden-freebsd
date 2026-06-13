syswarden_jail_telnet() {
    # 1. Fail-Fast: Verify telnet daemon presence or active Port 23 listening at the absolute top
    if ! command -v telnetd >/dev/null 2>&1 && ! ss -tlnp 2>/dev/null | grep -qE ':(23)\b'; then
        return 0
    fi

    local TELNET_LOG=""

    # 2. Dynamic log path discovery (Flattened structure based on OS family)
    if [[ -f "/var/log/auth-syswarden.log" ]]; then
        TELNET_LOG="/var/log/auth-syswarden.log"
    elif [[ -f "/var/log/auth.log" ]]; then
        TELNET_LOG="/var/log/auth.log"
    elif [[ -f "/var/log/messages" ]]; then
        TELNET_LOG="/var/log/messages" # Fallback
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$TELNET_LOG" ]]; then
        return 0
    fi

    log "INFO" "Telnet service detected on Port 23. Enabling IoT Botnet Guard."

    # Create Filter for Telnet Brute-force and IoT Botnet probing
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-telnet.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-telnet.conf
[Definition]
failregex = ^.*(?:in\.telnetd|telnetd)(?:\[\d+\])?: connect from (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+FAILED LOGIN.*(?:FROM|from) (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+.*(?:authentication failure|invalid password).*rhost=(?:::f{4}:)?<HOST>.*\s*$
            ^.*pam_unix\(login:auth\): authentication failure;.*rhost=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-telnet.conf
[syswarden-telnet]
enabled  = true
port     = 23,telnet
filter   = syswarden-telnet
logpath  = $TELNET_LOG
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 48h
EOF
}
