syswarden_jail_jenkins() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service jenkins onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/jenkins/jenkins.log" ]]; then
        return 0
    fi

    log "INFO" "Jenkins CI/CD daemon and logs detected. Enabling Jenkins Guard."

    # Create Filter for Jenkins Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-jenkins.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-jenkins.conf
[syswarden-jenkins]
enabled  = true
port     = http,https,8080
filter   = syswarden-jenkins
logpath  = /var/log/jenkins/jenkins.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
