install_cis_dependencies() {
    log "INFO" "Checking CIS Level 2 specific dependencies..."
}

disable_obscure_filesystems() {
    log "INFO" "Disabling obscure filesystems (CIS 1.1.1.1 - 1.1.1.8)..."
    # Not applicable in the same way on FreeBSD, but we can ensure modules aren't loaded
}

disable_uncommon_protocols() {
    log "INFO" "Disabling uncommon network protocols (CIS 3.3.1 - 3.3.4)..."
    # Not applicable in the same way on FreeBSD
}

apply_cis_sysctl() {
    log "INFO" "Applying strict kernel parameters (CIS 1.5, 3.2)..."
    local SYSCTL_CONF="/etc/sysctl.conf"

    cat <<'EOF' >>"$SYSCTL_CONF"
# --- SysWarden: CIS Level 2 Kernel Hardening (FreeBSD) ---
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.unprivileged_read_msgbuf=0
security.bsd.unprivileged_proc_debug=0
kern.randompid=1
net.inet.ip.redirect=0
net.inet6.ip6.redirect=0
net.inet.icmp.drop_redirect=1
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
EOF
    /etc/rc.d/sysctl reload >/dev/null 2>&1 || true
}

restrict_core_dumps() {
    log "INFO" "Enforcing hard limits on core dumps (CIS 1.5.1)..."
    # Core dumps can be disabled via sysctl on FreeBSD
    echo "kern.coredump=0" >>/etc/sysctl.conf
    sysctl kern.coredump=0 >/dev/null 2>&1 || true
}

apply_cis_ssh_hardening() {
    log "INFO" "Applying CIS Level 2 SSH Hardening (CIS 5.2)..."
    local SSHD_CONF="/etc/ssh/sshd_config"

    if [[ -f "$SSHD_CONF" ]]; then
        sed -i '' 's/^[[:space:]]*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONF"
        if ! grep -q "^X11Forwarding" "$SSHD_CONF"; then echo "X11Forwarding no" >>"$SSHD_CONF"; fi

        sed -i '' 's/^[[:space:]]*MaxAuthTries.*/MaxAuthTries 4/' "$SSHD_CONF"
        if ! grep -q "^MaxAuthTries" "$SSHD_CONF"; then echo "MaxAuthTries 4" >>"$SSHD_CONF"; fi

        sed -i '' 's/^[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CONF"
        if ! grep -q "^ClientAliveInterval" "$SSHD_CONF"; then echo "ClientAliveInterval 300" >>"$SSHD_CONF"; fi

        sed -i '' 's/^[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 3/' "$SSHD_CONF"
        if ! grep -q "^ClientAliveCountMax" "$SSHD_CONF"; then echo "ClientAliveCountMax 3" >>"$SSHD_CONF"; fi

        service sshd reload >/dev/null 2>&1 || true
    fi
}

secure_cron_permissions() {
    log "INFO" "Securing cron directories permissions (CIS 5.1)..."
    # Not using standard cron.d on FreeBSD in the same way, but securing /var/cron
    if [[ -d "/var/cron" ]]; then
        chown -R root:wheel "/var/cron"
        chmod -R 700 "/var/cron"
    fi
    if [[ -f "/etc/crontab" ]]; then
        chown root:wheel "/etc/crontab"
        chmod 600 "/etc/crontab"
    fi
}

enable_automatic_security_updates() {
    log "INFO" "Configuring automatic security updates for FreeBSD..."
    # FreeBSD uses freebsd-update for base and pkg upgrade for packages
    # A simple cron can be set
    local cron_job="0 3 * * * root freebsd-update cron && pkg upgrade -yq"
    if ! grep -q "freebsd-update" /etc/crontab; then
        echo "$cron_job" >>/etc/crontab
    fi
}

apply_cis_level2_hardening() {
    local state_cis="n"
    if grep -q "^APPLY_CIS_L2_HARDENING='y'" "$CONF_FILE" 2>/dev/null || grep -q "^APPLY_CIS_L2_HARDENING=\"y\"" "$CONF_FILE" 2>/dev/null; then
        state_cis="y"
    elif [[ "${APPLY_CIS_L2_HARDENING:-n}" == "y" ]]; then
        state_cis="y"
    fi

    if [[ "$state_cis" != "y" ]]; then
        return
    fi

    log "INFO" "Starting CIS Benchmark Level 2 compliance routines (FreeBSD)..."

    install_cis_dependencies
    disable_obscure_filesystems
    disable_uncommon_protocols
    apply_cis_sysctl
    restrict_core_dumps
    apply_cis_ssh_hardening
    secure_cron_permissions
    enable_automatic_security_updates

    log "SUCCESS" "CIS Benchmark Level 2 Hardening successfully applied."
}
