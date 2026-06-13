syswarden_jail_vsftpd() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! service vsftpd onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/vsftpd.log" ]]; then
        return 0
    fi

    log "INFO" "VSFTPD daemon and logs detected. Enabling FTP Jail."

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/vsftpd.conf
[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,20,21
logpath  = /var/log/vsftpd.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
