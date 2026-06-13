setup_cron_autoupdate() {
    # No manuel cron update function
    if [[ "${1:-}" != "update" ]] && [[ "${1:-}" != "cron-update" ]]; then
        local origin_path
        origin_path=$(realpath "$0")
        local script_path="/usr/local/sbin/syswarden-cron-update"
        local cron_file="/etc/cron.d/syswarden-update"
        local random_min=$((RANDOM % 60))

        # Sécurisation du binaire (F-001)
        cp -f "$origin_path" "$script_path"
        chown root:root "$script_path"
        chmod 700 "$script_path"

        # FIX DEVSECOPS
        echo "$random_min * * * * root $script_path cron-update >/dev/null 2>&1" >"$cron_file"
        chmod 644 "$cron_file"

        log "INFO" "Automatic updates enabled."

        cat <<EOF >/etc/logrotate.d/syswarden
/var/log/kern.log
/var/log/messages
/var/log/messages
$LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        service syslogd reload >/dev/null 2>&1 || true
    endscript
}
EOF
    fi
}
