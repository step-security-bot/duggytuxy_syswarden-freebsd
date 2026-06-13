apply_os_hardening() {
    if [[ "${APPLY_OS_HARDENING:-n}" != "y" ]]; then
        return
    fi

    log "INFO" "Applying strict OS hardening (Crontab, Wheel, Profiles)..."

    # 1. Lock down Crontab (Only root can schedule tasks)
    mkdir -p /var/cron
    echo "root" >/var/cron/allow
    chmod 600 /var/cron/allow
    rm -f /var/cron/deny 2>/dev/null || true

    # 2. Backup and Purge non-root users from privileged groups (wheel)
    mkdir -p "$SYSWARDEN_DIR"

    # Cascade detection to reliably identify the authenticating user even if 'su -' was used
    local current_admin="${SUDO_USER:-}"
    if [[ -z "$current_admin" ]]; then
        current_admin=$(logname 2>/dev/null || true)
    fi
    if [[ -z "$current_admin" ]]; then
        current_admin=$(who am i | awk '{print $1}' 2>/dev/null || true)
    fi

    # shellcheck disable=SC2043
    for grp in wheel; do
        if pw group show "$grp" >/dev/null 2>&1; then
            # Backup current members
            local members
            members=$(pw group show "$grp" | cut -d: -f4)
            if [[ -n "$members" && "$members" != "root" ]]; then
                echo "${grp}:${members}" >>"$SYSWARDEN_DIR/group_backup.txt"
            fi

            # Purge non-root users
            for user in $(echo "$members" | tr ',' ' ' 2>/dev/null); do
                if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                    # --- SAFEGUARD: Never purge the executing admin ---
                    if [[ -n "$current_admin" ]] && [[ "$user" == "$current_admin" ]]; then
                        log "INFO" "SAFEGUARD: Preserving current admin '$user' in '$grp' group."
                        continue
                    fi
                    pw groupmod "$grp" -d "$user" >/dev/null 2>&1 || true
                    log "INFO" "Removed user '$user' from '$grp' group."
                fi
            done
        fi
    done

    # 3. Lock down profiles for standard users (Prevents SSH Login backdoors)
    for user_dir in /home/* /usr/home/*; do
        if [[ -d "$user_dir" ]]; then
            local user_name
            user_name=$(basename "$user_dir")
            # Preserve current admin's profile to avoid breaking their active SSH session
            if [[ -n "$current_admin" ]] && [[ "$user_name" == "$current_admin" ]]; then
                continue
            fi
            for profile_file in "$user_dir/.profile" "$user_dir/.shrc" "$user_dir/.cshrc" "$user_dir/.login"; do
                if [[ -f "$profile_file" ]]; then
                    chflags noschg "$profile_file" 2>/dev/null || true
                    chown "$user_name:$user_name" "$profile_file" 2>/dev/null || chown "$user_name:wheel" "$profile_file" 2>/dev/null || true
                    chmod 644 "$profile_file"
                    chflags schg "$profile_file" 2>/dev/null || true
                fi
            done
        fi
    done

    # 4. Log Anti-Forging & CRLF Mitigation (Syslogd)
    log "INFO" "Applying strict anti-forging rules to system logging daemons..."

    # FreeBSD syslogd Hardening: ensure it drops secure events properly and is properly secured
    sysrc syslogd_flags="-ss" >/dev/null 2>&1 || true
    service syslogd restart >/dev/null 2>&1 || true

    # 5. Restrict Auth Log Permissions
    if [[ -f "/var/log/auth.log" ]]; then
        chmod 0640 /var/log/auth.log
        chown root:wheel /var/log/auth.log 2>/dev/null || true
    fi
}
