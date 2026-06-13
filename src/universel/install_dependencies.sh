install_dependencies() {
    log "INFO" "Checking dependencies for FreeBSD..."
    local missing_common=()

    # ==============================================================================
    # --- HOTFIX: STATE TRACKER (Avoid God Mode Uninstall) ---
    if [[ ! -f "$CONF_FILE" ]]; then
        touch "$CONF_FILE"
        chmod 600 "$CONF_FILE"
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "FAIL2BAN_INSTALLED_BY_SYSWARDEN='y'" >>"$CONF_FILE"
    fi
    # ==============================================================================

    log "INFO" "Updating pkg repository..."
    pkg update -q

    if ! command -v curl >/dev/null; then missing_common+=("curl"); fi
    if ! command -v wget >/dev/null; then missing_common+=("wget"); fi
    if ! command -v python3 >/dev/null; then missing_common+=("python3"); fi
    if ! command -v whois >/dev/null; then missing_common+=("whois"); fi
    if ! command -v jq >/dev/null; then missing_common+=("jq"); fi
    if ! command -v openssl >/dev/null; then missing_common+=("openssl"); fi

    # WireGuard & QR-Code
    if ! command -v wg >/dev/null || ! command -v qrencode >/dev/null; then
        missing_common+=("wireguard-tools" "libqrencode")
    fi

    # Fail2ban
    if ! command -v fail2ban-client >/dev/null; then
        missing_common+=("fail2ban")
    fi

    if [[ ${#missing_common[@]} -gt 0 ]]; then
        log "INFO" "Installing required packages: ${missing_common[*]}"
        env ASSUME_ALWAYS_YES=YES pkg install -y "${missing_common[@]}"
    fi

    # Web Log pre-creation for Fail2ban
    if [ -d /usr/local/etc/nginx ] || command -v nginx >/dev/null 2>&1; then
        mkdir -p /var/log/nginx
        touch /var/log/nginx/access.log /var/log/nginx/error.log
        chmod 640 /var/log/nginx/*.log 2>/dev/null || true
    fi
    if [ -d /usr/local/etc/apache24 ] || command -v httpd >/dev/null 2>&1; then
        mkdir -p /var/log/httpd
        touch /var/log/httpd/access_log /var/log/httpd/error_log
        chmod 640 /var/log/httpd/*_log 2>/dev/null || true
    fi

    # Python Requests
    if ! python3 -c "import requests" 2>/dev/null; then
        log "INFO" "Installing py3-requests..."
        env ASSUME_ALWAYS_YES=YES pkg install -y py311-requests || env ASSUME_ALWAYS_YES=YES pkg install -y py3-requests || true
        if ! python3 -c "import requests" 2>/dev/null; then
            log "ERROR" "Failed to install Python requests. AbuseIPDB reporting may be disabled."
        fi
    fi

    # Ensure cron is enabled
    sysrc cron_enable=YES >/dev/null 2>&1
    service cron start >/dev/null 2>&1 || true

    log "INFO" "All dependencies check complete."
}
