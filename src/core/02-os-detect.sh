detect_os_backend() {
    log "INFO" "Detecting Operating System and Firewall Backend..."

    # --- HOTFIX: PREVENT BACKEND AMNESIA ---
    if [[ -f "$CONF_FILE" ]] && grep -q "FIREWALL_BACKEND=" "$CONF_FILE"; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Loaded saved Firewall Backend: $FIREWALL_BACKEND"
        return
    fi
    # ---------------------------------------

    OS=$(uname -s)
    if [ "$OS" = "FreeBSD" ]; then
        OS_ID="freebsd"
        FIREWALL_BACKEND="pf"
    else
        log "ERROR" "This version of SysWarden is exclusively for FreeBSD 14.4+."
        exit 1
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"

    # Save detection for future cron jobs
    echo "FIREWALL_BACKEND='$FIREWALL_BACKEND'" >>"$CONF_FILE"
}
