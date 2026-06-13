define_firewall_engine() {
    local mode="$1"

    if [[ "$mode" == "update" ]]; then return; fi

    log "INFO" "Enabling pure pf (Packet Filter) for FreeBSD..."
    sysrc pf_enable=YES >/dev/null 2>&1
    sysrc pflog_enable=YES >/dev/null 2>&1

    FIREWALL_BACKEND="pf"
    sed -i '' '/^FIREWALL_BACKEND=/d' "$CONF_FILE" 2>/dev/null || true
    echo "FIREWALL_BACKEND='pf'" >>"$CONF_FILE"
}
