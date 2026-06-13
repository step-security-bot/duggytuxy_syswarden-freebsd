apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules (PF) ===${NC}"

    # --- LOCAL PERSISTENCE INJECTION ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE" "$F2B_BLOCKLIST_FILE"
    chmod 600 "$F2B_BLOCKLIST_FILE"

    # 1. Inject local blocklist and Fail2ban persistent list into the global list
    cat "$BLOCKLIST_FILE" >>"$FINAL_LIST"
    if [[ -s "$F2B_BLOCKLIST_FILE" ]]; then
        cat "$F2B_BLOCKLIST_FILE" >>"$FINAL_LIST"
    fi

    # [DEVSECOPS FIX] Strict Data Canonicalization
    grep -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$FINAL_LIST" >"$TMP_DIR/canonical_ips.txt" || true
    mv -f "$TMP_DIR/canonical_ips.txt" "$FINAL_LIST"

    # 2. Clean duplicates to ensure firewall stability
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"

    # 3. Exclude local whitelisted IPs from the final blocklist
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" >"$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi

    # Save the massive compiled list to disk so the telemetry engine can count it instantly
    cp "$FINAL_LIST" "$SYSWARDEN_DIR/active_global_blocklist.txt"

    log "INFO" "Configuring PF (Packet Filter)..."

    # 1. Start building the pf configuration file
    PF_CONF="/etc/pf.conf"
    PF_SYSWARDEN_CONF="/etc/syswarden/pf-syswarden.conf"
    mkdir -p /etc/syswarden

    # Detect active interface
    local ACTIVE_IF
    ACTIVE_IF=$(route -n get default | grep interface | awk '{print $2}')
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="em0"

    cat <<EOF >"$TMP_DIR/pf-syswarden.conf"
# SysWarden PF Ruleset
# ==============================================================

ext_if = "$ACTIVE_IF"

table <syswarden_blacklist> persist file "$FINAL_LIST"
table <syswarden_whitelist> persist file "$WHITELIST_FILE"
EOF

    if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
        echo "table <syswarden_geoip> persist file \"$GEOIP_FILE\"" >>"$TMP_DIR/pf-syswarden.conf"
    fi
    if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
        echo "table <syswarden_asn> persist file \"$ASN_FILE\"" >>"$TMP_DIR/pf-syswarden.conf"
    fi

    cat <<EOF >>"$TMP_DIR/pf-syswarden.conf"

# NAT for WireGuard
EOF

    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        echo "nat on \$ext_if from ${WG_SUBNET:-10.66.66.0/24} to any -> (\$ext_if)" >>"$TMP_DIR/pf-syswarden.conf"
    fi

    cat <<EOF >>"$TMP_DIR/pf-syswarden.conf"

# Default deny
block in log all

# Pass loopback
set skip on lo0

# Stateful handling
pass in all keep state
pass out all keep state

# Whitelist bypass
pass in quick from <syswarden_whitelist> to any

# Hardware Drops / Blacklists
block in quick from <syswarden_blacklist> to any
EOF

    if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
        echo "block in quick from <syswarden_geoip> to any" >>"$TMP_DIR/pf-syswarden.conf"
    fi
    if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
        echo "block in quick from <syswarden_asn> to any" >>"$TMP_DIR/pf-syswarden.conf"
    fi

    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        cat <<EOF >>"$TMP_DIR/pf-syswarden.conf"
# WireGuard rules
pass in quick on \$ext_if proto udp to port ${WG_PORT:-51820}
pass in quick on wg0
pass out quick on wg0
EOF
    fi

    # Ports
    local ALLOWED_TCP_PORTS="${SSH_PORT:-22}"
    if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
        ALLOWED_TCP_PORTS="${ALLOWED_TCP_PORTS},${ACTIVE_PORTS}"
    fi

    echo "pass in quick on \$ext_if proto tcp to port { $ALLOWED_TCP_PORTS }" >>"$TMP_DIR/pf-syswarden.conf"

    if [[ ",${ACTIVE_PORTS// /}," == *",443,"* ]]; then
        echo "pass in quick on \$ext_if proto udp to port 443" >>"$TMP_DIR/pf-syswarden.conf"
    fi

    cp "$TMP_DIR/pf-syswarden.conf" "$PF_SYSWARDEN_CONF"

    # Inject into main pf.conf if not there
    if ! grep -q 'include "/etc/syswarden/pf-syswarden.conf"' "$PF_CONF" 2>/dev/null; then
        echo "include \"/etc/syswarden/pf-syswarden.conf\"" >>"$PF_CONF"
    fi

    # Enable and start PF
    sysrc pf_enable=YES >/dev/null 2>&1
    sysrc pflog_enable=YES >/dev/null 2>&1
    service pf start >/dev/null 2>&1 || true
    service pflog start >/dev/null 2>&1 || true

    # Reload rules
    pfctl -f /etc/pf.conf >/dev/null 2>&1 || true

    # WireGuard IP Forwarding
    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        sysctl net.inet.ip.forwarding=1 >/dev/null 2>&1 || true
        echo "net.inet.ip.forwarding=1" >>/etc/sysctl.conf
    fi

    log "INFO" "PF rules applied."
}
