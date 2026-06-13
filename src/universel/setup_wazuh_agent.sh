setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (FreeBSD) ===${NC}"

    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_WAZUH:-n}
        log "INFO" "Auto Mode: Wazuh Agent choice loaded via env var [${response}]"
    else
        read -p "Install Wazuh Agent? (y/N): " response
    fi

    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping Wazuh Agent installation."
        return
    fi

    if [[ "${1:-}" == "auto" ]]; then
        WAZUH_IP=${SYSWARDEN_WAZUH_IP:-""}
        W_NAME=${SYSWARDEN_WAZUH_NAME:-$(hostname)}
        W_GROUP=${SYSWARDEN_WAZUH_GROUP:-default}
        W_PORT_COMM=${SYSWARDEN_WAZUH_COMM_PORT:-1514}
        W_PORT_ENROLL=${SYSWARDEN_WAZUH_ENROLL_PORT:-1515}

        if [[ -n "$WAZUH_IP" && ! "$WAZUH_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && ! "$WAZUH_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            log "ERROR" "Auto Mode: Invalid WAZUH_IP format. Skipping Wazuh installation."
            return
        fi
        if ! [[ "$W_PORT_COMM" =~ ^[0-9]+$ ]] || [ "$W_PORT_COMM" -lt 1 ] || [ "$W_PORT_COMM" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_COMM. Defaulting to 1514."
            W_PORT_COMM=1514
        fi
        if ! [[ "$W_PORT_ENROLL" =~ ^[0-9]+$ ]] || [ "$W_PORT_ENROLL" -lt 1 ] || [ "$W_PORT_ENROLL" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_ENROLL. Defaulting to 1515."
            W_PORT_ENROLL=1515
        fi
        log "INFO" "Auto Mode: Wazuh settings loaded via env vars."
    else
        read -p "Enter Wazuh Manager IP: " WAZUH_IP
        if [[ -z "$WAZUH_IP" ]]; then
            log "ERROR" "Missing IP. Skipping."
            return
        fi

        read -p "Agent Name [Press Enter for '$(hostname)']: " W_NAME
        W_NAME=${W_NAME:-$(hostname)}

        read -p "Agent Group [Press Enter for 'default']: " W_GROUP
        W_GROUP=${W_GROUP:-default}

        read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
        W_PORT_COMM=${W_PORT_COMM:-1514}

        read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
        W_PORT_ENROLL=${W_PORT_ENROLL:-1515}
    fi

    W_NAME=$(echo "$W_NAME" | tr -cd 'a-zA-Z0-9.-')
    W_GROUP=$(echo "$W_GROUP" | tr -cd 'a-zA-Z0-9_-')

    if [[ -z "$WAZUH_IP" ]]; then
        log "ERROR" "Missing Wazuh IP. Skipping."
        return
    fi

    W_PROTO="TCP"

    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on ports $W_PORT_COMM & $W_PORT_ENROLL..."
    if [[ -f "/etc/pf.conf" ]]; then
        if ! grep -q "pass in quick from $WAZUH_IP" /etc/pf.conf; then
            echo "pass in quick from $WAZUH_IP to any port { $W_PORT_COMM, $W_PORT_ENROLL }" >>/etc/pf.conf
            pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        fi
    fi

    log "INFO" "Starting Wazuh Agent installation..."

    export WAZUH_MANAGER="$WAZUH_IP"
    export WAZUH_AGENT_NAME="$W_NAME"
    export WAZUH_AGENT_GROUP="$W_GROUP"
    export WAZUH_MANAGER_PORT="$W_PORT_COMM"
    export WAZUH_REGISTRATION_PORT="$W_PORT_ENROLL"
    export WAZUH_PROTOCOL="$W_PROTO"

    pkg install -y wazuh-agent

    if pkg info wazuh-agent >/dev/null 2>&1; then
        sysrc wazuh_agent_enable=YES
        service wazuh-agent start >/dev/null 2>&1 || true

        echo "WAZUH_IP='$WAZUH_IP'" >>"$CONF_FILE"
        echo "WAZUH_AGENT_NAME='$W_NAME'" >>"$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >>"$CONF_FILE"
        echo "WAZUH_ENROLL_PORT='$W_PORT_ENROLL'" >>"$CONF_FILE"

        log "INFO" "Wazuh Agent '$W_NAME' installed (Group: $W_GROUP, Ports: $W_PORT_COMM/$W_PORT_ENROLL)."
    else
        log "ERROR" "Wazuh Agent installation seemed to fail."
    fi
}
