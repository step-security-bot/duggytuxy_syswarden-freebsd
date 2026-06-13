setup_wireguard() {
    if [[ "${USE_WIREGUARD:-n}" != "y" ]]; then
        if service wireguard onestatus >/dev/null 2>&1; then
            log "INFO" "Disabling WireGuard VPN as per configuration..."
            service wireguard stop >/dev/null 2>&1 || true
            sysrc wireguard_enable=NO >/dev/null 2>&1 || true
            rm -f /usr/local/etc/wireguard/wg0.conf
        fi
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring WireGuard VPN (FreeBSD) ===${NC}"

    if [[ -f "/usr/local/etc/wireguard/wg0.conf" ]]; then
        log "INFO" "WireGuard configuration already exists. Skipping key generation to prevent VPN lockout."
        return
    fi

    log "INFO" "Initializing WireGuard cryptographic engine..."

    mkdir -p /usr/local/etc/wireguard/clients
    chmod 700 /usr/local/etc/wireguard
    chmod 700 /usr/local/etc/wireguard/clients

    log "INFO" "Enabling Kernel IPv4 Forwarding..."
    sed -i '' '/net.inet.ip.forwarding=1/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.inet.ip.forwarding=1" >>/etc/sysctl.conf
    /etc/rc.d/sysctl reload >/dev/null 2>&1 || true

    local SERVER_PRIV
    SERVER_PRIV=$(wg genkey)
    local SERVER_PUB
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    local CLIENT_PRIV
    CLIENT_PRIV=$(wg genkey)
    local CLIENT_PUB
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    local PRESHARED_KEY
    PRESHARED_KEY=$(wg genpsk)

    local ACTIVE_IF
    ACTIVE_IF=$(route -n get default | grep interface | awk '{print $2}')
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="em0"

    local SERVER_IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
        curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null ||
        curl -4 -s --connect-timeout 3 icanhazip.com 2>/dev/null ||
        ifconfig "$ACTIVE_IF" | grep -Eo 'inet [0-9.]+' | awk '{print $2}' | head -n 1)

    local SUBNET_BASE
    SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
    local SERVER_VPN_IP="${SUBNET_BASE}.1"
    local CLIENT_VPN_IP="${SUBNET_BASE}.2"

    local POSTUP=""
    local POSTDOWN=""

    (
        umask 077

        log "INFO" "Deploying WireGuard Server Profile..."
        cat <<EOF >/usr/local/etc/wireguard/wg0.conf
# SysWarden WireGuard Server Configuration
[Interface]
Address = ${SERVER_VPN_IP}/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

[Peer]
# Admin Workstation Client
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF

        log "INFO" "Generating Secure Client Profile..."
        cat <<EOF >/usr/local/etc/wireguard/clients/admin-pc.conf
[Interface]
PrivateKey = $CLIENT_PRIV
Address = ${CLIENT_VPN_IP}/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    )

    chmod 600 /usr/local/etc/wireguard/clients/admin-pc.conf

    log "INFO" "Starting WireGuard Tunnel Interface (wg0)..."
    sysrc wireguard_enable="YES" >/dev/null 2>&1
    sysrc wireguard_interfaces="wg0" >/dev/null 2>&1
    service wireguard restart >/dev/null 2>&1 || true

    log "INFO" "WireGuard VPN deployed successfully."
    umask 022
}
