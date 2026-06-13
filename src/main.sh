MODE="${1:-install}"

if [[ -f "${1:-}" ]]; then
    echo -e "${GREEN}>>> Unattended configuration file detected: $1${NC}"
    chmod 600 "$1"

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*#.*$ || -z "$line" ]] && continue

        if [[ "$line" =~ ^(SYSWARDEN_[A-Z0-9_]+|APPLY_CIS_L2_HARDENING)=\"([a-zA-Z0-9_./: ,-?&=@%*]*)\"$ ]]; then
            export "${BASH_REMATCH[1]}"="${BASH_REMATCH[2]}"
        else
            echo -e "${RED}[!] ERROR: Configuration poisoning detected or invalid format at line: $line${NC}"
            exit 1
        fi
    done <"$1"

    MODE="auto"
elif [[ "$MODE" == "--auto" ]]; then
    MODE="auto"
fi

if [[ "$MODE" == "tui" ]] || [[ "$MODE" == "dashboard" ]]; then
    if [[ -x "/usr/local/bin/syswarden-tui" ]]; then
        exec /usr/local/bin/syswarden-tui
    else
        echo -e "${RED}[!] TUI Engine not found. Please run the installation or update first.${NC}"
        exit 1
    fi
fi

if [[ "$MODE" == "whitelist" ]]; then
    check_root
    detect_os_backend
    whitelist_ip
    exit 0
fi

if [[ "$MODE" == "blocklist" ]]; then
    check_root
    detect_os_backend
    blocklist_ip
    exit 0
fi

if [[ "$MODE" == "wireguard-client" ]]; then
    check_root
    add_wireguard_client
    exit 0
fi

if [[ "$MODE" == "protect-docker" ]]; then
    check_root
    protect_docker_jail
    exit 0
fi

if [[ "$MODE" == "fail2ban-jails" ]]; then
    check_root
    detect_os_backend

    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${GREEN}SysWarden - Fail2ban Jails Auto-Discovery & Reload${NC}"
    echo -e "${BLUE}======================================================================${NC}"

    if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log "INFO" "Configuration loaded successfully."
    else
        log "ERROR" "Configuration file ($CONF_FILE) not found. Please install SysWarden first."
        exit 1
    fi

    log "INFO" "Scanning system for active services and web applications..."
    discover_active_services 2>/dev/null || true
    discover_web_apps
    configure_fail2ban

    if [[ ! -f /var/log/fail2ban.log ]]; then
        touch /var/log/fail2ban.log
        chmod 640 /var/log/fail2ban.log
        chown root:wheel /var/log/fail2ban.log 2>/dev/null || true
    fi

    log "INFO" "Restarting Fail2ban to apply new jails..."
    service fail2ban restart 2>/dev/null || true

    sleep 5

    echo -e "\n${GREEN}[+] Fail2ban jails successfully updated! Active jails:${NC}"
    fail2ban-client status
    exit 0
fi

if [[ "$MODE" == "alerts" ]]; then
    check_root
    show_alerts_dashboard
    exit 0
fi

if [[ "$MODE" == "upgrade" ]]; then
    check_root
    check_upgrade
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    check_root
    detect_os_backend
    uninstall_syswarden
fi

if [[ "$MODE" == "cron-update" ]]; then
    log "INFO" "Starting silent CRON update (Threat Intelligence only)..."
    check_root
    detect_os_backend

    if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
    else
        log "ERROR" "Config file missing. Aborting cron update."
        exit 1
    fi

    select_list_type "update"
    select_mirror "update"
    download_list
    download_osint
    download_geoip
    download_asn

    discover_active_services
    discover_web_apps
    setup_wireguard
    apply_firewall_rules

    log "INFO" "CRON Update Complete. Firewall rules refreshed securely."
    exit 0
fi

if [[ "$MODE" != "update" ]] && [[ "$MODE" != "uninstall" ]]; then
    clear
    echo -e "${YELLOW}===================================================================================${NC}"
    echo -e "${BLUE} ██████╗██╗   ██╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗${NC}"
    echo -e "${BLUE}██╔════╝╚██╗ ██╔╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║${NC}"
    echo -e "${BLUE}███████╗ ╚████╔╝ ███████╗██║ █╗ ██║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║${NC}"
    echo -e "${BLUE}╚════██║  ╚██╔╝  ╚════██║██║███╗██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║${NC}"
    echo -e "${BLUE}███████║   ██║   ███████║╚███╔███╔╝██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║${NC}"
    echo -e "${BLUE}╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝${NC}"
    echo -e "${YELLOW}===================================================================================${NC}"
    echo -e "${BLUE}               HIDS & HIPS for Critical FreeBSD Infrastructure. | v1.00.2                  ${NC}"
    echo -e "${YELLOW}===================================================================================${NC}\n"
fi

check_root
detect_os_backend

auto_whitelist_admin
process_auto_whitelist "$MODE"
auto_whitelist_infra "$MODE"

touch "$CONF_FILE" "$LOG_FILE" 2>/dev/null || true
chmod 600 "$CONF_FILE" 2>/dev/null || true
chmod 640 "$LOG_FILE" 2>/dev/null || true

if [[ "$MODE" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"

    if ! grep -q "SYSWARDEN_ENABLE_WEBHOOK" "$CONF_FILE"; then
        log "INFO" "Migrating configuration: Injecting Webhook parameters into $CONF_FILE"
        {
            echo -e "\n# --- WebHook Notifications (Discord / Teams) ---"
            echo -e "SYSWARDEN_ENABLE_WEBHOOK=\"n\""
            echo -e "SYSWARDEN_WEBHOOK_URL_DISCORD=\"\""
            echo -e "SYSWARDEN_WEBHOOK_URL_TEAMS=\"\""
        } >>"$CONF_FILE"
    fi
fi

if [[ "$MODE" != "update" ]]; then
    : >"$CONF_FILE"
    install_dependencies

    detect_os_backend

    if [[ "$MODE" != "auto" ]]; then
        BOLD='\033[1m'
        CYAN='\033[0;36m'
        clear
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v1.00.2 - PRE-FLIGHT CHECKLIST                     ${NC}"
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "Before proceeding with the deployment, please ensure you have the following"
        echo -e "information ready. If you lack any required data, press [Ctrl+C] to abort,"
        echo -e "gather the info, and restart the script.\n"

        echo -e "${BOLD}1. SSH CONFIGURATION${NC}"
        echo -e "   You will need to confirm the custom SSH port used to connect to this server."

        echo -e "\n${BOLD}2. FIREWALL ENGINE OPTIMIZATION${NC}"
        echo -e "   pf (Packet Filter) is automatically enabled for native BSD routing."

        echo -e "\n${BOLD}3. WIREGUARD VPN${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Decide if you need a stealth admin VPN. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}4. DOCKER INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires Layer 3 routing adjustments for containers and multi-tenant WAF log paths."
        echo -e "   (e.g., /var/log/modsec/*.log). If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}5. OS HARDENING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Strict restrictions for privileged groups (Wheel) & Cron. Recommended for NEW servers only."

        echo -e "\n${BOLD}6. CIS BENCHMARK LEVEL 2${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Advanced Defense-in-Depth (Filesystem, Kernel, Network). Recommended for production."

        echo -e "\n${BOLD}7. GEOIP BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   ISO country codes to drop instantly (e.g., RU,CN,KP)."

        echo -e "\n${BOLD}8. ASN BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Target Autonomous System Numbers to drop (e.g., AS1234, AS5678)."

        echo -e "\n${BOLD}9. HA CLUSTER SYNC${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Standby Node IP for automatic threat intelligence replication."

        echo -e "\n${BOLD}10. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] Disabled"

        echo -e "\n${BOLD}11. SIEM LOG FORWARDING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   External SIEM IP, Port (Default: 6514), and Protocol for central log auditing."
        echo -e "   Required for strict ISO 27001 / NIS2 compliance."

        echo -e "\n${BOLD}12. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."

        echo -e "\n${BOLD}13. WEBHOOK NOTIFICATIONS${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Securely forwards Fail2ban L7 blocks (e.g., ModSecurity) to Discord or MS Teams."

        echo -e "\n${BOLD}14. WAZUH SIEM AGENT${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Required: Manager IP, Enrollment Port (1515), Listen Port (1514)."

        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        read -p "$(echo -e "${YELLOW}Press [ENTER] to begin the configuration, or [Ctrl+C] to abort... ${NC}")"
        echo ""
        log "INFO" "Pre-Flight Checklist acknowledged. Starting interactive configuration..."
    fi

    define_ssh_port "$MODE"
    define_firewall_engine "$MODE"
    define_wireguard "$MODE"
    define_docker_integration "$MODE"
    define_os_hardening "$MODE"
    define_cis_hardening "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
    define_ha_cluster "$MODE"
    define_webhook "$MODE"

    setup_siem_logging "$MODE"

    if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
    fi

    discover_web_apps
    configure_fail2ban
fi

select_list_type "$MODE"
select_mirror "$MODE"
download_list
download_osint

if [[ "$MODE" != "update" ]]; then
    discover_active_services
    discover_web_apps
    apply_firewall_rules
fi

download_geoip
download_asn

log "INFO" "Applying massive downloaded lists to active firewall..."
discover_active_services
discover_web_apps
apply_firewall_rules

log "INFO" "Applying Layer 7 Application Firewall Rules (Fail2ban)..."
configure_fail2ban

if [[ "${USE_DOCKER:-n}" == "y" ]] && [[ -n "${DOCKER_JAILS:-}" ]]; then
    log "INFO" "Routing multi-tenant Docker Jails ($DOCKER_JAILS) to Layer 3..."
    protect_docker_jail "auto"
fi

detect_protected_services

if sysrc -n syswarden_reporter_enable | grep -qi yes; then
    log "INFO" "Restarting SysWarden Unified Reporter..."
    service syswarden_reporter restart >/dev/null 2>&1 || true
fi

setup_telemetry_backend
generate_dashboard

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"

    apply_os_hardening
    apply_cis_level2_hardening

    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> List loaded: $LIST_TYPE"

    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Universal (Interactive)"
    fi

    echo -e " -> Protection: Active"

    display_wireguard_qr
else
    if [[ -f /etc/crontab ]]; then
        sed -i '' 's/\.sh update >/\.sh cron-update >/g' /etc/crontab 2>/dev/null || true
    fi

    service cron restart 2>/dev/null || true

    log "INFO" "Restarting Fail2ban engine to compile new definitions..."
    service fail2ban restart >/dev/null 2>&1 || true

    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
    echo -e " -> SysWarden Engine (L2/L3/L4 & L7) and Dashboard TUI have been updated to the latest version."
fi
