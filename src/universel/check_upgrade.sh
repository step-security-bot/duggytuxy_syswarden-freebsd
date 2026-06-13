check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Enterprise) - FreeBSD ===${NC}"

    local current_script
    current_script=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "${PWD}/${0#./}")

    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden-freebsd/releases/latest"
    local response

    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4 || true)

    if [[ -z "$latest_version" ]]; then
        echo -e "${RED}Failed to parse the latest version from GitHub API. Upgrade aborted.${NC}"
        return
    fi

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Enterprise version ($latest_version) is available!${NC}"

        if ! command -v git >/dev/null 2>&1; then
            echo -e "${RED}[ CRITICAL ALERT ] 'git' is not installed. Required for compilation.${NC}"
            echo -e "${YELLOW}Please run: pkg install -y git${NC}"
            return
        fi

        read -p "Do you want to proceed with the automated in-place upgrade now? (y/N): " proceed_upgrade
        if [[ ! "$proceed_upgrade" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrade aborted by user. System remains on $VERSION.${NC}"
            return
        fi

        echo -e "${YELLOW}Cloning and compiling update securely...${NC}"

        local UPGRADE_DIR="$TMP_DIR/syswarden_upgrade_payload"
        rm -rf "$UPGRADE_DIR"
        mkdir -p "$UPGRADE_DIR"

        if ! env GIT_TERMINAL_PROMPT=0 git clone -c core.askpass=true --branch "$latest_version" --depth 1 https://github.com/duggytuxy/syswarden-freebsd.git "$UPGRADE_DIR" >/dev/null 2>&1; then
            echo -e "${RED}[ CRITICAL ALERT ] Failed to clone the repository. Update aborted.${NC}"
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        cd "$UPGRADE_DIR" || exit 1

        log "INFO" "Executing SysWarden Universal Build..."
        /usr/local/bin/bash ./build.sh >/dev/null 2>&1 || {
            echo -e "${RED}[ CRITICAL ALERT ] Compilation failed. Update aborted.${NC}"
            cd /
            rm -rf "$UPGRADE_DIR"
            exit 1
        }

        local compiled_artifact="dist/install-syswarden.sh"

        if [[ ! -f "$compiled_artifact" ]] || ! head -n 1 "$compiled_artifact" | grep -q "bash"; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The compiled artifact is invalid or corrupted!${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            cd /
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        echo -e "${GREEN}Artifact compiled and validated successfully. Preparing in-place upgrade...${NC}"

        log "INFO" "Terminating existing SysWarden background processes safely..."
        pkill -15 -f syswarden-telemetry 2>/dev/null || true
        pkill -15 -f syswarden_reporter 2>/dev/null || true
        sleep 1
        pkill -9 -f syswarden-telemetry 2>/dev/null || true
        pkill -9 -f syswarden_reporter 2>/dev/null || true

        service syswarden_ui stop >/dev/null 2>&1 || true
        service syswarden_reporter stop >/dev/null 2>&1 || true

        log "INFO" "Replacing current orchestrator at $current_script..."

        cp -f "$compiled_artifact" "$current_script"
        chmod 700 "$current_script"

        if [[ ! -f "$CONF_FILE" ]]; then
            log "WARN" "Configuration file $CONF_FILE missing! The upgrade will behave as a fresh install."
        else
            log "INFO" "Configuration file $CONF_FILE found. User settings will be strictly preserved."
        fi

        cd /
        rm -rf "$UPGRADE_DIR"

        local STATE_BACKUP_DIR
        STATE_BACKUP_DIR=$(mktemp -d /tmp/syswarden_state_backup.XXXXXX)

        if [[ -f "/etc/syswarden/ui/data.json" ]]; then
            cp -f "/etc/syswarden/ui/data.json" "$STATE_BACKUP_DIR/data.json.bak"
        fi
        if [[ -f "/etc/syswarden/ui/osint_cache.txt" ]]; then
            cp -f "/etc/syswarden/ui/osint_cache.txt" "$STATE_BACKUP_DIR/osint_cache.txt.bak"
        fi

        echo -e "${GREEN}In-place upgrade sequence initiated. Executing the new version...${NC}"

        /usr/local/bin/bash "$current_script" update

        if [[ -d "$STATE_BACKUP_DIR" ]]; then
            mkdir -p /etc/syswarden/ui
            [[ -f "$STATE_BACKUP_DIR/data.json.bak" ]] && cp -f "$STATE_BACKUP_DIR/data.json.bak" /etc/syswarden/ui/data.json
            [[ -f "$STATE_BACKUP_DIR/osint_cache.txt.bak" ]] && cp -f "$STATE_BACKUP_DIR/osint_cache.txt.bak" /etc/syswarden/ui/osint_cache.txt
            rm -rf "$STATE_BACKUP_DIR"

            chown www:www /etc/syswarden/ui/data.json 2>/dev/null || true
            chmod 640 /etc/syswarden/ui/data.json 2>/dev/null || true
        fi
    fi
}
