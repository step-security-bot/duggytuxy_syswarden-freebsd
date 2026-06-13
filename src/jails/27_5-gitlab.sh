syswarden_jail_gitlab() {
    # 1. Fail-Fast: Verify native FreeBSD service at the absolute top
    if ! command -v gitlab-ctl >/dev/null 2>&1 && ! service gitlab-runsvdir onestatus >/dev/null 2>&1 2>/dev/null; then
        return 0
    fi

    local GITLAB_LOG=""

    # 2. Dynamic log path discovery
    if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
        GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
    elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then
        GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$GITLAB_LOG" ]]; then
        return 0
    fi

    log "INFO" "GitLab instance and logs detected. Enabling GitLab Guard."

    # Create Filter for GitLab Auth Failures
    if [[ ! -f "/usr/local/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
        cat <<'EOF' >/usr/local/etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/usr/local/etc/fail2ban/jail.d/syswarden-gitlab.conf
[syswarden-gitlab]
enabled  = true
port     = http,https
filter   = syswarden-gitlab
logpath  = $GITLAB_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
