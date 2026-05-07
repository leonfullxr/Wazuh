#!/bin/bash
# CIS RHEL 8 v4.0.0 Hardening Script
# Generated from the SCA policy validation run.
#
# WHAT THIS DOES:
#   Applies CIS Level 1 hardening configurations to match the SCA policy checks.
#   Run in sections — test each section's effect on the SCA score before proceeding.
#   Some items (partition layout, audit rules) require careful planning.
#
# RUN AS ROOT. Read each section's comment before applying.
#
# After each section, restart the Wazuh agent and re-probe:
#   systemctl restart wazuh-agent && sleep 30
#   # On manager: ./16_sca_probe_manager.sh 044

set -uo pipefail
echo "CIS RHEL 8 v4.0.0 Hardening — $(date)"
echo "This script is divided into sections. Apply one section at a time."
echo "Press Ctrl+C to stop before any section you want to review first."
echo ""

# ============================================================================
# SECTION 1: Kernel modules
# Checks 5000-5009 (1.1.1.x) and 5117-5122 (3.2.x)
# ============================================================================
apply_kernel_modules() {
    echo "=== Disabling unused kernel modules ==="
    
    MODULES=(cramfs freevxfs hfs hfsplus jffs2 overlay squashfs udf usb-storage
             firewire-core can tipc dccp sctp rds)
    
    for mod in "${MODULES[@]}"; do
        {
            echo "# CIS: Ensure $mod kernel module is not available"
            echo "install $mod /bin/false"
            echo "blacklist $mod"
        } >> "/etc/modprobe.d/60-cis-${mod}.conf"
        modprobe -r "$mod" 2>/dev/null || true
        echo "  Disabled: $mod"
    done
    
    echo "  Done. Reboot required for full effect."
}

# ============================================================================
# SECTION 2: Sysctl network parameters
# Checks 5123-5148 (3.3.x)
# ============================================================================
apply_sysctl_network() {
    echo "=== Setting CIS sysctl network parameters ==="
    
    cat > /etc/sysctl.d/99-cis-network.conf << 'EOF'
# CIS RHEL 8 v4.0.0 - Section 3.3 Network Kernel Parameters

# 3.3.1.x IPv4
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# 3.3.2.x IPv6
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
EOF
    
    sysctl --system > /dev/null 2>&1
    echo "  Sysctl applied. Persistent on reboot via /etc/sysctl.d/99-cis-network.conf"
}

# ============================================================================
# SECTION 3: Process hardening (1.5.x)
# ============================================================================
apply_sysctl_hardening() {
    echo "=== Setting CIS process hardening sysctls ==="
    
    cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
# CIS RHEL 8 v4.0.0 - Section 1.5 Process Hardening
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
EOF
    
    # Core dump settings (1.5.1)
    echo "* hard core 0" >> /etc/security/limits.conf
    cat > /etc/systemd/coredump.conf.d/cis.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    
    sysctl --system > /dev/null 2>&1
    echo "  Done."
}

# ============================================================================
# SECTION 4: cron permissions (2.4.1.x)
# ============================================================================
apply_cron_permissions() {
    echo "=== Setting CIS cron file permissions ==="
    
    chmod 0600 /etc/crontab && echo "  crontab: 600"
    for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [[ -d "$dir" ]] && chmod 0700 "$dir" && echo "  $dir: 700"
    done
    
    # at.deny — restrict at to root only
    [[ -f /etc/at.deny ]] && rm -f /etc/at.deny
    touch /etc/at.allow
    chown root:root /etc/at.allow && chmod 0600 /etc/at.allow
    echo "  at.allow: restricted to root"
}

# ============================================================================
# SECTION 5: Warning banners (1.7.x)
# ============================================================================
apply_banners() {
    echo "=== Setting CIS warning banners ==="
    
    BANNER='Authorized users only. All activity may be monitored and reported.'
    
    echo "$BANNER" > /etc/motd
    echo "$BANNER" > /etc/issue
    echo "$BANNER" > /etc/issue.net
    
    chmod 0644 /etc/motd /etc/issue /etc/issue.net
    chown root:root /etc/motd /etc/issue /etc/issue.net
    echo "  Banners set."
}

# ============================================================================
# SECTION 6: SSH configuration (5.1.x)
# ============================================================================
apply_ssh_config() {
    echo "=== Applying CIS SSH configuration ==="
    
    SSHD_CONF=/etc/ssh/sshd_config
    cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"
    
    # Function to set or replace a directive
    set_sshd() {
        local key="$1"
        local val="$2"
        if grep -qE "^\s*#?\s*${key}\s" "$SSHD_CONF"; then
            sed -i "s|^\s*#\?\s*${key}\s.*|${key} ${val}|" "$SSHD_CONF"
        else
            echo "${key} ${val}" >> "$SSHD_CONF"
        fi
    }
    
    # 5.1.6 - access control (adjust to your environment)
    # set_sshd "AllowUsers" "yourusername"
    echo "  NOTE: Set AllowUsers/AllowGroups manually to restrict SSH access (5.1.6)"
    
    # 5.1.7 - Banner
    set_sshd "Banner" "/etc/issue.net"
    
    # 5.1.8 - Ciphers (CIS-approved list)
    set_sshd "Ciphers" "aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
    
    # 5.1.9 - ClientAlive
    set_sshd "ClientAliveInterval" "15"
    set_sshd "ClientAliveCountMax" "3"
    
    # 5.1.10 - DisableForwarding
    set_sshd "DisableForwarding" "yes"
    
    # 5.1.11 - GSSAPIAuthentication
    set_sshd "GSSAPIAuthentication" "no"
    
    # 5.1.12 - HostbasedAuthentication
    set_sshd "HostbasedAuthentication" "no"
    
    # 5.1.13 - IgnoreRhosts
    set_sshd "IgnoreRhosts" "yes"
    
    # 5.1.14 - LoginGraceTime
    set_sshd "LoginGraceTime" "60"
    
    # 5.1.15 - LogLevel
    set_sshd "LogLevel" "INFO"
    
    # 5.1.16 - MACs
    set_sshd "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    
    # 5.1.17 - MaxAuthTries
    set_sshd "MaxAuthTries" "4"
    
    # 5.1.18 - MaxSessions
    set_sshd "MaxSessions" "10"
    
    # 5.1.19 - MaxStartups
    set_sshd "MaxStartups" "10:30:60"
    
    # 5.1.20 - PermitEmptyPasswords
    set_sshd "PermitEmptyPasswords" "no"
    
    # 5.1.21 - PermitRootLogin (already no per diagnostic)
    set_sshd "PermitRootLogin" "no"
    
    # 5.1.22 - PermitUserEnvironment
    set_sshd "PermitUserEnvironment" "no"
    
    # 5.1.23 - UsePAM (already yes)
    set_sshd "UsePAM" "yes"
    
    sshd -t && echo "  sshd_config validated OK" && systemctl reload sshd
    echo "  SSH configured."
}

# ============================================================================
# SECTION 7: sudo configuration (5.2.x)
# ============================================================================
apply_sudo_config() {
    echo "=== Applying CIS sudo configuration ==="
    
    cat > /etc/sudoers.d/99-cis << 'EOF'
# CIS RHEL 8 v4.0.0 - Section 5.2 Sudo hardening
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
EOF
    
    chmod 0440 /etc/sudoers.d/99-cis
    visudo -cf /etc/sudoers.d/99-cis && echo "  sudo config validated OK"
    echo "  sudo configured."
}

# ============================================================================
# SECTION 8: PAM configuration (5.3.x)
# ============================================================================
apply_pam_config() {
    echo "=== Applying CIS PAM configuration ==="
    
    # Use authselect with faillock and pwquality
    authselect select sssd with-faillock with-pwquality --force 2>/dev/null || \
    authselect select minimal with-faillock with-pwquality --force 2>/dev/null || \
        echo "  WARNING: authselect profile selection failed — configure manually"
    
    # faillock.conf (5.3.3.1.x)
    cat > /etc/security/faillock.conf << 'EOF'
# CIS RHEL 8 v4.0.0 - pam_faillock settings
deny = 5
unlock_time = 900
even_deny_root
EOF
    
    # pwquality.conf (5.3.3.2.x)
    cat > /etc/security/pwquality.conf << 'EOF'
# CIS RHEL 8 v4.0.0 - pam_pwquality settings
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 2
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforce_for_root
EOF
    
    echo "  PAM configured. Test login in a separate session before logging out."
}

# ============================================================================
# SECTION 9: Password aging (5.4.1.x)
# ============================================================================
apply_password_policy() {
    echo "=== Applying CIS password aging policy ==="
    
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    
    useradd -D -f 30
    echo "  Password policy set in /etc/login.defs"
}

# ============================================================================
# SECTION 10: AIDE integrity checking (6.1.x)
# ============================================================================
apply_aide() {
    echo "=== Installing and configuring AIDE ==="
    
    if ! rpm -q aide &>/dev/null; then
        dnf install -y aide
    fi
    
    if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        echo "  Initializing AIDE database (this may take a few minutes)..."
        aide --init
        mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
    
    # Schedule daily check (6.1.2)
    cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "AIDE check $(hostname)" root@localhost 2>/dev/null || true
EOF
    chmod 0700 /etc/cron.daily/aide
    echo "  AIDE installed and scheduled."
}

# ============================================================================
# SECTION 11: Journald configuration (6.2.1.x)
# ============================================================================
apply_journald() {
    echo "=== Applying CIS journald configuration ==="
    
    mkdir -p /etc/systemd/journald.conf.d/
    cat > /etc/systemd/journald.conf.d/99-cis.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
    
    systemctl restart systemd-journald
    echo "  journald configured."
}

# ============================================================================
# SECTION 12: auditd configuration (6.3.x)
# ============================================================================
apply_auditd() {
    echo "=== Applying CIS auditd configuration ==="
    
    # Kernel cmdline: add audit=1 and audit_backlog_limit=8192 to grub
    if ! grep -q "audit=1" /proc/cmdline; then
        grubby --update-kernel=ALL --args="audit=1 audit_backlog_limit=8192"
        echo "  Added audit=1 audit_backlog_limit=8192 to kernel cmdline (takes effect on reboot)"
    fi
    
    # auditd.conf (6.3.2.x)
    sed -i 's/^max_log_file\s*=.*/max_log_file = 8/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action\s*=.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^action_mail_acct\s*=.*/action_mail_acct = root/' /etc/audit/auditd.conf
    sed -i 's/^disk_full_action\s*=.*/disk_full_action = halt/' /etc/audit/auditd.conf
    sed -i 's/^disk_error_action\s*=.*/disk_error_action = halt/' /etc/audit/auditd.conf
    
    # Audit rules (6.3.3.x) — create CIS ruleset
    cat > /etc/audit/rules.d/99-cis.rules << 'EOF'
# CIS RHEL 8 v4.0.0 audit rules

# 6.3.3.2 Ensure actions as another user are always logged
-a always,exit -F arch=b64 -C auid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C auid!=uid -F auid!=unset -S execve -k user_emulation

# 6.3.3.3 Ensure system administration scope changes are collected
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# 6.3.3.4 Ensure login and logout events are collected
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# 6.3.3.5 Ensure session initiation information is collected
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# 6.3.3.6 Ensure events that modify date and time are collected
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-w /etc/localtime -p wa -k time-change

# 6.3.3.7 Ensure events that modify the system's network environment are collected
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# 6.3.3.8 Ensure use of privileged commands is collected
-a always,exit -F path=/usr/bin/newrole -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# 6.3.3.9 Ensure unsuccessful file access attempts are collected
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access

# 6.3.3.10 Ensure events that modify user/group information are collected
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# 6.3.3.11 Ensure discretionary access control permission modification are collected
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# 6.3.3.12 Ensure successful file system mounts are collected
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# 6.3.3.13 Ensure file deletion events by users are collected
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete

# 6.3.3.14 Ensure changes to system administration scope are collected
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# 6.3.3.15 Ensure changes to MAC policy are collected
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# 6.3.3.17 Ensure usermod command usage is recorded
-w /usr/sbin/usermod -p x -k usermod

# 6.3.3.19 Ensure kernel module loading and unloading is collected
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-w /etc/modprobe.d/ -p wa -k modules

# 6.3.3.20 Ensure the audit configuration is immutable
-e 2
EOF
    
    augenrules --load
    systemctl restart auditd
    echo "  auditd configured with CIS rules."
}

# ============================================================================
# SECTION 13: File permissions (7.1.x)
# ============================================================================
apply_file_permissions() {
    echo "=== Applying CIS file permission requirements ==="
    
    # 7.1.1 - Already at 644 (correct)
    chmod 0644 /etc/passwd /etc/group
    chmod 0000 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
    chmod 0600 /etc/security/opasswd 2>/dev/null || true  # CIS wants 000
    chmod 0000 /etc/security/opasswd 2>/dev/null || true
    
    echo "  File permissions set."
}

# ============================================================================
# SECTION 14: Remove unnecessary packages (2.2.4)
# ============================================================================
apply_package_cleanup() {
    echo "=== Removing CIS-prohibited packages ==="
    dnf remove -y telnet 2>/dev/null && echo "  telnet removed" || echo "  telnet already absent"
}

# ============================================================================
# Main menu
# ============================================================================
echo "Available sections:"
echo "  1: Kernel modules (1.1.1.x, 3.2.x)"
echo "  2: Network sysctl (3.3.x)"
echo "  3: Process hardening sysctl (1.5.x)"
echo "  4: cron permissions (2.4.1.x)"
echo "  5: Warning banners (1.7.x)"
echo "  6: SSH configuration (5.1.x)"
echo "  7: sudo configuration (5.2.x)"
echo "  8: PAM configuration (5.3.x)"
echo "  9: Password aging (5.4.1.x)"
echo " 10: AIDE integrity checking (6.1.x)"
echo " 11: journald configuration (6.2.1.x)"
echo " 12: auditd configuration (6.3.x)"
echo " 13: File permissions (7.1.x)"
echo " 14: Remove prohibited packages"
echo ""
echo "  all: Apply all sections (NOT recommended for production without review)"
echo ""

SECTION="${1:-help}"
case "$SECTION" in
    1)  apply_kernel_modules ;;
    2)  apply_sysctl_network ;;
    3)  apply_sysctl_hardening ;;
    4)  apply_cron_permissions ;;
    5)  apply_banners ;;
    6)  apply_ssh_config ;;
    7)  apply_sudo_config ;;
    8)  apply_pam_config ;;
    9)  apply_password_policy ;;
    10) apply_aide ;;
    11) apply_journald ;;
    12) apply_auditd ;;
    13) apply_file_permissions ;;
    14) apply_package_cleanup ;;
    all)
        apply_kernel_modules
        apply_sysctl_network
        apply_sysctl_hardening
        apply_cron_permissions
        apply_banners
        apply_ssh_config
        apply_sudo_config
        apply_package_cleanup
        apply_file_permissions
        apply_password_policy
        apply_journald
        apply_auditd
        echo ""
        echo "=== All hardening sections applied ==="
        echo "NOTE: PAM (section 8) and AIDE (section 10) not auto-applied — run manually."
        echo "NOTE: Reboot recommended for kernel module blacklisting to take full effect."
        ;;
    help|*)
        echo "Usage: $0 <section_number|all>"
        echo "Example: $0 5  # Apply only SSH configuration"
        ;;
esac

echo ""
echo "After applying, restart the Wazuh agent and re-probe from the manager:"
echo "  systemctl restart wazuh-agent"
echo "  # On manager: ./16_sca_probe_manager.sh 044"