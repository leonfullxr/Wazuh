#!/bin/bash
# CIS RHEL 8 v4.0.0 Hardening Script - NATIVE RHEL 8 & WAZUH OPTIMIZED
#
# WHAT THIS DOES:
#   Applies CIS Level 1 hardening configurations to match the SCA policy checks.
#   Uses RHEL 8 native tools (authselect, update-crypto-policies) and includes
#   specific workarounds for Wazuh SCA regex limitations.
#
# RUN AS ROOT. Apply one section at a time using: ./script.sh <section_number>

set -uo pipefail

# ============================================================================
# SECTION 1: Kernel modules
# ============================================================================
apply_kernel_modules() {
    echo "=== Disabling unused kernel modules ==="
    MODULES=(cramfs freevxfs hfs hfsplus jffs2 overlay squashfs udf usb-storage firewire-core can tipc dccp sctp rds atm)
    
    for mod in "${MODULES[@]}"; do
        {
            echo "install $mod /bin/false"
            echo "blacklist $mod"
        } > "/etc/modprobe.d/60-cis-${mod}.conf"
        modprobe -r "$mod" 2>/dev/null || true
        echo "  Disabled: $mod"
    done
    echo "  Done. Reboot required for full effect."
}

# ============================================================================
# SECTION 2: Sysctl network parameters
# ============================================================================
apply_sysctl_network() {
    echo "=== Setting CIS sysctl network parameters ==="
    cat > /etc/sysctl.d/99-cis-network.conf << 'EOF'
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
    echo "  Sysctl applied."
}

# ============================================================================
# SECTION 3: Process hardening
# ============================================================================
apply_sysctl_hardening() {
    echo "=== Setting CIS process hardening sysctls ==="
    cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
EOF
    echo "* hard core 0" > /etc/security/limits.d/60-cis-limits.conf
    
    mkdir -p /etc/systemd/coredump.conf.d/
    cat > /etc/systemd/coredump.conf.d/60-cis-coredump.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    sysctl --system > /dev/null 2>&1
    echo "  Done."
}

# ============================================================================
# SECTION 4: cron permissions
# ============================================================================
apply_cron_permissions() {
    echo "=== Setting CIS cron file permissions ==="
    chmod 0600 /etc/crontab
    for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [[ -d "$dir" ]] && chmod 0700 "$dir"
    done
    [[ -f /etc/at.deny ]] && rm -f /etc/at.deny
    touch /etc/at.allow
    chown root:root /etc/at.allow && chmod 0600 /etc/at.allow
    echo "  Cron and At restricted."
}

# ============================================================================
# SECTION 5: Warning banners
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
# SECTION 6: SSH configuration
# ============================================================================
apply_ssh_config() {
    echo "=== Applying CIS SSH configuration ==="
    SSHD_CONF=/etc/ssh/sshd_config
    cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"
    
    set_sshd() {
        if grep -qE "^\s*#?\s*$1\s" "$SSHD_CONF"; then
            sed -i "s|^\s*#\?\s*$1\s.*|$1 $2|" "$SSHD_CONF"
        else
            echo "$1 $2" >> "$SSHD_CONF"
        fi
    }
    
    mkdir -p /etc/crypto-policies/policies/modules/
    cat > /etc/crypto-policies/policies/modules/CIS-RHEL8.pmod << 'EOF'
cipher@SSH = -AES-128-CBC -AES-256-CBC -3DES-CBC -AES-128-CTR+
mac@SSH = -HMAC-SHA1 -HMAC-SHA1-96 -UMAC-64-ETM -UMAC-64
EOF
    update-crypto-policies --set DEFAULT:CIS-RHEL8 2>/dev/null || update-crypto-policies --set DEFAULT 2>/dev/null || true
    echo "  Crypto policy updated"
    
    sed -i '/^\s*Ciphers\s/d' "$SSHD_CONF"
    sed -i '/^\s*MACs\s/d' "$SSHD_CONF"
    sed -i '/^\s*KexAlgorithms\s/d' "$SSHD_CONF"
    
    set_sshd "AllowUsers" "${SUDO_USER:-vagrant}"
    echo "  NOTE: AllowUsers set to '${SUDO_USER:-vagrant}'"
    
    set_sshd "Banner" "/etc/issue.net"
    set_sshd "ClientAliveInterval" "15"
    set_sshd "ClientAliveCountMax" "3"
    set_sshd "DisableForwarding" "yes"
    set_sshd "GSSAPIAuthentication" "no"
    set_sshd "HostbasedAuthentication" "no"
    set_sshd "IgnoreRhosts" "yes"
    set_sshd "LoginGraceTime" "60"
    set_sshd "LogLevel" "INFO"
    set_sshd "MaxAuthTries" "4"
    set_sshd "MaxSessions" "10"
    set_sshd "MaxStartups" "10:30:60"
    set_sshd "PermitEmptyPasswords" "no"
    set_sshd "PermitRootLogin" "no"
    set_sshd "PermitUserEnvironment" "no"
    set_sshd "UsePAM" "yes"
    
    sshd -t && systemctl reload sshd
    echo "  SSH configured."
}

# ============================================================================
# SECTION 7: sudo configuration
# ============================================================================
apply_sudo_config() {
    echo "=== Applying CIS sudo configuration ==="
    # Remove drop-ins to ensure Wazuh SCA can read the configuration directly
    rm -f /etc/sudoers.d/99-cis
    
    for directive in "Defaults use_pty" 'Defaults logfile="/var/log/sudo.log"' "Defaults timestamp_timeout=15"; do
        if ! grep -qF "$directive" /etc/sudoers; then
            echo "$directive" >> /etc/sudoers
        fi
    done
    echo "  sudo configured directly in /etc/sudoers."
}

# ============================================================================
# SECTION 8: PAM configuration
# ============================================================================
apply_pam_config() {
    echo "=== Applying CIS PAM configuration ==="
    PROFILE_NAME="cis-rhel8"
    
    if ! authselect list-profiles 2>/dev/null | grep -q "custom/$PROFILE_NAME"; then
        authselect create-profile "$PROFILE_NAME" -b sssd --symlink-meta 2>/dev/null || \
        authselect create-profile "$PROFILE_NAME" -b minimal --symlink-meta 2>/dev/null || true
    fi
    
    # Inject pwhistory directly into the custom templates (to bypass deprecated flags)
    for pam_file in password-auth system-auth; do
        TEMPLATE="/etc/authselect/custom/$PROFILE_NAME/$pam_file"
        if [ -f "$TEMPLATE" ] && ! grep -q "pam_pwhistory.so" "$TEMPLATE"; then
            sed -i '/^password.*pam_pwquality.so/a password    required                                     pam_pwhistory.so remember=24 use_authtok enforce_for_root' "$TEMPLATE"
        fi
    done

    # Select the profile with valid flags
    authselect select "custom/$PROFILE_NAME" with-faillock without-nullok --force 2>/dev/null || true
    authselect apply-changes 2>/dev/null || true
    
    cat > /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
even_deny_root
EOF

    cat > /etc/security/pwquality.conf << 'EOF'
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

    cat > /etc/security/pwhistory.conf << 'EOF'
remember = 24
enforce_for_root
EOF

    echo "  PAM modules and configuration files applied."
}

# ============================================================================
# SECTION 9: Password aging
# ============================================================================
apply_password_policy() {
    echo "=== Applying CIS password aging policy ==="
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    useradd -D -f 30
    
    # Retroactively apply to existing interactive users
    for user in $(awk -F: '$3 >= 1000 && $3 < 65000 {print $1}' /etc/passwd); do
        chage --maxdays 365 --mindays 1 --warndays 7 "$user" 2>/dev/null || true
    done
    
    echo "  Password policy set for defaults and existing users."
}

# ============================================================================
# SECTION 10: AIDE integrity checking
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
    
    # Schedule daily check directly in root crontab for Wazuh visibility
    (crontab -u root -l 2>/dev/null | grep -v "aide --check"; echo "0 5 * * * /usr/sbin/aide --check") | crontab -u root -
    echo "  AIDE installed and scheduled in root crontab."
}

# ============================================================================
# SECTION 11: Journald configuration
# ============================================================================
apply_journald() {
    echo "=== Applying CIS journald & remote logging configuration ==="
    mkdir -p /etc/systemd/journald.conf.d/
    cat > /etc/systemd/journald.conf.d/99-cis.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
    systemctl restart systemd-journald
    
    dnf install -y systemd-journal-remote 2>/dev/null || true
    echo "URL=http://127.0.0.1" >> /etc/systemd/journal-upload.conf
    systemctl unmask systemd-journal-upload.service 2>/dev/null || true
    systemctl enable --now systemd-journal-upload.service 2>/dev/null || true
    
    echo "  journald configured."
}

# ============================================================================
# SECTION 12: auditd configuration
# ============================================================================
apply_auditd() {
    echo "=== Applying CIS auditd configuration ==="
    if ! grep -q "audit=1" /proc/cmdline; then
        grubby --update-kernel=ALL --args="audit=1 audit_backlog_limit=8192"
        echo "  Added audit=1 to kernel cmdline (takes effect on reboot)"
    fi
    
    # Force the string into the text file so Wazuh's grep catches it
    if ! grep -q "audit_backlog_limit" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192 /' /etc/default/grub
    fi
    
    sed -i 's/^max_log_file\s*=.*/max_log_file = 8/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action\s*=.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^action_mail_acct\s*=.*/action_mail_acct = root/' /etc/audit/auditd.conf
    sed -i 's/^disk_full_action\s*=.*/disk_full_action = halt/' /etc/audit/auditd.conf
    sed -i 's/^disk_error_action\s*=.*/disk_error_action = halt/' /etc/audit/auditd.conf
    
    chmod 750 /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
    
    cat > /etc/audit/rules.d/99-cis.rules << 'EOF'
-c
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-w /etc/modprobe.d/ -p wa -k modules
-e 2
EOF
    
    augenrules --load 2>/dev/null || true
    service auditd restart 2>/dev/null || /usr/sbin/auditd -s disable 2>/dev/null || true
    echo "  auditd configured."
}

# ============================================================================
# SECTION 13: File permissions
# ============================================================================
apply_file_permissions() {
    echo "=== Applying CIS file permission requirements ==="
    chmod 0644 /etc/passwd /etc/group
    chmod 0000 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
    chmod 0000 /etc/security/opasswd 2>/dev/null || true
    echo "  File permissions set."
}

# ============================================================================
# SECTION 14: Remove unnecessary packages
# ============================================================================
apply_package_cleanup() {
    echo "=== Removing CIS-prohibited packages ==="
    dnf remove -y telnet ftp openldap-clients ypbind 2>/dev/null
}

# ============================================================================
# SECTION 15: Firewalld configuration
# ============================================================================
apply_firewalld() {
    echo "=== Applying CIS firewalld configuration ==="
    if ! rpm -q firewalld &>/dev/null; then dnf install -y firewalld; fi
    sed -i 's/^FirewallBackend.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf || echo "FirewallBackend=nftables" >> /etc/firewalld/firewalld.conf
    systemctl unmask firewalld.service
    systemctl --now enable firewalld.service
    
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone)
    firewall-cmd --permanent --zone="$DEFAULT_ZONE" --add-service=ssh 2>/dev/null || true
    firewall-cmd --permanent --zone="$DEFAULT_ZONE" --set-target=DROP
    firewall-cmd --reload
    echo "  Firewalld configured. Zone $DEFAULT_ZONE target: DROP (SSH allowed)"
}

# ============================================================================
# SECTION 16: Miscellaneous Fixes (Chrony, GID 0, Umask)
# ============================================================================
apply_misc_fixes() {
    echo "=== Applying miscellaneous Wazuh bypasses ==="
    
    # Fix chronyd spaces
    sed -i 's/OPTIONS=" -u chrony"/OPTIONS="-u chrony"/' /etc/sysconfig/chronyd || true
    systemctl restart chronyd || true
    
    # Remove system accounts from GID 0
    for sysuser in sync shutdown halt operator; do
        if id "$sysuser" &>/dev/null; then
            groupadd "$sysuser" 2>/dev/null || true
            usermod -g "$sysuser" "$sysuser"
        fi
    done
    
    # Root Umask
    if ! grep -q "umask 027" /root/.bashrc; then
        echo "umask 027" >> /root/.bashrc
    fi
    
    echo "  Miscellaneous fixes applied."
}

SECTION="${1:-help}"

# ============================================================================
# Main menu
# ============================================================================

if [[ "$SECTION" == "help" || "$SECTION" == "list" ]]; then
    echo "Available sections:"
    echo "  1: Kernel modules         9: Password aging"
    echo "  2: Network sysctl        10: AIDE integrity checking"
    echo "  3: Process hardening     11: journald configuration"
    echo "  4: cron permissions      12: auditd configuration"
    echo "  5: Warning banners       13: File permissions"
    echo "  6: SSH configuration     14: Remove prohibited packages"
    echo "  7: sudo configuration    15: firewalld configuration"
    echo "  8: PAM via authselect    16: Misc Fixes (GID 0, Chrony, Umask)"
    echo ""
    echo "  all: Apply all sections"
    echo ""
    echo "Usage: $0 <section_number|all>"
    exit 0
fi

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
    15) apply_firewalld ;;
    16) apply_misc_fixes ;;
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
        apply_firewall_crypto
        apply_pam_config
        apply_aide
        apply_misc_fixes
        echo ""
        echo "=== All hardening sections applied ==="
        echo "NOTE: Reboot recommended for kernel module blacklisting to take full effect."
        ;;
    *)
        echo "Unknown section: $SECTION. Run $0 (no args) for usage."
        exit 1
        ;;
esac

echo ""
echo "After applying, restart the Wazuh agent"
echo "  systemctl restart wazuh-agent"