#!/bin/bash
# CIS RHEL 8 v4.0.0 Hardening Script - NATIVE RHEL 8 EDITION
# 
# WHAT THIS DOES:
#   Applies CIS Level 1 hardening configurations to match the SCA policy checks.
#   Uses RHEL 8 native tools (authselect, update-crypto-policies) for compliance.
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
# SECTION 6: SSH configuration (RHEL 8 Native)
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
    
    # Do NOT set Ciphers/MACs here anymore. That is handled in Section 15.
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
    cat > /etc/sudoers.d/99-cis << 'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
EOF
    chmod 0440 /etc/sudoers.d/99-cis
    visudo -cf /etc/sudoers.d/99-cis && echo "  sudo configured."
}

# ============================================================================
# SECTION 8: PAM configuration (RHEL 8 Authselect)
# ============================================================================
apply_pam_config() {
    echo "=== Applying CIS PAM configuration via Authselect ==="
    
    # Create custom profile from sssd to ensure updates don't overwrite it
    authselect create-profile cis-profile -b sssd --symlink-meta 2>/dev/null || true
    
    # Apply the custom profile with required CIS features
    authselect select custom/cis-profile with-faillock with-pwquality with-pwhistory --force

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

    echo "  Authselect and PAM modules configured."
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
    echo "  Password policy set in /etc/login.defs"
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
    cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "AIDE check $(hostname)" root@localhost 2>/dev/null || true
EOF
    chmod 0700 /etc/cron.daily/aide
    echo "  AIDE installed and scheduled."
}

# ============================================================================
# SECTION 11: Journald configuration
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
# SECTION 12: auditd configuration (Fixed Typo)
# ============================================================================
apply_auditd() {
    echo "=== Applying CIS auditd configuration ==="
    if ! grep -q "audit=1" /proc/cmdline; then
        grubby --update-kernel=ALL --args="audit=1 audit_backlog_limit=8192"
        echo "  Added audit=1 to kernel cmdline (takes effect on reboot)"
    fi
    
    sed -i 's/^max_log_file\s*=.*/max_log_file = 8/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action\s*=.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^action_mail_acct\s*=.*/action_mail_acct = root/' /etc/audit/auditd.conf
    sed -i 's/^disk_full_action\s*=.*/disk_full_action = halt/' /etc/audit/auditd.conf
    sed -i 's/^disk_error_action\s*=.*/disk_error_action = halt/' /etc/audit/auditd.conf
    
    cat > /etc/audit/rules.d/99-cis.rules << 'EOF'
# 6.3.3.2 Ensure actions as another user are always logged (Fixed to euid)
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation

# 6.3.3.3 Scope
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# 6.3.3.4 Logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# 6.3.3.5 Session
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# 6.3.3.6 Time
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

# 6.3.3.7 Network
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# 6.3.3.8 Privileged
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

# 6.3.3.9 Access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -k access

# 6.3.3.10 Identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity

# 6.3.3.11 Perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# 6.3.3.12 Mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# 6.3.3.13 Delete
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete

# 6.3.3.15 MAC policy
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# 6.3.3.19 Modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-w /etc/modprobe.d/ -p wa -k modules

# 6.3.3.20 Immutable
-e 2
EOF
    
    if ! augenrules --load; then
        echo "  Failed to load auditd rules." >&2
        return 1
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl restart auditd 2>/dev/null && ! service auditd restart 2>/dev/null; then
            echo "  Failed to restart auditd after loading rules." >&2
            return 1
        fi
    else
        if ! service auditd restart 2>/dev/null; then
            echo "  Failed to restart auditd after loading rules." >&2
            return 1
        fi
    fi

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
# SECTION 15: Firewalld & Crypto Policies (NEW)
# ============================================================================
apply_firewall_crypto() {
    echo "=== Setting Crypto Policies and Firewalld ==="
    
    # Apply RHEL 8 System-Wide Crypto Policies
    mkdir -p /etc/crypto-policies/policies/modules/
    
    echo "hash = -SHA1" > /etc/crypto-policies/policies/modules/NO-SHA1.pmod
    echo "sign = -*-SHA1" >> /etc/crypto-policies/policies/modules/NO-SHA1.pmod
    echo "sha1_in_certs = 0" >> /etc/crypto-policies/policies/modules/NO-SHA1.pmod
    
    echo "mac@SSH = -HMAC-MD5* -UMAC-64* -UMAC-128*" > /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod
    echo "cipher@SSH = -*-CBC" > /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod
    echo "cipher@SSH = -3DES-CBC -AES-128-CBC -AES-192-CBC -AES-256-CBC -CHACHA20-POLY1305" > /etc/crypto-policies/policies/modules/NO-SSHWEAKCIPHERS.pmod

    # Apply policy (This satisfies checks 5057-5060)
    update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHWEAKCIPHERS
    
    # Configure Firewalld (Safely)
    dnf install -y firewalld
    systemctl unmask firewalld
    systemctl enable --now firewalld
    
    # Force nftables backend
    sed -i 's/^FirewallBackend.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf
    systemctl restart firewalld
    
    # CRITICAL: Allow SSH before setting default drop to prevent lockout
    firewall-cmd --permanent --zone=public --add-service=ssh
    # Add Wazuh port if needed: firewall-cmd --permanent --zone=public --add-port=1514/tcp
    
    firewall-cmd --permanent --zone=public --set-target=DROP
    firewall-cmd --reload
    
    echo "  Crypto policies and Firewalld applied safely."
}

# ============================================================================
# Main menu
# ============================================================================
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
    15) apply_firewall_crypto ;;
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
        echo ""
        echo "=== All hardening sections applied ==="
        echo "NOTE: Reboot recommended for kernel module blacklisting and crypto policies to take full effect."
        ;;
    *)
        echo "Available sections:"
        echo "  1: Kernel modules      8: PAM configuration"
        echo "  2: Network sysctl      9: Password aging"
        echo "  3: Process hardening  10: AIDE integrity"
        echo "  4: cron permissions   11: journald"
        echo "  5: Warning banners    12: auditd configuration"
        echo "  6: SSH config         13: File permissions"
        echo "  7: sudo config        14: Package cleanup"
        echo "                        15: Firewalld & Crypto Policies"
        echo "  all: Apply all sections"
        echo ""
        echo "Usage: $0 <section_number|all>"
        exit 1
        ;;
esac

echo "After applying, restart the Wazuh agent and re-probe from the manager."