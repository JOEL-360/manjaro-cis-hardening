#!/bin/bash

# CIS Level 1 Hardening Script for Manjaro/Arch Linux Workstation
# Based on CIS Benchmark recommendations

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

echo "Starting CIS Level 1 hardening process..."

# 1.1 Filesystem Configuration
echo "Configuring filesystem security..."

# 1.1.1 Disable unused filesystems
cat > /etc/modprobe.d/cis.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
#install vfat /bin/true
EOF

# 1.1.2 Configure /tmp
systemctl enable tmp.mount
sed -i 's/^Options=.*/Options=mode=1777,strictatime,noexec,nodev,nosuid/' /etc/systemd/system/tmp.mount

# 1.1.3 Configure /dev/shm
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab

# 2.1 Services
echo "Configuring services..."

# 2.1.1 Time Synchronization
pacman -S --noconfirm ntp
systemctl enable ntpd
systemctl start ntpd

# 2.2 Special Purpose Services
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable dhcpd
systemctl disable slapd
systemctl disable nfs-server
systemctl disable rpcbind
systemctl disable named
systemctl disable vsftpd
systemctl disable httpd
systemctl disable dovecot
systemctl disable smb
systemctl disable squid
systemctl disable snmpd

# 3.1 Network Parameters
#echo "Configuring network parameters..."

#cat > /etc/sysctl.d/99-cis.conf << EOF
# 3.1.1 Disable IPv6
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1

# 3.2 Network Parameters (Host Only)
#net.ipv4.conf.all.send_redirects = 0
#net.ipv4.conf.default.send_redirects = 0

# 3.3 Network Parameters (Host and Router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv4.conf.default.accept_source_route = 0
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0
#net.ipv4.conf.all.secure_redirects = 0
#net.ipv4.conf.default.secure_redirects = 0
#net.ipv4.conf.all.log_martians = 1
#net.ipv4.conf.default.log_martians = 1
#net.ipv4.icmp_echo_ignore_broadcasts = 1
#net.ipv4.icmp_ignore_bogus_error_responses = 1
#net.ipv4.conf.all.rp_filter = 1
#net.ipv4.conf.default.rp_filter = 1
#net.ipv4.tcp_syncookies = 1
#EOF

#sysctl -p /etc/sysctl.d/99-cis.conf

# 4.1 Configure UFW
#echo "Configuring firewall..."
#pacman -S --noconfirm ufw
#ufw default deny incoming
#ufw default allow outgoing
#ufw enable

# 5.1 Configure time-based job schedulers
echo "Configuring cron and at..."
systemctl enable cronie
systemctl start cronie

chmod 600 /etc/crontab
chmod 600 /etc/cron.hourly
chmod 600 /etc/cron.daily
chmod 600 /etc/cron.weekly
chmod 600 /etc/cron.monthly

# 5.2 SSH Server Configuration
#echo "Configuring SSH..."
#cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

#cat > /etc/ssh/sshd_config << EOF
#Protocol 2
#LogLevel INFO
#X11Forwarding no
#MaxAuthTries 4
#IgnoreRhosts yes
#HostbasedAuthentication no
#PermitRootLogin no
#PermitEmptyPasswords no
#PermitUserEnvironment no
#Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
#MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
#KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
#ClientAliveInterval 300
#ClientAliveCountMax 0
#LoginGraceTime 60
#AllowUsers your_username_here
#EOF

#systemctl restart sshd

# 5.3 Configure PAM and password settings
echo "Configuring PAM and password policies..."

# Install PAM modules
pacman -S --noconfirm pam pam_pwquality cracklib

# Configure password quality requirements
cat > /etc/security/pwquality.conf << EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

# 5.4 User Accounts and Environment
echo "Configuring user accounts and environment..."

# Set default umask
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bash.bashrc

# Set TMOUT for automatic logout
echo "TMOUT=600" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile

# 6.1 System File Permissions
echo "Setting secure file permissions..."

chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group
chmod 000 /etc/gshadow
chmod 644 /etc/passwd-
chmod 000 /etc/shadow-
chmod 644 /etc/group-
chmod 000 /etc/gshadow-

# 6.2 User and Group Settings
echo "Configuring user and group settings..."

# Set root group owner and permissions
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/group
chown root:root /etc/gshadow

# 6.3 Warning Banners
echo "Configuring warning banners..."

cat > /etc/issue << EOF
Authorized uses only. All activity may be monitored and reported.
EOF

cat > /etc/issue.net << EOF
Authorized uses only. All activity may be monitored and reported.
EOF

chmod 644 /etc/issue
chmod 644 /etc/issue.net

# 7.1 Install AIDE
echo "Installing and configuring AIDE..."
pacman -S --noconfirm aide
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Create daily AIDE check
cat > /etc/cron.daily/aide-check << EOF
#!/bin/bash
/usr/bin/aide --check
EOF

chmod 755 /etc/cron.daily/aide-check

# 7.2 Configure System Accounting with auditd
echo "Configuring system auditing..."
pacman -S --noconfirm audit

cat > /etc/audit/rules.d/cis.rules << EOF
# 7.2.1 Configure Data Retention
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

systemctl enable auditd
systemctl start auditd

# Final steps
echo "Performing final steps..."

# Update all packages
pacman -Syu --noconfirm

echo "CIS Level 1 hardening completed. Please:"
echo "1. Update SSH configuration with your actual username"
echo "2. Review all configurations and adjust as needed"
echo "3. Reboot the system to apply all changes"
echo "4. Run 'aide --check' after reboot to establish baseline"
echo "5. Consider implementing additional CIS Level 2 controls if needed"
