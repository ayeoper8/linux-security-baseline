#!/bin/bash
#===============================================================================
# apply-linux-baseline.sh
#
# Applies the company Linux server build standard (CIS Ubuntu 24.04 L1
# aligned essentials subset - see docs/04-decisions.md for scope rationale).
#
#   M1  qualys-scanner service account + SSH key + sudoers   (Tier 1, unchanged)
#   M2  sshd hardening drop-in  - weak crypto removed (incl. all SHA1 MACs),
#       validated with 'sshd -t', applied with RELOAD ONLY (never restart)
#   M3  UFW firewall            - default-deny inbound, role-based ports
#   M4  unattended-upgrades     - security patches only
#   M5  chrony                  - time synchronisation
#   M6  CrowdStrike Falcon      - installs sensor if installer + CID provided
#   M7  Registration upload     - posts host JSON to Azure blob (never fatal)
#   M8  Listener check          - flags unexpected non-loopback listeners
#   M9  ansible-mgmt account    - estate enrollment for future config mgmt
#   M10 Hardening pack          - sysctl network params, fs module blacklist,
#       core dump restriction, cron/at access, login banner
#
# Usage (run as root):
#   sudo bash apply-linux-baseline.sh [--role standard|webserver]
#        [--auto-reboot on|off] [--admin-user NAME --admin-key 'ssh-ed25519 ...']
#
# Defaults: role=standard, auto-reboot=off. Safe to re-run (idempotent).
# Non-interactive by design (cloud-init / Ansible compatible) - all decisions
# are flags or CONFIGURATION values, never prompts.
#===============================================================================
set -uo pipefail   # NOTE: no -e; modules handle their own errors so one
                   # non-critical failure does not abort the whole baseline.

#----------------------------------------------------------------------------
# CONFIGURATION
#----------------------------------------------------------------------------

# --- Qualys scanner account (Tier 1) ---
QUALYS_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1xsQ0On3DLZkLL4//ukMpYbzfnM8nlDMimIc1GeeGt qualys-scanner'
SCANNER_SOURCE_IPS='<SCANNER_IP>'
SCAN_USER='qualys-scanner'

# --- SSH / firewall ---
# NOTE: SSH (22/tcp) is allowed from ANY source. Flat network + DHCP + VPN
# means admin source restriction is not workable. Recorded as an accepted
# limitation; revisit if an admin VLAN or bastion host is introduced.

# --- Unattended upgrades ---
# Automatic reboot when a kernel update requires it. Decide with infrastructure.
AUTO_REBOOT='false'
AUTO_REBOOT_TIME='04:00'

# --- Time sync ---
# Leave empty to keep Ubuntu pool defaults, or set internal NTP, e.g. '<INTERNAL_NTP_IP>'
NTP_SERVERS=''

# --- CrowdStrike ---
# Provide your CID and place the falcon-sensor .deb on the host to enable M6.
CS_CID=''
CS_INSTALLER='/root/falcon-sensor.deb'

# --- Ansible management account (M9 - estate enrollment) ---
# Public key for the ansible-mgmt account. PRIVATE key lives in the dedicated
# Ansible Key Vault (ansible-rg - to be created; deliberately separate from
# the Qualys vault). Leave placeholder to skip M9 with a warning.
ANSIBLE_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1XMC/ZF7jJSDXIXHDEviyEIEfGS9cM0GpvF/3FpNox ansible-mgmt'
# Control node IP(s) permitted to use the key (comma-separated).
# INTERIM value: example-host-01. Will change when the dedicated Ansible
# control node is built with infrastructure.
ANSIBLE_SOURCE_IPS='<ANSIBLE_CONTROL_IP>'
ANSIBLE_USER='ansible-mgmt'

# --- Registration upload (M7) ---
STORAGE_ACCOUNT='qualysvulndata'
STORAGE_CONTAINER='linux-registrations'
# Write-only SAS token (no read/list/delete), scoped to the container above.
# Leave empty to skip upload - the script will print the IP for manual entry.
SAS_TOKEN=''

#----------------------------------------------------------------------------
# Role handling and helpers
#----------------------------------------------------------------------------
ROLE='standard'
ADMIN_USER=''
ADMIN_KEY=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            case "${2:-}" in
                standard|webserver) ROLE="$2"; shift 2 ;;
                *) echo "ERROR: --role must be 'standard' or 'webserver'" >&2; exit 1 ;;
            esac ;;
        --auto-reboot)
            case "${2:-}" in
                on)  AUTO_REBOOT='true';  shift 2 ;;
                off) AUTO_REBOOT='false'; shift 2 ;;
                *) echo "ERROR: --auto-reboot must be 'on' or 'off'" >&2; exit 1 ;;
            esac ;;
        --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
        --admin-key)  ADMIN_KEY="${2:-}";  shift 2 ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 1 ;;
    esac
done
if [[ -n "$ADMIN_USER" && -z "$ADMIN_KEY" ]] || [[ -z "$ADMIN_USER" && -n "$ADMIN_KEY" ]]; then
    echo "ERROR: --admin-user and --admin-key must be supplied together" >&2; exit 1
fi

PASS=0; FAIL=0; WARN=0
ok()    { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()   { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn()  { echo "  [WARN] $1"; WARN=$((WARN+1)); }
info()  { echo "  [....] $1"; }

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (sudo bash $0)" >&2; exit 1
fi

PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')

echo "==============================================================="
echo " Linux baseline - $(hostname) - role: ${ROLE}"
echo " $(date)"
echo "==============================================================="

#----------------------------------------------------------------------------
# M0. Optional named admin account (via --admin-user / --admin-key flags)
#     Enables root SSH login to be disabled in M2 on hosts that lack one.
#----------------------------------------------------------------------------
if [[ -n "$ADMIN_USER" ]]; then
    echo ""
    echo "[M0] Admin account: ${ADMIN_USER}"
    if id "$ADMIN_USER" &>/dev/null; then
        info "User ${ADMIN_USER} already exists - adding key and sudo only"
    else
        useradd --create-home --shell /bin/bash "$ADMIN_USER" \
            && info "User ${ADMIN_USER} created (NOTE: no password set - run 'passwd ${ADMIN_USER}' so sudo can prompt)" \
            || bad "useradd ${ADMIN_USER} failed"
    fi
    usermod -aG sudo "$ADMIN_USER"
    AD_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    mkdir -p "${AD_HOME}/.ssh"
    grep -qxF "$ADMIN_KEY" "${AD_HOME}/.ssh/authorized_keys" 2>/dev/null \
        || echo "$ADMIN_KEY" >> "${AD_HOME}/.ssh/authorized_keys"
    chown -R "${ADMIN_USER}:$(id -gn "$ADMIN_USER")" "${AD_HOME}/.ssh"
    chmod 700 "${AD_HOME}/.ssh"; chmod 600 "${AD_HOME}/.ssh/authorized_keys"
    info "SSH key installed for ${ADMIN_USER} (sudo group member)"
fi

#----------------------------------------------------------------------------
# M1. Qualys scanner account
#----------------------------------------------------------------------------
echo ""
echo "[M1] Qualys scanner account"
if id "$SCAN_USER" &>/dev/null; then
    info "User ${SCAN_USER} already exists"
else
    useradd --system --create-home --shell /bin/bash \
            --comment "Qualys authenticated scanning service account" "$SCAN_USER" \
        && info "User ${SCAN_USER} created" || bad "useradd failed"
fi
passwd -l "$SCAN_USER" >/dev/null 2>&1 || usermod -L "$SCAN_USER"

HOME_DIR=$(getent passwd "$SCAN_USER" | cut -d: -f6)
SSH_DIR="${HOME_DIR}/.ssh"; AUTH_KEYS="${SSH_DIR}/authorized_keys"
mkdir -p "$SSH_DIR"
echo "from=\"${SCANNER_SOURCE_IPS}\" ${QUALYS_PUBKEY}" > "$AUTH_KEYS"
chown -R "${SCAN_USER}:$(id -gn "$SCAN_USER")" "$SSH_DIR"
chmod 700 "$SSH_DIR"; chmod 600 "$AUTH_KEYS"
info "SSH key installed, restricted to ${SCANNER_SOURCE_IPS}"

TMP=$(mktemp)
cat > "$TMP" <<EOF
# Qualys authenticated scanning - root delegation via 'sudo su -'
# Managed by apply-linux-baseline.sh - do not hand-edit
Cmnd_Alias QUALYS_SU = /bin/su -, /usr/bin/su -
${SCAN_USER} ALL=(root) NOPASSWD: QUALYS_SU
EOF
if visudo -c -f "$TMP" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$TMP" "/etc/sudoers.d/${SCAN_USER}"
    info "Sudoers rule installed"
else
    bad "Sudoers rule failed validation - NOT installed"
fi
rm -f "$TMP"

#----------------------------------------------------------------------------
# M2. sshd hardening drop-in (validate, then RELOAD ONLY - never restart)
#----------------------------------------------------------------------------
echo ""
echo "[M2] sshd hardening"
SSHD_DROPIN='/etc/ssh/sshd_config.d/60-example-hardening.conf'

# Safety: only disable root SSH login if another sudo-capable user with an
# SSH key exists, otherwise we risk locking admins out entirely.
ROOT_LOGIN_LINE='# PermitRootLogin unchanged - no alternate sudo admin with SSH key found'
ALT_ADMIN=''
while IFS=: read -r u _ uid _ _ home _; do
    [[ "$uid" -ge 1000 && "$u" != "nobody" ]] || continue
    if id -nG "$u" 2>/dev/null | grep -qwE 'sudo|admin' \
       && [[ -s "${home}/.ssh/authorized_keys" ]]; then
        ALT_ADMIN="$u"; break
    fi
done < /etc/passwd
if [[ -n "$ALT_ADMIN" ]]; then
    ROOT_LOGIN_LINE='PermitRootLogin no'
    info "Alternate admin '${ALT_ADMIN}' found - root SSH login will be disabled"
else
    warn "No non-root sudo user with an SSH key found - leaving PermitRootLogin unchanged (fix: re-run with --admin-user NAME --admin-key 'ssh-ed25519 ...')"
fi

TMP=$(mktemp)
cat > "$TMP" <<EOF
# Example Linux baseline - sshd hardening (CIS 24.04 L1 aligned;
# additionally removes ALL SHA1-based MACs, stricter than CIS)
# Managed by apply-linux-baseline.sh - do not hand-edit
${ROOT_LOGIN_LINE}
PermitEmptyPasswords no
MaxAuthTries 4
MaxSessions 10
LoginGraceTime 60
# CIS 5.1.6 - weak ciphers
Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc
# CIS 5.1.12 - weak key exchange
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
# CIS 5.1.15 weak MACs, PLUS hmac-sha1 and hmac-sha1-etm (stricter than CIS)
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
# CIS 5.1.x session and misc hardening
ClientAliveInterval 15
ClientAliveCountMax 3
MaxStartups 10:30:60
X11Forwarding no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
LogLevel VERBOSE
Banner /etc/issue.net
EOF

install -m 0600 -o root -g root "$TMP" "$SSHD_DROPIN"; rm -f "$TMP"
if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
    info "Drop-in installed at ${SSHD_DROPIN}, config valid, sshd RELOADED"
else
    rm -f "$SSHD_DROPIN"
    bad "sshd -t failed with drop-in applied - drop-in REMOVED, sshd untouched"
fi

#----------------------------------------------------------------------------
# M3. UFW - default deny inbound, role-based allow rules
#----------------------------------------------------------------------------
echo ""
echo "[M3] UFW firewall (role: ${ROLE})"
if ! command -v ufw >/dev/null 2>&1; then
    apt-get install -y ufw >/dev/null 2>&1 || bad "ufw install failed"
fi
if command -v ufw >/dev/null 2>&1; then
    ufw default deny incoming  >/dev/null
    ufw default allow outgoing >/dev/null
    # CRITICAL ORDER: allow SSH BEFORE enabling, or this session dies.
    # Open from any source - flat network/DHCP/VPN makes source
    # restriction unworkable (accepted limitation, see CONFIGURATION note).
    ufw allow 22/tcp >/dev/null
    info "SSH (22/tcp) allowed from any source"
    if [[ "$ROLE" == "webserver" ]]; then
        ufw allow 80/tcp  >/dev/null
        ufw allow 443/tcp >/dev/null
        info "Webserver role: 80/tcp and 443/tcp allowed"
    fi
    ufw --force enable >/dev/null && info "UFW enabled (default deny inbound)" \
        || bad "ufw enable failed"
else
    bad "ufw unavailable - firewall NOT configured"
fi

#----------------------------------------------------------------------------
# M4. Unattended upgrades (security only)
#----------------------------------------------------------------------------
echo ""
echo "[M4] Unattended upgrades"
apt-get install -y unattended-upgrades >/dev/null 2>&1
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52example-unattended <<EOF
// Example baseline - security updates only, managed by provisioning script
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "${AUTO_REBOOT}";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1
info "Security-only unattended upgrades enabled (auto-reboot: ${AUTO_REBOOT})"

#----------------------------------------------------------------------------
# M5. chrony time sync
#----------------------------------------------------------------------------
echo ""
echo "[M5] Time synchronisation (chrony)"
apt-get install -y chrony >/dev/null 2>&1
if [[ -n "$NTP_SERVERS" ]]; then
    sed -i '/^pool /d;/^server /d' /etc/chrony/chrony.conf
    IFS=',' read -ra NTPS <<< "$NTP_SERVERS"
    for s in "${NTPS[@]}"; do echo "server $s iburst" >> /etc/chrony/chrony.conf; done
    info "chrony pointed at: ${NTP_SERVERS}"
else
    info "chrony using Ubuntu pool defaults"
fi
systemctl enable --now chrony >/dev/null 2>&1 && info "chrony running" || bad "chrony failed to start"

#----------------------------------------------------------------------------
# M6. CrowdStrike Falcon sensor (skips cleanly if CID/installer absent)
#----------------------------------------------------------------------------
echo ""
echo "[M6] CrowdStrike Falcon"
if pgrep -x falcon-sensor >/dev/null 2>&1; then
    info "Falcon sensor already running - skipping"
elif [[ -z "$CS_CID" ]]; then
    warn "CS_CID not set - CrowdStrike skipped (install later)"
elif [[ ! -f "$CS_INSTALLER" ]]; then
    warn "Installer ${CS_INSTALLER} not found - CrowdStrike skipped"
else
    if apt-get install -y "$CS_INSTALLER" >/dev/null 2>&1 \
       && /opt/CrowdStrike/falconctl -s --cid="$CS_CID" \
       && systemctl enable --now falcon-sensor >/dev/null 2>&1; then
        info "Falcon sensor installed and started"
    else
        bad "Falcon sensor install failed"
    fi
fi

#----------------------------------------------------------------------------
# M7. Registration upload to Azure blob (NEVER fatal)
#----------------------------------------------------------------------------
echo ""
echo "[M7] Registration upload"
REG_JSON=$(mktemp)
cat > "$REG_JSON" <<EOF
{
  "hostname": "$(hostname)",
  "ip": "${PRIMARY_IP}",
  "distro": "$(. /etc/os-release && echo "$ID")",
  "version": "$(. /etc/os-release && echo "$VERSION_ID")",
  "role": "${ROLE}",
  "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
if [[ -z "$SAS_TOKEN" ]]; then
    warn "SAS_TOKEN not set - registration skipped. Add ${PRIMARY_IP} to Qualys manually."
elif curl -sf -X PUT -H "x-ms-blob-type: BlockBlob" \
        -H "Content-Type: application/json" \
        --data-binary @"$REG_JSON" \
        "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${STORAGE_CONTAINER}/$(hostname).json?${SAS_TOKEN}" \
        --max-time 15; then
    info "Registered $(hostname) (${PRIMARY_IP}) to ${STORAGE_CONTAINER}"
else
    warn "Blob upload failed - registration skipped. Add ${PRIMARY_IP} to Qualys manually."
fi
rm -f "$REG_JSON"

#----------------------------------------------------------------------------
# M8. Listener check - flag unexpected non-loopback listeners
#----------------------------------------------------------------------------
echo ""
echo "[M8] Listening port check (role: ${ROLE})"
case "$ROLE" in
    webserver) EXPECTED_TCP="22 80 443" ;;
    *)         EXPECTED_TCP="22" ;;
esac
UNEXPECTED=0
while read -r proto local process; do
    addr="${local%:*}"; port="${local##*:}"
    # ignore loopback-only listeners
    [[ "$addr" == "127."* || "$addr" == "::1" || "$addr" == "[::1]" ]] && continue
    if [[ "$proto" == "tcp" ]]; then
        if ! grep -qw "$port" <<< "$EXPECTED_TCP"; then
            warn "Unexpected TCP listener: port ${port} (${process:-unknown}) on ${addr} - UFW blocks it, but investigate why it is running"
            UNEXPECTED=$((UNEXPECTED+1))
        fi
    fi
done < <(ss -tlnpH 2>/dev/null | awk '{split($4,a," "); print "tcp", $4, $6}')
[[ $UNEXPECTED -eq 0 ]] && ok "No unexpected non-loopback TCP listeners"

#----------------------------------------------------------------------------
# M9. Ansible management account (estate enrollment for future config mgmt)
#     Same trust pattern as qualys-scanner: key-only, locked password,
#     source-restricted. Differs in sudo scope: full ALL (config management
#     genuinely needs it). See docs/04-decisions.md entry #11.
#----------------------------------------------------------------------------
echo ""
echo "[M9] Ansible management account"
if [[ "$ANSIBLE_PUBKEY" == "REPLACE_WITH_ANSIBLE_PUBLIC_KEY" ]]; then
    warn "ANSIBLE_PUBKEY not set - M9 skipped (host NOT enrolled for config management)"
else
    if id "$ANSIBLE_USER" &>/dev/null; then
        info "User ${ANSIBLE_USER} already exists"
    else
        useradd --system --create-home --shell /bin/bash \
                --comment "Ansible configuration management service account" "$ANSIBLE_USER" \
            && info "User ${ANSIBLE_USER} created" || bad "useradd ${ANSIBLE_USER} failed"
    fi
    passwd -l "$ANSIBLE_USER" >/dev/null 2>&1 || usermod -L "$ANSIBLE_USER"

    A_HOME=$(getent passwd "$ANSIBLE_USER" | cut -d: -f6)
    mkdir -p "${A_HOME}/.ssh"
    echo "from=\"${ANSIBLE_SOURCE_IPS}\" ${ANSIBLE_PUBKEY}" > "${A_HOME}/.ssh/authorized_keys"
    chown -R "${ANSIBLE_USER}:$(id -gn "$ANSIBLE_USER")" "${A_HOME}/.ssh"
    chmod 700 "${A_HOME}/.ssh"; chmod 600 "${A_HOME}/.ssh/authorized_keys"
    info "SSH key installed, restricted to ${ANSIBLE_SOURCE_IPS}"

    TMP=$(mktemp)
    cat > "$TMP" <<EOF
# Ansible configuration management - full sudo required
# Managed by apply-linux-baseline.sh - do not hand-edit
${ANSIBLE_USER} ALL=(ALL) NOPASSWD: ALL
EOF
    if visudo -c -f "$TMP" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "$TMP" "/etc/sudoers.d/${ANSIBLE_USER}"
        info "Sudoers rule installed"
    else
        bad "ansible-mgmt sudoers failed validation - NOT installed"
    fi
    rm -f "$TMP"
fi

#----------------------------------------------------------------------------
# M10. Hardening pack - static set-once CIS L1 items (no operational tail)
#----------------------------------------------------------------------------
echo ""
echo "[M10] Hardening pack"

# Network kernel parameters + core dump restriction (CIS 1.5 / 3.3)
cat > /etc/sysctl.d/60-example-hardening.conf <<'EOF'
# Example Linux baseline - kernel hardening (CIS Ubuntu 24.04 L1 subset)
# Managed by apply-linux-baseline.sh - do not hand-edit
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF
sysctl -q --load /etc/sysctl.d/60-example-hardening.conf >/dev/null 2>&1 \
    && info "Kernel parameters applied (sysctl.d/60-example-hardening.conf)" \
    || warn "Some sysctl values failed to apply - check 'sysctl --system' output"

# Unused filesystem kernel modules (CIS 1.1.1) - VMs need none of these
cat > /etc/modprobe.d/60-example-fs.conf <<'EOF'
# Example Linux baseline - disable unused filesystem/storage modules
# Managed by apply-linux-baseline.sh - do not hand-edit
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install jffs2 /bin/false
blacklist jffs2
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install udf /bin/false
blacklist udf
install usb-storage /bin/false
blacklist usb-storage
EOF
info "Unused filesystem modules disabled (modprobe.d/60-example-fs.conf)"

# Core dumps off for all users (pairs with fs.suid_dumpable above)
echo '* hard core 0' > /etc/security/limits.d/60-example-coredump.conf
info "Core dumps disabled"

# cron/at restricted to root (CIS 2.4)
rm -f /etc/cron.deny /etc/at.deny
echo root > /etc/cron.allow; chown root:root /etc/cron.allow; chmod 640 /etc/cron.allow
echo root > /etc/at.allow;   chown root:root /etc/at.allow;   chmod 640 /etc/at.allow
info "cron/at restricted to root"

# Login banner (referenced by sshd Banner directive in M2)
cat > /etc/issue.net <<'EOF'
*****************************************************************
* This system is for authorised use only. Activity is monitored *
* and logged. Disconnect now if you are not an authorised user. *
*****************************************************************
EOF
cp /etc/issue.net /etc/issue
info "Login banner installed"

#----------------------------------------------------------------------------
# Validation summary
#----------------------------------------------------------------------------
echo ""
echo "[Validation]"
id "$SCAN_USER" &>/dev/null && ok "qualys-scanner account present" || bad "qualys-scanner missing"
sudo -l -U "$SCAN_USER" 2>/dev/null | grep -q "/bin/su" && ok "Scanner sudo rule active" || bad "Scanner sudo rule missing"
[[ -f "$SSHD_DROPIN" ]] && ok "sshd hardening drop-in present" || bad "sshd drop-in missing"
sshd -T 2>/dev/null | grep -qiw 'hmac-sha1' && bad "weak SHA1 MACs still negotiable by sshd" || ok "SHA1 MACs removed from sshd"
ufw status 2>/dev/null | grep -q "Status: active" && ok "UFW active" || bad "UFW not active"
systemctl is-active --quiet unattended-upgrades && ok "unattended-upgrades active" || warn "unattended-upgrades not active"
systemctl is-active --quiet chrony && ok "chrony active" || warn "chrony not active"
pgrep -x falcon-sensor >/dev/null 2>&1 && ok "Falcon sensor running" || warn "Falcon sensor not running"
if [[ "$ANSIBLE_PUBKEY" != "REPLACE_WITH_ANSIBLE_PUBLIC_KEY" ]]; then
    id "$ANSIBLE_USER" &>/dev/null && sudo -l -U "$ANSIBLE_USER" 2>/dev/null | grep -q "NOPASSWD: ALL" \
        && ok "ansible-mgmt account enrolled" || bad "ansible-mgmt enrollment incomplete"
fi
[[ "$(sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null)" == "0" ]] \
    && ok "Kernel network hardening active" || warn "Kernel network hardening not in effect"
[[ -f /etc/modprobe.d/60-example-fs.conf ]] && ok "Filesystem module blacklist present" || bad "Module blacklist missing"
if [[ -n "$ADMIN_USER" ]]; then
    id "$ADMIN_USER" &>/dev/null && id -nG "$ADMIN_USER" | grep -qw sudo \
        && ok "Admin account ${ADMIN_USER} present with sudo" || bad "Admin account setup incomplete"
fi

echo ""
echo "==============================================================="
echo " Result: ${PASS} passed, ${FAIL} failed, ${WARN} warnings on $(hostname)"
echo " Host IP: ${PRIMARY_IP}   Role: ${ROLE}"
echo "==============================================================="
if [[ $FAIL -eq 0 ]]; then
    echo " Baseline applied. Run a Qualys authenticated scan to confirm"
    echo " authentication still succeeds with the hardened SSH configuration."
else
    echo " Fix FAIL items above, then re-run (script is idempotent)."
fi
exit $FAIL
