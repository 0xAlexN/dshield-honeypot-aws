#!/bin/bash
set -euo pipefail
exec > /var/log/dshield-init.log 2>&1

echo "=== DShield Honeypot Bootstrap ==="

# -------------------------------------------------------------------
# 1. Base hardening
# -------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl wget unzip fail2ban ufw \
  python3 python3-pip \
  jq net-tools dialog

# Move admin SSH to non-standard port
sed -i "s/^#Port 22/Port ${admin_ssh_port}/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port ${admin_ssh_port}/" /etc/ssh/sshd_config
grep -q "^Port ${admin_ssh_port}" /etc/ssh/sshd_config || echo "Port ${admin_ssh_port}" >> /etc/ssh/sshd_config

# Disable password authentication
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

systemctl restart sshd

# -------------------------------------------------------------------
# 2. Pre-write dshield.ini so install.sh --update runs silently
# -------------------------------------------------------------------
# Retrieve instance public IP from metadata
PUBLIC_IP=$(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")
ADMIN_NET="${admin_ip}/32"

mkdir -p /etc/
cat > /etc/dshield.ini << INIEOF
[DShield]
userid=${dshield_email}
apikey=${dshield_apikey}
email=${dshield_email}
interface=ens5
adminport=${admin_ssh_port}
localnet=10.0.0.0/8 ${admin_ip}/32
nofwlog=10.0.0.0/8 ${admin_ip}/32
honeypotip=$PUBLIC_IP
authenticationkey=${dshield_apikey}
INIEOF

chmod 600 /etc/dshield.ini

# -------------------------------------------------------------------
# 3. Clone and install DShield in unattended mode
# -------------------------------------------------------------------
cd /opt
git clone https://github.com/DShield-ISC/dshield.git

# Fix permissions for SSL cert generation
chown -R admin:admin /opt/dshield/

# Run in --update mode: uses dshield.ini, no interactive prompts
cd /opt/dshield
sudo -u admin bash bin/install.sh --update || true

# -------------------------------------------------------------------
# 4. UFW firewall rules
# -------------------------------------------------------------------
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ${admin_ssh_port}/tcp comment "Admin SSH"
ufw allow 22/tcp  comment "DShield SSH decoy"
ufw allow 23/tcp  comment "DShield Telnet decoy"
ufw allow 80/tcp  comment "DShield HTTP decoy"
ufw --force enable

# -------------------------------------------------------------------
# 5. fail2ban - protect admin SSH port
# -------------------------------------------------------------------
cat > /etc/fail2ban/jail.local << JAIL
[sshd]
enabled  = true
port     = ${admin_ssh_port}
maxretry = 3
bantime  = 3600
JAIL

systemctl enable fail2ban
systemctl restart fail2ban

# -------------------------------------------------------------------
# 6. Weekly status check cron
# -------------------------------------------------------------------
echo "0 6 * * 1 admin /opt/dshield/bin/status.sh >> /var/log/dshield-status.log 2>&1" \
  > /etc/cron.d/dshield-check

echo "=== Bootstrap complete — rebooting ==="
reboot