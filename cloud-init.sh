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
  python3 python3-pip python3-flask \
  jq net-tools dialog

# Move admin SSH to non-standard port
sed -i "s/^#Port 22/Port ${admin_ssh_port}/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port ${admin_ssh_port}/" /etc/ssh/sshd_config
grep -q "^Port ${admin_ssh_port}" /etc/ssh/sshd_config || echo "Port ${admin_ssh_port}" >> /etc/ssh/sshd_config

# Disable password authentication
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Ubuntu 24.04 ships ssh as socket-activated (ssh.socket), which makes the
# Port directive in sshd_config a no-op. Switch to the traditional service
# so our custom port takes effect.
systemctl disable --now ssh.socket 2>/dev/null || true
systemctl enable ssh.service
systemctl restart ssh.service

# -------------------------------------------------------------------
# 2. Backup SSH keys before DShield install
# DShield's install.sh can rewrite/move authorized_keys; we restore them
# afterwards and on every boot via dshield-extras.service.
# -------------------------------------------------------------------
mkdir -p /root/.ssh-backup
chmod 700 /root/.ssh-backup
if [ -f /home/ubuntu/.ssh/authorized_keys ]; then
  cp -a /home/ubuntu/.ssh/authorized_keys /root/.ssh-backup/ubuntu.authorized_keys
fi
if [ -f /root/.ssh/authorized_keys ]; then
  cp -a /root/.ssh/authorized_keys /root/.ssh-backup/root.authorized_keys
fi

# -------------------------------------------------------------------
# 3. Pre-write dshield.ini so install.sh --update runs silently
# -------------------------------------------------------------------
PUBLIC_IP=$(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")

mkdir -p /etc/
cat > /etc/dshield.ini << INIEOF
[DShield]
userid=${dshield_userid}
apikey=${dshield_apikey}
email=${dshield_email}
interface=ens5
adminport=${admin_ssh_port}
localnet=10.0.0.0/8 ${admin_ip}/32
nofwlogging=10.0.0.0/8 ${admin_ip}/32
honeypotip=$PUBLIC_IP
authenticationkey=${dshield_apikey}
INIEOF

chmod 600 /etc/dshield.ini

# -------------------------------------------------------------------
# 4. postinstall.sh — DShield runs this after every install/update.
# Restores UFW (DShield removes it during install) and SSH keys.
# -------------------------------------------------------------------
mkdir -p /root/bin
cat > /root/bin/postinstall.sh << POSTINSTALL
#!/bin/bash
set -u

apt-get install -y ufw

ufw allow from ${admin_ip} to any port ${admin_ssh_port} proto tcp comment "Admin SSH"
ufw allow 22/tcp comment "DShield SSH decoy"
ufw allow 23/tcp comment "DShield Telnet decoy"
ufw allow 80/tcp comment "DShield HTTP decoy"
ufw allow from ${admin_ip} to any port 8888 proto tcp comment "Dashboard (admin only)"
ufw --force enable

if [ -f /root/.ssh-backup/ubuntu.authorized_keys ]; then
  install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
  install -m 0600 -o ubuntu -g ubuntu \
    /root/.ssh-backup/ubuntu.authorized_keys \
    /home/ubuntu/.ssh/authorized_keys
fi
POSTINSTALL
chmod +x /root/bin/postinstall.sh

# -------------------------------------------------------------------
# 5. Clone and install DShield in unattended mode
# -------------------------------------------------------------------
cd /opt
git clone https://github.com/DShield-ISC/dshield.git

# install.sh runs sudo internally and creates files under /opt/dshield.
# Ensure the ubuntu user owns the tree before invocation.
chown -R ubuntu:ubuntu /opt/dshield

cd /opt/dshield
sudo -u ubuntu bash bin/install.sh --update || true

# -------------------------------------------------------------------
# 6. Restore SSH keys (DShield may have clobbered them)
# -------------------------------------------------------------------
install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
if [ -f /root/.ssh-backup/ubuntu.authorized_keys ]; then
  install -m 0600 -o ubuntu -g ubuntu \
    /root/.ssh-backup/ubuntu.authorized_keys \
    /home/ubuntu/.ssh/authorized_keys
fi
if [ -f /root/.ssh-backup/root.authorized_keys ]; then
  install -m 0600 -o root -g root \
    /root/.ssh-backup/root.authorized_keys \
    /root/.ssh/authorized_keys
fi

# -------------------------------------------------------------------
# 7. fail2ban - protect admin SSH port
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
# 8. Threat intel dashboard (Flask, port 8888)
# -------------------------------------------------------------------
install -d -m 0755 /opt/dshield-dashboard
REPO_RAW="https://raw.githubusercontent.com/0xAlexN/dshield-honeypot-aws/main"
curl -sf "$REPO_RAW/dashboard/app.py" -o /opt/dshield-dashboard/app.py
chmod 0644 /opt/dshield-dashboard/app.py

curl -sf "$REPO_RAW/dashboard/dshield-dashboard.service" -o /etc/systemd/system/dshield-dashboard.service

systemctl daemon-reload
systemctl enable dshield-dashboard.service
systemctl restart dshield-dashboard.service

# -------------------------------------------------------------------
# 9. dshield-extras: re-apply admin iptables rules + SSH keys on boot.
# DShield's firewall script flushes iptables at boot, so admin SSH and
# the dashboard port need to be re-inserted into INPUT after it runs.
# -------------------------------------------------------------------
cat > /usr/local/sbin/dshield-extras.sh << 'EXTRAS'
#!/bin/bash
set -u
ADMIN_IP="__ADMIN_IP__"
ADMIN_PORT="__ADMIN_PORT__"

# Give DShield's firewall a moment to finish setting up
sleep 30

# Restore SSH keys if DShield wiped them on boot
if [ -f /root/.ssh-backup/ubuntu.authorized_keys ]; then
  install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
  install -m 0600 -o ubuntu -g ubuntu \
    /root/.ssh-backup/ubuntu.authorized_keys \
    /home/ubuntu/.ssh/authorized_keys
fi

# Re-insert admin firewall rules at the top of INPUT (idempotent)
for PORT in "$ADMIN_PORT" 8888; do
  iptables -C INPUT -p tcp -s "$ADMIN_IP" --dport "$PORT" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp -s "$ADMIN_IP" --dport "$PORT" -j ACCEPT
done
EXTRAS

# Substitute the runtime values into the script (kept literal in the heredoc
# so the cloud-init template engine does not try to expand the shell vars).
sed -i "s|__ADMIN_IP__|${admin_ip}|g; s|__ADMIN_PORT__|${admin_ssh_port}|g" \
  /usr/local/sbin/dshield-extras.sh
chmod 0755 /usr/local/sbin/dshield-extras.sh

cat > /etc/systemd/system/dshield-extras.service << 'UNIT'
[Unit]
Description=DShield extras (preserve admin access after DShield firewall reset)
After=multi-user.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dshield-extras.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable dshield-extras.service

# -------------------------------------------------------------------
# 10. Cron: weekly status check + @reboot SSH key restore (belt-and-
# suspenders alongside dshield-extras.service, in case the unit is
# delayed or fails after a DShield-triggered reboot).
# -------------------------------------------------------------------
echo "0 6 * * 1 ubuntu /opt/dshield/bin/status.sh >> /var/log/dshield-status.log 2>&1" \
  > /etc/cron.d/dshield-check

cat > /etc/cron.d/dshield-ssh-restore << 'CRON'
@reboot root sleep 60 && install -m 0600 -o ubuntu -g ubuntu /root/.ssh-backup/ubuntu.authorized_keys /home/ubuntu/.ssh/authorized_keys
CRON

echo "=== Bootstrap complete — rebooting ==="
reboot
