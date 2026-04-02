#!/bin/bash

# auto fix kalau ada CRLF (windows line ending)
[ -f "$0" ] && sed -i 's/\r$//' "$0" 2>/dev/null || true

set -e

echo "[+] STOP & REMOVE BACKDOOR SERVICE"

systemctl stop defunct.service 2>/dev/null || true
systemctl disable defunct.service 2>/dev/null || true

systemctl stop gs-dbus.service 2>/dev/null || true
systemctl disable gs-dbus.service 2>/dev/null || true

rm -f /etc/systemd/system/defunct.service
rm -f /lib/systemd/system/defunct.service

rm -f /etc/systemd/system/gs-dbus.service
rm -f /lib/systemd/system/gs-dbus.service

rm -f /etc/systemd/system/multi-user.target.wants/defunct.service
rm -f /etc/systemd/system/multi-user.target.wants/gs-dbus.service


echo "[+] REMOVE BACKDOOR BINARIES"

rm -f /usr/bin/defunct
rm -f /usr/bin/gs-dbus
rm -f /lib/systemd/system/defunct.dat


echo "[+] FIX DBUS"

systemctl unmask dbus.service || true
systemctl unmask dbus.socket || true

systemctl daemon-reexec
systemctl daemon-reload

systemctl restart dbus.service || true


echo "[+] CREATE PROTECTION (ANTI RE-CREATE FILE)"

touch /usr/bin/defunct
touch /usr/bin/gs-dbus
touch /lib/systemd/system/defunct.dat

chmod 000 /usr/bin/defunct
chmod 000 /usr/bin/gs-dbus
chmod 000 /lib/systemd/system/defunct.dat


echo "[+] CREATE SYSTEMD GUARD (MONITOR AUTO DELETE)"

cat > /etc/systemd/system/anti-backdoor.service << 'EOF'
[Unit]
Description=Anti Backdoor Guard
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do rm -f /usr/bin/defunct /usr/bin/gs-dbus /lib/systemd/system/defunct.dat; sleep 60; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable anti-backdoor.service
systemctl start anti-backdoor.service

echo "[+] DONE. SYSTEM CLEAN & PROTECTED"
