# Linux Collection Plan (PrivacyWarden)
# Target: Ubuntu 22.04+, Fedora 38+, Arch
# Script: linux-collect.sh (POSIX sh + systemd integration)

## Top-level additions

### Linux Profile
New profile tag: "linux" — all linux steps tagged.

### New Functions
- name: SetSysctlParameter
  parameters: [key, value, persist (default: "true")]
  code: sysctl -w {key}={value}; if persist: echo "{key}={value}" >> /etc/sysctl.d/99-privacywarden.conf
  checkCode: sysctl {key} | grep -q "{value}"
  revertCode: sed -i "/^{key}=/d" /etc/sysctl.d/99-privacywarden.conf; sysctl -w {key}=0

- name: DisableSystemdService
  parameters: [serviceName]
  code: systemctl stop {serviceName}; systemctl disable {serviceName}
  checkCode: systemctl is-enabled {serviceName} | grep -q "disabled"
  revertCode: systemctl enable {serviceName}; systemctl start {serviceName}

- name: BlockViaIptables
  parameters: [direction, protocol, dport, comment]
  code: iptables -{direction} {protocol} --dport {dport} -j DROP -m comment --comment "{comment}"
  checkCode: iptables -L -n | grep -q "{comment}"
  revertCode: iptables -D {direction} {protocol} --dport {dport} -j DROP

### New Category: Linux Hardening
LIN01 - Disable IP forwarding (sysctl net.ipv4.ip_forward=0)
LIN02 - Disable IPv6 if not needed (sysctl net.ipv6.conf.all.disable_ipv6=1)
LIN03 - Harden SSH config (PermitRootLogin no, PasswordAuthentication no, Port change)
LIN04 - Enable firewall (ufw default deny, allow 22/tcp, 80/tcp, 443/tcp)
LIN05 - Disable Apport crash reporting (systemctl mask apport)
LIN06 - Enable auditd (systemctl enable auditd)
LIN07 - Harden kernel parameters (kernel.kptr_restrict=2, kernel.dmesg_restrict=1)
LIN08 - Disable unnecessary services (cups, avahi-daemon, bluetooth)
LIN09 - Block outgoing DNS (only allow systemd-resolved via 9.9.9.9)
LIN10 - Disable core dumps (limits.conf + sysctl fs.suid_dumpable=0)

### Categories
- Linux Hardening (LIN01-LIN10)
- Linux Network (LIN11-LIN15 — firewall, DNS hardening, network lockdown)

## Integration
- Shell script: scripts/linux-collect.sh
- YAML collection: collections/linux.yaml
- Encrypted: collections/linux.bin (v3 scheme)
