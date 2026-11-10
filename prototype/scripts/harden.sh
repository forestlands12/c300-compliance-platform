#!/usr/bin/env bash
# harden.sh - applies our 42-rule CIS baseline (CIS Ubuntu Linux 24.04 LTS v1.0.0) to an Ubuntu server
# Usage:  sudo ./harden.sh --dry-run    show every change, change NOTHING
#         sudo ./harden.sh              apply the changes
# Options (environment variables):
#         SSH_USERS="ace"               who may log in over SSH (CIS 5.1.4). Default: the user running sudo
# Before changing anything it backs up every file it touches and writes rollback.sh, which undoes the changes.

DRY=0; [ "$1" = "--dry-run" ] && DRY=1
[ "$(id -u)" -eq 0 ] || { echo "Please run with sudo"; exit 1; }
SSH_USERS="${SSH_USERS:-${SUDO_USER:-}}"
for u in $SSH_USERS; do id "$u" &>/dev/null || { echo "SSH user '$u' does not exist - stopping (would lock you out)"; exit 1; }; done
[ -n "$SSH_USERS" ] || { echo "Set SSH_USERS, e.g. SSH_USERS=ace - stopping"; exit 1; }

STAMP=$(date +%Y%m%d-%H%M%S)
BK="/home/${SUDO_USER:-root}/fyp-evidence/harden-$STAMP"   # backups + rollback script live here
RB="$BK/rollback.sh"

run()  { echo "  + $*"; [ $DRY -eq 1 ] || bash -c "$*"; }            # show a command; run it unless dry run
undo() { [ $DRY -eq 1 ] || echo "$*" >> "$RB"; }                     # add a line to the rollback script
step() { echo; echo "== $*"; }
newfile() { [ -e "$1" ] || undo "rm -f '$1'"; }                      # if we create a file, rollback deletes it
set_kv() {  # set "key = value" in a config file (replace the active line, or add one)
  local f=$1 k=$2 v=$3
  if grep -Pq "^\h*$k\h*=" "$f"; then run "sed -ri 's/^\\s*$k\\s*=.*/$k = $v/' '$f'"
  else run "echo '$k = $v' >> '$f'"; fi
}
set_sshd() {  # set an SSH option so it is the FIRST occurrence (CIS: above any Include line)
  local k=$1 v=$2
  if grep -Piq "^\h*$k\h" /etc/ssh/sshd_config; then run "sed -ri '0,/^\\s*$k\\s/I s/^\\s*$k\\s.*/$k $v/I' /etc/ssh/sshd_config"
  else run "sed -i '1i $k $v' /etc/ssh/sshd_config"; fi
}

if [ $DRY -eq 1 ]; then
  echo "DRY RUN: nothing will be changed."
else
  mkdir -p "$BK"
  printf '#!/usr/bin/env bash\n# rollback.sh - undoes harden.sh run %s (run with sudo)\nB=%s\n' "$STAMP" "$BK" > "$RB"
  # ---- back up every file/folder this script can change (our "save old values" rule) ----
  for p in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/pam.d /usr/share/pam-configs /etc/security \
           /etc/login.defs /etc/default/useradd /etc/default/grub /etc/crontab /etc/modprobe.d \
           /etc/profile.d /etc/sudoers.d /etc/ufw /var/lib/pam /etc/sysstat; do
    [ -e "$p" ] && cp -a "$p" "$BK/" 
  done
  ufw status verbose > "$BK/ufw-status-before.txt" 2>&1
  awk -F: '($2~/^\$.+\$/){print $1, ($5==""?"-1":$5), ($7==""?"-1":$7)}' /etc/shadow > "$BK/password-ages-before.txt"
  find -L /var/log -type f -exec stat -Lc '%a %n' {} + > "$BK/varlog-modes-before.txt" 2>/dev/null
  echo "Backups saved in $BK"
  # rollback restores whole files first (lines added below undo the rest)
  cat >> "$RB" <<'RBEOF'
cp -a "$B/sshd_config" /etc/ssh/sshd_config
cp -a "$B/sshd_config.d/." /etc/ssh/sshd_config.d/
cp -a "$B/pam.d/." /etc/pam.d/
cp -a "$B/pam-configs/." /usr/share/pam-configs/
cp -a "$B/security/." /etc/security/
cp -a "$B/login.defs" /etc/login.defs
cp -a "$B/useradd" /etc/default/useradd
cp -a "$B/grub" /etc/default/grub
cp -a "$B/crontab" /etc/crontab
cp -a "$B/ufw/." /etc/ufw/
[ -d "$B/pam" ] && cp -a "$B/pam/." /var/lib/pam/          # the login tool's own records, so files and records match
[ -d "$B/sysstat" ] && cp -a "$B/sysstat/." /etc/sysstat/
RBEOF
fi

# =============== 1. Updates and required packages (first, so updates cannot undo later fixes) ===============
step "CIS 1.2.2.1 updates + packages (1.3.1.1 AppArmor, 5.3.2.3 pwquality, 4.2.1 ufw)"
run "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade"
run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q ufw apparmor apparmor-utils libpam-pwquality"
undo "# packages and updates are not removed by rollback - revert the VM snapshot if needed"

# =============== 2. Boot and kernel ===============
step "CIS 1.1.1.9 USB storage"
newfile /etc/modprobe.d/usb-storage.conf
run "printf 'install usb-storage /bin/false\nblacklist usb-storage\n' > /etc/modprobe.d/usb-storage.conf"
run "modprobe -r usb-storage 2>/dev/null; rmmod usb-storage 2>/dev/null; true"

step "CIS 1.3.1.2 AppArmor at boot"
if ! grep -Pq '^GRUB_CMDLINE_LINUX="[^"]*apparmor=1' /etc/default/grub; then
  run "sed -i 's/^GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 apparmor=1 security=apparmor\"/; s/^GRUB_CMDLINE_LINUX=\" /GRUB_CMDLINE_LINUX=\"/' /etc/default/grub"
  run "update-grub"
else echo "  already set"; fi

# =============== 3. Scheduled tasks ===============
step "CIS 2.4.1.2 /etc/crontab"
run "chown root:root /etc/crontab && chmod og-rwx /etc/crontab"

# =============== 4. Firewall ===============
step "CIS 4.2.x firewall (4.2.3 on, 4.2.4 loopback, 4.2.6 open ports, 4.2.7 default deny)"
run "ufw allow proto tcp from any to any port 22"                       # keep SSH reachable BEFORE enabling
for o in "http" "https" "ntp" "to any port 53" "to any port 853" "67/udp"; do run "ufw allow out $o"; done
run "ufw allow in proto udp from any port 67 to any port 68"           # DHCP client replies (port 68)
run "ufw allow in on lo && ufw allow out on lo"
run "ufw deny in from 127.0.0.0/8 && ufw deny in from ::1"
run "ufw default deny incoming && ufw default deny outgoing && ufw default deny routed"
run "ufw logging on"
run "systemctl unmask ufw.service && systemctl --now enable ufw.service && ufw --force enable"
if grep -q "Status: inactive" "$BK/ufw-status-before.txt" 2>/dev/null; then undo "ufw --force reset; ufw disable"; else undo "ufw reload"; fi

# =============== 5. SSH ===============
step "CIS 5.1.x SSH (5.1.1, 5.1.4, 5.1.11, 5.1.14, 5.1.19, 5.1.20)"
set_sshd PermitRootLogin no
set_sshd PermitEmptyPasswords no
set_sshd IgnoreRhosts yes
set_sshd LogLevel INFO
set_sshd AllowUsers "$SSH_USERS"
run "chmod u-x,og-rwx /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config"
run "find /etc/ssh/sshd_config.d -type f -name '*.conf' -exec chmod u-x,og-rwx {} \; -exec chown root:root {} \;"
if [ $DRY -eq 0 ]; then
  if sshd -t; then systemctl reload ssh; echo "  SSH settings tested and applied"
  else echo "  !! SSH settings invalid - restoring the backup"; cp -a "$BK/sshd_config" /etc/ssh/sshd_config; fi
fi
undo "systemctl reload ssh"

# =============== 6. sudo and su ===============
step "CIS 5.2.6 sudo timeout, 5.2.7 su restricted"
newfile /etc/sudoers.d/50-cis-sudo-timeout
run "printf 'Defaults timestamp_timeout=15\n' > /tmp/50-cis-sudo-timeout && visudo -cf /tmp/50-cis-sudo-timeout && install -m 0440 -o root -g root /tmp/50-cis-sudo-timeout /etc/sudoers.d/50-cis-sudo-timeout"
if ! getent group sugroup >/dev/null; then run "groupadd sugroup"; undo "groupdel sugroup"; fi
if ! grep -Pq '^\h*auth\h+required\h+pam_wheel\.so\h+use_uid\h+group=sugroup' /etc/pam.d/su; then
  run "sed -i '/^auth\\s\\+sufficient\\s\\+pam_rootok.so/a auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su"
fi

# =============== 7. Login system (PAM) ===============
step "CIS 5.3.3.2.2 password length"
set_kv /etc/security/pwquality.conf minlen 14
run "rm -f /etc/security/pwquality.conf.d/50-pwlength.conf"             # keep the setting in ONE place

step "CIS 5.3.2.2 + 5.3.3.1.x lockout (deny 4, unlock 900s)"
newfile /usr/share/pam-configs/faillock; newfile /usr/share/pam-configs/faillock_notify
run "printf '%s\n' 'Name: Enable pam_faillock to deny access' 'Default: yes' 'Priority: 0' 'Auth-Type: Primary' 'Auth:' '        [default=die]                    pam_faillock.so authfail' > /usr/share/pam-configs/faillock"
run "printf '%s\n' 'Name: Notify of failed login attempts and reset count upon success' 'Default: yes' 'Priority: 1024' 'Auth-Type: Primary' 'Auth:' '        requisite                       pam_faillock.so preauth' 'Account-Type: Primary' 'Account:' '        required                        pam_faillock.so' > /usr/share/pam-configs/faillock_notify"
set_kv /etc/security/faillock.conf deny 4
set_kv /etc/security/faillock.conf unlock_time 900

step "CIS 5.3.2.4 + 5.3.3.3.1 password history (remember 24)"
newfile /usr/share/pam-configs/pwhistory
run "printf '%s\n' 'Name: pwhistory password history checking' 'Default: yes' 'Priority: 1024' 'Password-Type: Primary' 'Password:' '        requisite                       pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok' > /usr/share/pam-configs/pwhistory"

step "CIS 5.3.3.4.1 remove nullok (no empty passwords)"
run "sed -i 's/\\s\\+nullok\\b//g' /usr/share/pam-configs/unix"

step "Apply PAM profiles"
run "pam-auth-update --enable unix pwquality faillock faillock_notify pwhistory"
if [ $DRY -eq 0 ] && grep -Pq '^\h*[^#\n]*\bpam_unix\.so\b[^#\n]*\bnullok\b' /etc/pam.d/common-{auth,account,password,session,session-noninteractive} 2>/dev/null; then
  echo "  !! pam-auth-update kept 'nullok' in /etc/pam.d - removing it directly (CIS 5.3.3.4.1 note: edit /etc/pam.d when needed)"
  run "sed -ri '/pam_unix\.so/ s/\s+nullok\b//g' /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive"
fi

# =============== 8. Accounts ===============
step "CIS 5.4.1.1 password expiry 365, 5.4.1.5 inactive lock 45"
run "sed -ri 's/^\\s*PASS_MAX_DAYS\\s+[0-9]+/PASS_MAX_DAYS\t365/' /etc/login.defs"
run "useradd -D -f 45"
while read -r u mx ia; do
  [ "$mx" -gt 365 ] || [ "$mx" -lt 1 ] && { run "chage --maxdays 365 $u"; undo "chage --maxdays $mx $u"; }
  [ "$ia" -gt 45 ] || [ "$ia" -lt 0 ] && { run "chage --inactive 45 $u"; undo "chage --inactive $ia $u"; }
done < <(awk -F: '($2~/^\$.+\$/){print $1, ($5==""?"-1":$5), ($7==""?"-1":$7)}' /etc/shadow)

step "CIS 5.4.3.2 idle shell timeout 900s"
newfile /etc/profile.d/50-cis-tmout.sh
run "printf 'TMOUT=900\nreadonly TMOUT\nexport TMOUT\n' > /etc/profile.d/50-cis-tmout.sh"

# =============== 9. Log files ===============
step "CIS 6.1.4.1 new log files private: sysstat UMASK 0027 (found in Lab 6)"
if [ -f /etc/sysstat/sysstat ]; then run "sed -ri 's/^\s*UMASK=.*/UMASK=0027/' /etc/sysstat/sysstat"; else echo "  sysstat not installed"; fi

step "CIS 6.1.4.1 /var/log permissions"
n=0
while IFS= read -r -d $'\0' f; do
  m=$(stat -Lc '%a' "$f")
  case "$(basename "$f")" in
    lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*|README) mask=113; fix="ug-x,o-wx" ;;
    cloud-init.log*|localmessages*|waagent.log*) mask=133; fix="u-x,go-wx" ;;
    SSSD|sssd|gdm|gdm3) mask=117; fix="ug-x,o-rwx" ;;
    *) mask=137; fix="u-x,g-wx,o-rwx"; [[ "$(dirname "$f")" =~ /apt$ ]] && { mask=133; fix="u-x,go-wx"; } ;;
  esac
  if (( 8#$m & 8#$mask )); then run "chmod $fix '$f'"; undo "chmod $m '$f'"; n=$((n+1)); fi
done < <(find -L /var/log -type f -print0 2>/dev/null)
echo "  log files fixed: $n"

# =============== finish ===============
undo "update-grub; systemctl reload ssh; echo 'Rollback finished - reboot recommended'"
echo
if [ $DRY -eq 1 ]; then echo "DRY RUN finished: nothing was changed."
else chmod +x "$RB"; echo "Done. Backups: $BK"; echo "Undo everything with: sudo $RB"; echo "Next: reboot, wait 3 minutes, then run: sudo ~/fyp-scan.sh"; fi
