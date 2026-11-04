#!/usr/bin/env bash
# fyp-scan.sh - our compliance scanner for UBU-WEB: all 42 "Keep" rules (CIS Ubuntu Linux 24.04 LTS v1.0.0)
# Each check uses the audit method from the CIS PDF.
# Run with: sudo ./fyp-scan.sh
# Output: host|check_id|title|expected|actual|status|timestamp   (+ a score line at the end)

host=$(hostname)                         # which machine we are checking
ts=$(date --iso-8601=seconds)            # when we checked it
pass=0; total=0                          # counters for our compliance score

report() {                               # prints one finding and updates the score
  echo "$host|$1|$2|$3|$4|$5|$ts"
  total=$((total+1)); [ "$5" = PASS ] && pass=$((pass+1))
}
sshd_val() {                             # reads the value SSH is really using for one setting
  sshd -T 2>/dev/null | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }'
}

# ===== Lab 1-2 rules =====
a=$(sshd_val permitrootlogin)
[ "$a" = "no" ] && s=PASS || s=FAIL
report "CIS-5.1.20" "SSH root login disabled" "no" "$a" "$s"

a=$(sshd_val permitemptypasswords)
[ "$a" = "no" ] && s=PASS || s=FAIL
report "CIS-5.1.19" "SSH empty passwords disabled" "no" "$a" "$s"

a=$(grep -Phs '^\h*minlen\h*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | tail -n 1 | tr -dc '0-9')
if [ -n "$a" ] && [ "$a" -ge 14 ]; then s=PASS; else s=FAIL; a=${a:-"not set"}; fi
report "CIS-5.3.3.2.2" "Minimum password length" ">=14" "$a" "$s"

a=$(ufw status | awk 'NR==1{print $2}')
[ "$a" = "active" ] && s=PASS || s=FAIL
report "CIS-4.2.3" "Firewall (ufw) active" "active" "$a" "$s"

a=$(ufw status verbose | grep '^Default:' | sed 's/^Default: //')
if echo "$a" | grep -Pq '^(deny|reject) \(incoming\), (deny|reject) \(outgoing\), (deny|reject|disabled) \(routed\)'; then s=PASS; else s=FAIL; a=${a:-"firewall inactive"}; fi
report "CIS-4.2.7" "Firewall default deny" "deny in/out" "$a" "$s"

# ===== Lab 3 rules =====
# CIS 5.1.1: sshd_config (and drop-in .conf files) must be mode 600 or stricter, owned root:root
s=PASS; a=""
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ -e "$f" ] || continue
  read -r m u g < <(stat -Lc '%a %U %G' "$f")
  a="$a $(basename "$f")=$m:$u:$g"
  if (( 8#$m & 8#177 )) || [ "$u" != root ] || [ "$g" != root ]; then s=FAIL; fi
done
[ -z "$a" ] && { s=FAIL; a="file missing"; }
report "CIS-5.1.1" "SSH config file permissions" "600 root:root" "${a# }" "$s"

# CIS 5.1.4: SSH must limit who can log in (AllowUsers/AllowGroups/DenyUsers/DenyGroups)
a=$(sshd -T 2>/dev/null | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+' | tr '\n' ' ')
[ -n "$a" ] && s=PASS || { s=FAIL; a="not set"; }
report "CIS-5.1.4" "SSH access limited to named users" "allowusers <list>" "${a% }" "$s"

# CIS 5.1.11: SSH ignores old .rhosts trust files
a=$(sshd_val ignorerhosts)
[ "$a" = "yes" ] && s=PASS || s=FAIL
report "CIS-5.1.11" "SSH IgnoreRhosts enabled" "yes" "$a" "$s"

# CIS 5.1.14: SSH logging level is INFO or VERBOSE
a=$(sshd_val loglevel)
[[ "$a" =~ ^(INFO|VERBOSE)$ ]] && s=PASS || s=FAIL
report "CIS-5.1.14" "SSH LogLevel" "INFO or VERBOSE" "$a" "$s"

# CIS 5.2.6: sudo re-asks for the password after 15 minutes or less
vals=$(grep -rhoP 'timestamp_timeout=\K-?[0-9]+' /etc/sudoers /etc/sudoers.d 2>/dev/null | tr '\n' ' ')
if [ -z "$vals" ]; then a="not set (default 15)"; s=PASS
else a="${vals% }"; s=PASS; for v in $vals; do { [ "$v" -lt 0 ] || [ "$v" -gt 15 ]; } && s=FAIL; done; fi
report "CIS-5.2.6" "sudo timeout" "<=15 min" "$a" "$s"

# CIS 5.2.7: only members of an EMPTY group may use su
grp=$(grep -Pi '^\h*auth\h+(required|requisite)\h+pam_wheel\.so\b' /etc/pam.d/su | grep -w use_uid | grep -oP 'group=\K\H+' | head -n 1)
if [ -n "$grp" ]; then
  members=$(getent group "$grp" | cut -d: -f4)
  a="group=$grp members=${members:-none}"
  [ -z "$members" ] && s=PASS || s=FAIL
else a="not restricted"; s=FAIL; fi
report "CIS-5.2.7" "su restricted to empty group" "pam_wheel + empty group" "$a" "$s"

# CIS 5.4.1.1: passwords expire after 365 days or less (default AND every existing user)
d=$(grep -Pi '^\h*PASS_MAX_DAYS\h+\d+' /etc/login.defs | awk '{print $2}' | tail -n 1)
bad=$(awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1) print $1}' /etc/shadow | tr '\n' ' ')
a="login.defs=${d:-none} users_over=${bad:-none}"
if [ -n "$d" ] && [ "$d" -ge 1 ] && [ "$d" -le 365 ] && [ -z "$bad" ]; then s=PASS; else s=FAIL; fi
report "CIS-5.4.1.1" "Password expiry" "<=365 days" "${a% }" "$s"

# CIS 5.4.1.5: unused accounts lock 45 days or less after the password expires
d=$(useradd -D | awk -F= '/^INACTIVE/{print $2}')
bad=$(awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0) print $1}' /etc/shadow | tr '\n' ' ')
a="default=${d} users_over=${bad:-none}"
if [ "$d" -ge 0 ] && [ "$d" -le 45 ] && [ -z "$bad" ]; then s=PASS; else s=FAIL; fi
report "CIS-5.4.1.5" "Inactive password lock" "<=45 days" "${a% }" "$s"

# CIS 5.4.3.2: idle shells log out after 900 seconds or less (TMOUT set, readonly, exported)
f_ok=""
for f in /etc/bashrc /etc/profile /etc/profile.d/*.sh; do
  [ -f "$f" ] || continue
  grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" &&
  grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT\b' "$f" &&
  grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT\b' "$f" && f_ok="$f"
done
bad=$(grep -Phs '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc)
if [ -n "$f_ok" ] && [ -z "$bad" ]; then s=PASS; a="set in $f_ok"; else s=FAIL; a=${bad:-"not set"}; fi
report "CIS-5.4.3.2" "Idle shell timeout" "TMOUT<=900" "$a" "$s"

# ===== Lab 4 rules (login system / PAM) =====
# CIS 5.3.2.2: pam_faillock is switched on (preauth + authfail in common-auth, and in common-account)
pre=$(grep -Pc '^\h*auth\h+\S+.*\bpam_faillock\.so\h+preauth\b' /etc/pam.d/common-auth)
fail=$(grep -Pc '^\h*auth\h+\S+.*\bpam_faillock\.so\h+authfail\b' /etc/pam.d/common-auth)
acct=$(grep -Pc '^\h*account\h+\S+.*\bpam_faillock\.so\b' /etc/pam.d/common-account)
a="preauth=$pre authfail=$fail account=$acct"
[ "$pre" -ge 1 ] && [ "$fail" -ge 1 ] && [ "$acct" -ge 1 ] && s=PASS || s=FAIL
report "CIS-5.3.2.2" "Account lockout module enabled" "preauth+authfail+account" "$a" "$s"

# CIS 5.3.3.1.1: lock the account after 5 or fewer failed logins
d=$(grep -Pi '^\h*deny\h*=\h*\d+' /etc/security/faillock.conf | tr -dc '0-9')
badpam=$(grep -Pi '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth)
if [ -n "$d" ] && [ "$d" -ge 1 ] && [ "$d" -le 5 ] && [ -z "$badpam" ]; then s=PASS; a="deny=$d"; else s=FAIL; a="deny=${d:-not set}"; fi
report "CIS-5.3.3.1.1" "Lockout after failed logins" "deny 1-5" "$a" "$s"

# CIS 5.3.3.3.1: remember the last 24+ passwords (no reuse)
r=$(grep -Psi '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b' /etc/pam.d/common-password | grep -oP 'remember=\K\d+' | head -n 1)
if [ -n "$r" ] && [ "$r" -ge 24 ]; then s=PASS; a="remember=$r"; else s=FAIL; a="remember=${r:-not set}"; fi
report "CIS-5.3.3.3.1" "Password history" "remember>=24" "$a" "$s"

# CIS 5.3.3.4.1: pam_unix must NOT have "nullok" (which allows empty passwords)
n=$(grep -PHs '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} | cut -d: -f1 | xargs -r -n1 basename | tr '\n' ' ')
if [ -z "$n" ]; then s=PASS; a="no nullok"; else s=FAIL; a="nullok in: ${n% }"; fi
report "CIS-5.3.3.4.1" "No empty passwords (nullok removed)" "no nullok" "$a" "$s"

# ===== Lab 5 rules =====
modechk() {   # usage: modechk FILE MASK OWNER_REGEX GROUP_REGEX -> sets a (actual) and s (PASS/FAIL)
  if [ ! -e "$1" ]; then a="missing"; s=FAIL; return; fi
  read -r m u g < <(stat -Lc '%a %U %G' "$1"); a="$m:$u:$g"
  if (( 8#$m & 8#$2 )) || [[ ! "$u" =~ ^($3)$ ]] || [[ ! "$g" =~ ^($4)$ ]]; then s=FAIL; else s=PASS; fi
}
pkg() { dpkg-query -s "$1" &>/dev/null; }   # true if a package is installed

# CIS 1.1.1.9: USB storage driver cannot be loaded (deny listed + install /bin/false + not loaded)
if ls -d /lib/modules/*/kernel/drivers/usb/storage &>/dev/null; then
  cfg=$(modprobe --showconfig 2>/dev/null | grep -P '\b(install|blacklist)\h+usb_storage\b')
  ins=$(grep -Pc '\binstall\h+usb_storage\h+(/usr)?/bin/(true|false)\b' <<< "$cfg")
  bl=$(grep -Pc '\bblacklist\h+usb_storage\b' <<< "$cfg")
  ld=$(lsmod | grep -c '^usb_storage\b')
  a="install_false=$ins blacklisted=$bl loaded=$ld"
  [ "$ins" -ge 1 ] && [ "$bl" -ge 1 ] && [ "$ld" -eq 0 ] && s=PASS || s=FAIL
else a="module not present"; s=PASS; fi
report "CIS-1.1.1.9" "USB storage disabled" "not loadable" "$a" "$s"

# CIS 1.3.1.1: AppArmor and its tools are installed
a="apparmor=$(pkg apparmor && echo yes || echo no) apparmor-utils=$(pkg apparmor-utils && echo yes || echo no)"
[[ "$a" == "apparmor=yes apparmor-utils=yes" ]] && s=PASS || s=FAIL
report "CIS-1.3.1.1" "AppArmor installed" "both packages" "$a" "$s"

# CIS 1.3.1.2: every boot entry turns AppArmor on (apparmor=1 security=apparmor)
miss=$(grep "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -v "apparmor=1" | wc -l)
miss2=$(grep "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -v "security=apparmor" | wc -l)
a="entries_missing_apparmor=$miss entries_missing_security=$miss2"
[ "$miss" -eq 0 ] && [ "$miss2" -eq 0 ] && s=PASS || s=FAIL
[ -r /boot/grub/grub.cfg ] && grep -q "^\s*linux" /boot/grub/grub.cfg || { a="grub.cfg not readable"; s=FAIL; }
report "CIS-1.3.1.2" "AppArmor enabled at boot" "all boot entries" "$a" "$s"

# CIS 1.2.2.1 (Manual in CIS, automated by us): no pending updates (uses the last 'apt update')
n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')
a="pending_updates=$n"; [ "$n" -eq 0 ] && s=PASS || s=FAIL
report "CIS-1.2.2.1" "Security updates installed" "0 pending" "$a" "$s"

# CIS 2.1.1: autofs not installed (or not enabled/active)
if pkg autofs; then
  en=$(systemctl is-enabled autofs.service 2>/dev/null); ac=$(systemctl is-active autofs.service 2>/dev/null)
  a="installed enabled=$en active=$ac"; { [ "$en" != enabled ] && [ "$ac" != active ]; } && s=PASS || s=FAIL
else a="not installed"; s=PASS; fi
report "CIS-2.1.1" "autofs not in use" "not installed" "$a" "$s"

# CIS 2.4.1.2: /etc/crontab mode 600, root:root
modechk /etc/crontab 077 root root
report "CIS-2.4.1.2" "/etc/crontab permissions" "600 root:root" "$a" "$s"

# CIS 4.1.1: exactly one firewall tool enabled and active
act=""
for fw in ufw nftables iptables; do
  cmd=$fw; [ $fw = nftables ] && cmd=nft
  command -v $cmd &>/dev/null && systemctl is-enabled --quiet $fw 2>/dev/null && systemctl is-active --quiet $fw 2>/dev/null && act="$act $fw"
done
a="${act# }"; [ "$(wc -w <<< "$act")" -eq 1 ] && s=PASS || { s=FAIL; a=${a:-none}; }
report "CIS-4.1.1" "Single firewall tool in use" "exactly one" "$a" "$s"

# CIS 4.2.1: ufw installed
pkg ufw && { a=installed; s=PASS; } || { a="not installed"; s=FAIL; }
report "CIS-4.2.1" "ufw installed" "installed" "$a" "$s"

# CIS 4.2.4: loopback allowed on lo, and traffic claiming to be loopback blocked on other cards
lo=$(grep -Pc -- '-A ufw-before-(input -i|output -o) lo -j ACCEPT' /etc/ufw/before.rules 2>/dev/null); lo=${lo:-0}
v=$(ufw status verbose)
d4=$(grep -Pc 'DENY IN\s+127\.0\.0\.0/8' <<< "$v"); d6=$(grep -Pc 'DENY IN\s+::1\b' <<< "$v")
a="lo_accept=$lo deny_127=$d4 deny_::1=$d6"
[ "$lo" -ge 2 ] && [ "$d4" -ge 1 ] && [ "$d6" -ge 1 ] && s=PASS || s=FAIL
report "CIS-4.2.4" "Firewall loopback rules" "lo allowed, 127/8 denied" "$a" "$s"

# CIS 4.2.6: every open port has a firewall rule (CIS audit logic)
fwp=$(ufw status verbose | grep -Po '^\h*\d+\b' | sort -u)
opn=$(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}' | grep -v '^$' | sort -u)
miss=$(printf '%s\n' $opn $fwp $fwp | sort | uniq -u | tr '\n' ' ')
a="open=$(echo $opn | tr ' ' ',') missing_rule=${miss:-none}"; a=${a% }
[ -z "${miss// }" ] && s=PASS || s=FAIL
command -v ss &>/dev/null || { a="ss command missing"; s=FAIL; }
report "CIS-4.2.6" "Firewall rule for every open port" "no missing" "$a" "$s"

# CIS 5.1.2: SSH private host keys readable by root only (600, or 640 with group ssh_keys)
s=PASS; a=""
for k in /etc/ssh/ssh_host_*_key; do
  [ -e "$k" ] || continue
  read -r m u g < <(stat -Lc '%a %U %G' "$k"); a="$a $(basename "$k")=$m"
  mask=177; [ "$g" = ssh_keys ] && mask=137
  if (( 8#$m & 8#$mask )) || [ "$u" != root ]; then s=FAIL; fi
done
[ -z "$a" ] && { a="no host keys found"; s=FAIL; }
report "CIS-5.1.2" "SSH private host key permissions" "600 root" "${a# }" "$s"

# CIS 5.1.22: SSH uses PAM (so all our password rules apply to SSH)
a=$(sshd_val usepam); [ "$a" = yes ] && s=PASS || s=FAIL
report "CIS-5.1.22" "SSH UsePAM enabled" "yes" "$a" "$s"

# CIS 5.2.1: sudo installed
{ pkg sudo || pkg sudo-ldap; } && { a=installed; s=PASS; } || { a="not installed"; s=FAIL; }
report "CIS-5.2.1" "sudo installed" "installed" "$a" "$s"

# CIS 5.3.2.3: password-strength module switched on
grep -Pq '\bpam_pwquality\.so\b' /etc/pam.d/common-password && { a=enabled; s=PASS; } || { a="not enabled"; s=FAIL; }
report "CIS-5.3.2.3" "Password strength module enabled" "enabled" "$a" "$s"

# CIS 5.4.2.4: root account has a password or is locked
a=$(passwd -S root | awk '{print $2}'); [[ "$a" =~ ^(P|L)$ ]] && s=PASS || s=FAIL
report "CIS-5.4.2.4" "Root account access controlled" "P or L" "$a" "$s"

# CIS 5.4.2.7: system (service) accounts cannot log in (CIS audit logic)
vs="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"
umin=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
bad=$(awk -v pat="$vs" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$umin"' || $3 == 65534) && $(NF) ~ pat) {print $1}' /etc/passwd | tr '\n' ' ')
[ -z "$bad" ] && { a=none; s=PASS; } || { a="${bad% }"; s=FAIL; }
report "CIS-5.4.2.7" "Service accounts have no login shell" "none" "$a" "$s"

# CIS 6.1.1.1: journald running
en=$(systemctl is-enabled systemd-journald.service 2>/dev/null); ac=$(systemctl is-active systemd-journald.service 2>/dev/null)
a="enabled=$en active=$ac"; [ "$en" = static ] && [ "$ac" = active ] && s=PASS || s=FAIL
report "CIS-6.1.1.1" "journald running" "static/active" "$a" "$s"

# CIS 6.1.3.1 and 6.1.3.2: rsyslog installed, enabled and active
pkg rsyslog && { a=installed; s=PASS; } || { a="not installed"; s=FAIL; }
report "CIS-6.1.3.1" "rsyslog installed" "installed" "$a" "$s"
en=$(systemctl is-enabled rsyslog 2>/dev/null); ac=$(systemctl is-active rsyslog 2>/dev/null)
a="enabled=$en active=$ac"; [ "$en" = enabled ] && [ "$ac" = active ] && s=PASS || s=FAIL
report "CIS-6.1.3.2" "rsyslog running" "enabled/active" "$a" "$s"

# CIS 6.1.4.1: log files in /var/log not readable/writable by everyone (permission part of the CIS audit)
bad=0; ex=""
while IFS= read -r -d $'\0' f; do
  m=$(stat -Lc '%a' "$f")
  case "$(basename "$f")" in
    lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*|README) mask=113 ;;
    cloud-init.log*|localmessages*|waagent.log*) mask=133 ;;
    SSSD|sssd|gdm|gdm3) mask=117 ;;
    *) mask=137; [[ "$(dirname "$f")" =~ /apt$ ]] && mask=133 ;;
  esac
  if (( 8#$m & 8#$mask )); then bad=$((bad+1)); [ -z "$ex" ] && ex=" e.g. ${f}=$m"; fi
done < <(find -L /var/log -type f -print0 2>/dev/null)
a="files_too_open=$bad$ex"; [ "$bad" -eq 0 ] && s=PASS || s=FAIL
report "CIS-6.1.4.1" "Log file permissions" "0 too open" "$a" "$s"

# CIS 7.1.1: /etc/passwd 644 or stricter, root:root
modechk /etc/passwd 133 root root
report "CIS-7.1.1" "/etc/passwd permissions" "644 root:root" "$a" "$s"

# CIS 7.1.5: /etc/shadow 640 or stricter, owner root, group root or shadow
modechk /etc/shadow 137 root "root|shadow"
report "CIS-7.1.5" "/etc/shadow permissions" "640 root:shadow" "$a" "$s"

# CIS 7.1.11: no world-writable files; world-writable folders must have the sticky bit
wf=$(find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /snap \) -prune -o -type f -perm -0002 -print 2>/dev/null | wc -l)
wd=$(find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /snap \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | wc -l)
a="ww_files=$wf ww_dirs_no_sticky=$wd"; [ "$wf" -eq 0 ] && [ "$wd" -eq 0 ] && s=PASS || s=FAIL
report "CIS-7.1.11" "No world-writable files" "0 and 0" "$a" "$s"

# CIS 7.2.2: no account has an empty password field
bad=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow | tr '\n' ' ')
[ -z "$bad" ] && { a=none; s=PASS; } || { a="${bad% }"; s=FAIL; }
report "CIS-7.2.2" "No empty password fields" "none" "$a" "$s"

# ===== Our compliance score =====
echo "$host|SCORE|Compliance score|$total rules|$pass passed|$(( pass*100/total ))%|$ts"
