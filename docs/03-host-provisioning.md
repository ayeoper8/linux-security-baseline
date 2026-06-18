# Host provisioning

## Prerequisites
- Root (or full sudo) access to the host
- **A working named admin account on the host** (sudo group + SSH key + tested
  login) if you want root SSH login disabled. The script checks for one and
  will NOT disable root login without it — it warns instead.
- The script's CONFIGURATION block reviewed (public key, scanner IP; SAS token
  and CrowdStrike CID optional — modules skip cleanly when unset)

## Run
```bash
scp scripts/apply-linux-baseline.sh <user>@<host>:/tmp/
ssh <user>@<host>
sudo bash /tmp/apply-linux-baseline.sh            # standard server
sudo bash /tmp/apply-linux-baseline.sh --role webserver   # opens 80/443
```
Keep your existing SSH session open until you have verified re-entry.

## What it does (modules)
| # | Module | Notes |
|---|---|---|
| M1 | qualys-scanner account, key, sudoers | identical to Tier 1 |
| M2 | sshd hardening drop-in (`/etc/ssh/sshd_config.d/60-example-hardening.conf`) | weak crypto + all SHA1 MACs removed, session limits, banner; validates with `sshd -t`; **reload only, never restart**; drop-in removed and sshd untouched on validation failure; disables root SSH login only if an alternate admin exists (create one in the same run: `--admin-user`/`--admin-key`) |
| M3 | UFW | default deny inbound, 22/tcp from any (see decisions doc), +80/443 for webserver role |
| M4 | unattended-upgrades | security origins only; auto-reboot OFF by default |
| M5 | chrony | pool defaults unless `NTP_SERVERS` set |
| M6 | CrowdStrike | skips with WARN unless CID + installer present |
| M7 | Blob registration | skips with WARN unless SAS token set; never fails the run; prints IP for manual entry |
| M8 | Listener check | flags non-loopback listeners outside the role's expected ports; report-only |
| M9 | ansible-mgmt account | estate enrollment for future config management; skips with WARN unless `ANSIBLE_PUBKEY` set; full NOPASSWD sudo, `from=` restricted to control node (decision #11) |
| M10 | Hardening pack | sysctl network params + core dump restriction, filesystem module blacklist, cron/at restricted to root, login banner. All static, set-once. |
| M0 | Admin account (optional) | `--admin-user NAME --admin-key <pubkey>` creates a sudo admin with key auth in the same run, enabling M2 to disable root login. Set a password afterwards (`passwd NAME`) for sudo prompts. |

## Verify afterwards
1. New terminal: `ssh <admin>@<host>` works; `ssh root@<host>` refused (if root login was disabled)
2. `sudo ufw status` shows active, expected rules
3. Add host IP to the Qualys auth record (manual until central sync exists)
4. Run an authenticated scan: auth passes **and** QID 38909 (SHA1 SSH) no longer reported
5. Script is idempotent — fix any FAIL and re-run

## Rollback
- Scanner account: `userdel -r qualys-scanner && rm /etc/sudoers.d/qualys-scanner`
- ansible-mgmt account: `userdel -r ansible-mgmt && rm /etc/sudoers.d/ansible-mgmt`
- sshd hardening: `rm /etc/ssh/sshd_config.d/60-example-hardening.conf && sshd -t && systemctl reload ssh`
- Firewall: `ufw disable`
- Unattended upgrades: `systemctl disable --now unattended-upgrades`
