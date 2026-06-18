# Linux Security Baseline

A single, idempotent Bash script that brings a Linux host to a CIS-aligned
security baseline in one non-interactive run — SSH hardening, host firewall,
automated patching, kernel hardening, EDR deployment, and Azure Key Vault–backed
authenticated vulnerability scanning — with every design trade-off recorded in
an auditable decisions register.

Built and run in production across a ~150-host Linux estate in a
Windows-majority environment with no prior configuration-management tooling.

> **Sanitised reference implementation.** This is a public, generalised version
> of a baseline I run in production. Internal IPs, Azure identifiers, hostnames,
> and SSH keys are placeholders (`<SCANNER_IP>`, `<APP_ID>`, `kv-example-*`).

## What the script does

`apply-linux-baseline.sh` brings a host to the build standard in one run. Modules
are independent and skip cleanly when their inputs aren't provided.

| Module | Purpose |
|---|---|
| Admin account | Optional named sudo admin (key auth), enabling safe root-login disable |
| Scanner account | Key-only, locked-password account for authenticated scanning; source-IP restricted; minimal `sudo su -` only |
| sshd hardening | Removes weak crypto and SHA1 MACs, session limits, banner; validate-then-reload; conditional root-login disable |
| UFW firewall | Default-deny inbound; `--role webserver` opens 80/443 |
| Unattended upgrades | Security origins only; auto-reboot off by default |
| Time sync | chrony, internal NTP optional |
| EDR | CrowdStrike Falcon (optional; skips unless configured) |
| Hardening pack | sysctl network params, filesystem-module blacklist, core-dump restriction, cron/at lockdown, login banner |
| Config-mgmt enrolment | Optional Ansible account for estate-wide management |
| Listener check | Flags unexpected non-loopback listeners (report-only) |

Idempotent and non-interactive by design — decisions are passed as flags, never
prompted, so it works unattended in cloud-init and Ansible.

## Design highlights

A few decisions that show the reasoning behind the build (full register in
[`docs/04-decisions.md`](docs/04-decisions.md)):

- **The scanner needs root, so it gets `sudo su -` with NOPASSWD** — Qualys
  requires UID 0 and can't type a password. Rather than accept that as an
  open risk, it's tightly bounded: key-only auth, private key solely in Key
  Vault, source-IP restriction to the scanner, locked password, and a sudoers
  rule permitting only `su -`. Mirrors the accepted Windows domain-scan model.
- **One SSH keypair for the whole estate** — chosen for rotation feasibility
  (one vault secret, one auth record); the source-IP restriction makes a leaked
  key unusable from anywhere but the scanner appliance.
- **A minimal CIS subset, not full L1** — deliberately scoped to set-once static
  controls suited to a team with no config-management tooling, avoiding an
  unmaintainable sprawl. Expansion path documented rather than over-promised.

## Usage

```bash
sudo bash apply-linux-baseline.sh \
  [--role standard|webserver] \
  [--auto-reboot on|off] \
  [--admin-user NAME --admin-key 'ssh-ed25519 ...']
```

The script prints a PASS/FAIL summary per module; fix any failure and re-run
(idempotent). Full provisioning, verification, and rollback steps in
[`docs/03-host-provisioning.md`](docs/03-host-provisioning.md).

## Repository layout

| Path | Contents |
|---|---|
| `scripts/apply-linux-baseline.sh` | The provisioning script |
| `docs/01-architecture.md` | Components and how they connect |
| `docs/02-qualys-azure-setup.md` | One-time Qualys/Azure setup runbook |
| `docs/03-host-provisioning.md` | Provision, verify, and roll back a host |
| `docs/04-decisions.md` | Decisions & accepted-limitations register |
| `docs/05-roadmap.md` | Planned and deferred work |
| `docs/06-credentials.md` | Credential & expiry inventory |

## Direction of travel

The Bash script is the executable specification for an Ansible-managed estate:
run per-host today (which also enrols each host for config management), then
push standards estate-wide via Ansible, then bake the baseline into golden
images / cloud-init so new builds come up compliant with zero manual steps.
