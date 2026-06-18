# Architecture

## Components

```
┌─────────────────┐  1. OAuth token        ┌──────────────────────┐
│ Qualys Scanner  │ ─────────────────────► │ login.microsoftonline │
│ Appliance       │                        └──────────────────────┘
│ (vSphere,       │  2. Get secret         ┌──────────────────────┐
│  <SCANNER_MGMT_IP> / │ ─────────────────────► │ Azure Key Vault       │
│  scans from     │     (SSH private key)  │ kv-example-qualys-auth │
│  <SCANNER_IP>)  │                        └──────────────────────┘
│                 │  3. SSH as qualys-scanner (key auth)
│                 │ ─────────────────────► ┌──────────────────────┐
│                 │  4. sudo su -  (root)  │ Linux host            │
└─────────────────┘                        │ qualys-scanner account│
                                           └──────────────────────┘
```

## Azure resources (resource group: `qualys-rg`, subscription `<AZURE_SUBSCRIPTION_ID>`)

| Resource | Purpose |
|---|---|
| Key Vault `kv-example-qualys-auth` | Holds the SSH private key (secret: `qualys-scanner-private-key`). RBAC-enabled. |
| App Registration `qualys-scanner-auth` (AppId `<APP_ID>`) | Identity Qualys uses to read the vault. Certificate credential `CN=qualys-auth` (expires Oct 2028). |
| Service principal role assignment | `Key Vault Secrets User` on `kv-example-qualys-auth` |
| Certificate `qualys-auth-cert` (in same vault) | Self-signed, 24-month validity. Public+private halves pasted into the Qualys vault record. |

Note: `kv-example-etl` (ETL pipeline credentials) is deliberately separate. Do not mix.

## Qualys configuration

| Object | Value |
|---|---|
| Vault record | `kv-example-qualys-auth` → URL `https://kv-example-qualys-auth.vault.azure.net` |
| Unix auth record | `Linux Estate - SSH Key Auth` — user `qualys-scanner`, private key from vault, root delegation: **Sudo**, no password (NOPASSWD by design) |
| Scanner appliance | Qualys-Scanner-01, scans from `<SCANNER_IP>` |

## On every Linux host (deployed by the provisioning script)

- Local account `qualys-scanner`: locked password, `/bin/bash`, key-only SSH
- `authorized_keys` with `from="<SCANNER_IP>"` source restriction
- `/etc/sudoers.d/qualys-scanner`: permits exactly `sudo su -` with NOPASSWD
- The baseline script also applies: sshd hardening drop-in, UFW, unattended security upgrades, chrony, hardening pack (sysctl/modules/cron/banner), CrowdStrike (optional), blob registration (optional), ansible-mgmt enrollment (optional)

## Key lifecycle

One ed25519 keypair for the whole estate. Private key exists **only** in the
vault. Public key is embedded in the provisioning script (safe to commit).
Rotation: generate new pair → update `QUALYS_PUBKEY` in script → re-run script
on all hosts (idempotent) → update vault secret → done (auth record reads the
vault, no Qualys change needed).
