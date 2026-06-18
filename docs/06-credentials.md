# Credential & expiry inventory

Every credential this project depends on, where it lives, when it dies, and
what breaks when it does. **No secret values in this file, ever.**
Single source of truth — update on any credential change.

| Credential | Type | Lives in | Expires | Breaks on expiry | Rotation procedure |
|---|---|---|---|---|---|
| `qualys-scanner` SSH keypair | ed25519 | Private: `kv-example-qualys-auth` secret `qualys-scanner-private-key`. Public: embedded in `apply-linux-baseline.sh` | Never (rotate on policy/compromise) | Authenticated scanning estate-wide | Deploy new public key to all hosts FIRST (re-run script / Ansible), then swap vault secret. docs/01. |
| `qualys-auth-cert` | X.509 self-signed, RSA 2048 | Cert object in `kv-example-qualys-auth`; attached to app reg `qualys-scanner-auth`; PEM halves pasted in Qualys vault record | **Oct 2028** | Qualys vault retrieval → all authenticated scans | Regenerate in vault, re-attach to app reg (`New-AzADAppCredential`), re-paste PEM halves into Qualys vault record. docs/02 §2-4. |
| `ansible-mgmt` SSH keypair | ed25519 | Private: Ansible vault (ansible-rg, **to be created**). Public: `ANSIBLE_PUBKEY` in script | Never (rotate on policy/compromise) | Estate config management | Same pattern as scanner key. |
| Blob registration SAS | SAS token, write-only (create+write), container `linux-registrations` | Embedded in DEPLOYED copy of script only — never committed | **TBD** (2-3yr acceptable: write-only, minimal blast radius) | M7 registration uploads (non-fatal; script falls back to manual IP entry) | Regenerate in storage account, update deployed script copies. |
| Sensor mirror SAS (planned) | SAS token, read-only, container `installers` | Deployed script copy | TBD | M6 CrowdStrike installs on new hosts | Regenerate, update deployed copies. |
| ETL pipeline credentials | (existing, pre-dates this project) | `kv-example-etl` | per-credential | Vulnerability data pipeline / Power BI | Tracked separately — listed here for expiry awareness only. |

**Calendar entries to create:** qualys-auth-cert renewal (Sep 2028 reminder);
SAS expiry dates once generated.
