# Qualys ↔ Azure one-time setup (completed 10 Jun 2026)

Reference runbook — needed again only for rebuild, rotation, or a second environment.

## 1. Generate the SSH keypair
```bash
ssh-keygen -t ed25519 -C "qualys-scanner" -f ./qualys-scanner-key -N ""
```
Public key → provisioning script. Private key → vault (step 3), then shred local copy.

## 2. Azure identity for Qualys
1. App registration: `New-AzADApplication -DisplayName "qualys-scanner-auth"`
2. **Create the service principal** (portal: app registration → "Create service principal" link). Role assignments attach to the SP, not the app object — this step is easy to miss.
3. Certificate for the app: generated in the vault (`qualys-auth-cert`, self-signed, RSA 2048, 24 months), then attached:
   `New-AzADAppCredential -ObjectId $app.Id -CertValue ([Convert]::ToBase64String($cert.Certificate.RawData))`
4. Role assignment: `Key Vault Secrets User` for the SP, scoped to the vault.
   (Vault is RBAC-mode: being RG Owner does **not** grant data-plane access — assign `Key Vault Administrator` to yourself for admin work.)

## 3. Store the SSH private key
```powershell
$privateKey = [System.IO.File]::ReadAllText("<path>\qualys-scanner-key")
Set-AzKeyVaultSecret -VaultName "kv-example-qualys-auth" -Name "qualys-scanner-private-key" `
  -SecretValue (ConvertTo-SecureString $privateKey -AsPlainText -Force)
```
**Verify it reads back before shredding the local file.**

## 4. Qualys vault record (Scans → Authentication → vault config)
| Field | Value |
|---|---|
| URL | `https://kv-example-qualys-auth.vault.azure.net` |
| SSL Verify | on |
| App ID | `<APP_ID>` |
| Certificate / Private Key | PEM halves of `qualys-auth-cert` (export PFX from vault, split with openssl: `-nokeys` → cert, `-nocerts -nodes` → key) |

## 5. Qualys Unix authentication record
| Field | Value |
|---|---|
| Title | `Linux Estate - SSH Key Auth` |
| Username | `qualys-scanner` |
| Private key from vault | Yes → record `kv-example-qualys-auth`, secret `qualys-scanner-private-key` |
| Passphrase / Certificate fields | blank |
| Root delegation | **Sudo**, username/password blank (NOPASSWD on hosts) |
| Ports | Well Known (22) |

Option profile must have **Unix authentication enabled**; "Test Authentication"
profiles validate login without a full scan.

## Troubleshooting (all hit during setup)
| Symptom | Cause / fix |
|---|---|
| `Unable to get private key password from the vault: network error while requesting token: Connection time-out` | Scanner appliance couldn't reach `login.microsoftonline.com`. Resolved network-side after raising with network engineer. Workaround while blocked: paste private key directly into auth record. |
| Auth fails, journal shows `correct key but not from a permitted host` | `from=` restriction vs actual scanner source IP. Confirm appliance scans from `<SCANNER_IP>`. |
| Auth fails, `Connection closed ... [preauth]`, key fingerprints differ | Wrong keypair half somewhere. Compare `ssh-keygen -l -f` fingerprints on both sides. |
| Sudoers install fails: `unknown setting: 'requiretty'` | sudo ≥1.9 removed `requiretty`. Line removed from script. |
| Role assignment `BadRequest` in PowerShell | Used app **object** ID instead of **service principal** ID, or SP didn't exist yet. |
| `New-AzKeyVault` says name in use but vault invisible | Global name collision or soft-deleted vault (`Get-AzKeyVault -InRemovedState`). |
