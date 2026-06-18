# Roadmap / deferred

## Next (designed, not built)
1. **Central Qualys sync** — Python on `example-host-01`: read `linux-registrations/`
   container in `qualysvulndata`, add new IPs to the auth record via Qualys API
   (`add_ips`), move processed blobs to `processed/`, log additions. Cron before
   scan window. Requires generating the write-only SAS token for M7.
2. **Detection backstop** — alert (Teams, same pattern as `qualys_scan_health.py`)
   for any Linux host that was scanned but never authenticated. Alert on
   state-change or weekly digest, not daily repeats. Include hostname, IP,
   last-seen, and the one-line fix. Doubles as the rollout burndown tracker
   for the existing ~150-host estate.
3. **ansible-rg + Ansible Key Vault** — dedicated resource group and vault for
   config management credentials (deliberately separate from qualys-rg).
   Then: **ansible-mgmt keypair** — generate ed25519 pair, private key to
   the Ansible vault (secret: `ansible-mgmt-private-key`), public key
   into `ANSIBLE_PUBKEY` in the script BEFORE estate rollout (the rollout is
   the free enrollment window).
4. **First full baseline run** on example-test-host, then example-host-01; confirm
   scanner-appliance compatibility with tightened SSH crypto and QID 38909 clearance.

## With infrastructure
4. **Proxmox golden template + cloud-init** — bake the baseline into the template
   for the new Proxmox environment so new builds need no manual step; quarterly
   patch/re-template cadence owned by infrastructure.
5. **CrowdStrike rollout** — CID; mirror the sensor .deb in an `installers`
   blob container with a read-only SAS so M6 can fetch it itself (no Falcon
   API credentials on hosts); reset agent ID
   (`falconctl -d -f --aid`) before templating so clones register uniquely.
6. **Reboot policy** for unattended kernel updates.
7. **Supported distro list** — note `example-host-01` already runs Ubuntu 26.04;
   decide "24.04 LTS" vs "current LTS".

## Deferred (recorded in docs/04)
- auditd + log forwarding to Sentinel (cost assessment first)
- Full CIS L1 via USG/OpenSCAP enforcement; partitioning standards (template-time)
- sysctl network hardening; PAM password policy; AIDE
- Admin VLAN / bastion (would allow re-restricting SSH sources)
- Key rotation schedule for the estate SSH keypair and the `qualys-auth-cert`
  app credential (expires Oct 2028 — calendar it)
