# Intune-Proactive-Remediations

PowerShell detection and remediation script pairs for **Microsoft Intune Remediations** across Windows 10, Windows 11, and Windows Server endpoints. The same scripts can run from RMM script policies (for example GoTo Resolve or Syncro).

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![CI](https://github.com/Santiago-Agudelo-R/Intune-Proactive-Remediations/actions/workflows/ci.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/Intune-Proactive-Remediations/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

Microsoft Intune Remediations and centralized RMM policies allow endpoint and systems engineers to detect and fix compliance, backup, and security posture drift automatically before incidents escalate to the Service Desk.

Every script pair in this repository follows the same conventions:
- **Deterministic Exit Codes:** Detection scripts return `exit 0` (Compliant / Healthy) or `exit 1` (Non-Compliant / Trigger Remediation).
- **Single-Line `STDOUT` Telemetry:** Outputs a concise, structured summary string on the final line so Intune and RMM operational dashboards can parse pre- and post-remediation status cleanly.
- **Zero Hardcoded Tenant Data:** No tenant IDs, domain names, or credentials are embedded in scripts.
- **Offline Testability:** Script evaluation logic is modularized so functions can be unit-tested offline with **Pester 5** (Windows PowerShell 5.1 and PowerShell 7) in GitHub Actions.
- **Safe by Default:** Destructive actions are opt-in. `Remediate-UnauthorizedLocalAdmins.ps1` runs report-only until you set `$Enforce = $true`, `Remediate-SystemBackupAndPatchHealth.ps1` does not purge `C:\Windows\Temp` by default (`$PurgeTempOnLowDisk = $false`) to avoid destroying forensic staging evidence, and no script enables BitLocker on its own.
- **Language-Independent & Non-Spoofable:** Checks rely on SIDs (`RID -500` for built-in Administrator, `RID -512`/`-519` for Domain/Enterprise Admins, explicit Entra ID role SIDs, and `<ComputerName>\Account` machine scoping) and numeric `vssadmin` states instead of English console text, so they work on Spanish (`es-CO` / `es-ES`) and other non-English Windows builds.

---

## Remediation Catalog

| Package | Detection Script | Remediation Script | Run Context | Target Issue |
| :--- | :--- | :--- | :--- | :--- |
| **BitLocker-Escrow** | `Detect-BitLockerEscrow.ps1` | `Remediate-BitLockerEscrow.ps1` | `SYSTEM` (64-bit) | Detects suspended protection, a missing `RecoveryPassword` protector, or a protector with no escrow confirmation (Event ID 845). Resumes protection and escrows the key to Entra ID. |
| **LocalAdmin-Hygiene** | `Detect-UnauthorizedLocalAdmins.ps1` | `Remediate-UnauthorizedLocalAdmins.ps1` | `SYSTEM` (64-bit) | Audits local `Administrators` (`S-1-5-32-544`) membership by SID: this machine's RID-500, your domain's `-512`/`-519`, and listed Entra ID role SIDs. Report-only by default. |
| **SystemHealth-VSS-Patching** | `Detect-SystemBackupAndPatchHealth.ps1` | `Remediate-SystemBackupAndPatchHealth.ps1` | `SYSTEM` (64-bit) | Pre-backup and patch window checklist: detects failed Volume Shadow Copy (VSS) writers, disabled Windows Update (`wuauserv`/`BITS`/`CryptSvc`) services, and system drive disk pressure. Selectively restarts VSS only when writers are failed. |
| **Defender-SensorHealth** | `Detect-DefenderSensorHealth.ps1` | `Remediate-DefenderSensorHealth.ps1` | `SYSTEM` (64-bit) | Audits Defender Antivirus (`WinDefend`), the Defender for Endpoint sensor (`Sense`, only when onboarded), Real-Time/Behavior Monitoring (skipped in Passive mode), Tamper Protection and signature age. Remediation restarts services, updates signatures and verifies the result. |

---

## LocalAdmin-Hygiene: how approval works

Both scripts contain the same `Test-IsApprovedLocalAdmin` function, so detection and remediation always reach the same verdict. Approval is by **SID**, which makes it independent of the Windows display language (`Administrator` / `Administrador`, `Domain Admins` / `Admins. del dominio`):

| Approved member | How it is matched | Configuration |
| :--- | :--- | :--- |
| Built-in local Administrator | `<this machine's SID>-500` | Automatic |
| Your Domain Admins / Enterprise Admins | `<ApprovedDomainSid>-512` / `-519` | Set `$ApprovedDomainSid` |
| Entra ID role SIDs (Global Administrator, Entra Joined Device Local Administrator) | Exact SID in `$ApprovedSids` | Add your tenant's two role SIDs |
| Other domain groups | `DOMAIN\Name` in `$ApprovedDomainAccounts`, SID must belong to `$ApprovedDomainSid` when set | Optional |
| Extra local accounts | Name in `$ApprovedLocalAccounts` **and** SID belongs to this machine | Optional, empty by default |

Design decisions:
- `-500`, `-512` and `-519` from **other** domains are never approved, and plain SID entries are compared exactly (no prefix matches).
- Local accounts are not approved by name by default: anyone who already has local admin rights can create `LAPS_Admin`. Let Windows LAPS manage the built-in RID-500 account instead, which is approved by SID.
- If the machine SID cannot be resolved, both scripts fail closed and remediation removes nothing.
- This is drift detection for configuration hygiene. An attacker who already holds local admin can tamper with anything that runs on the device, so this is not tamper-proof evidence.

Because Intune Remediations cannot pass parameters, set these values by editing the defaults in **both** scripts before uploading them.

---

## Sample Detection & Remediation Flow

Intune captures the final `STDOUT` line and the process exit code (`0` = compliant, `1` = trigger remediation):

```text
# 1. Pre-Remediation Detection (Detect-BitLockerEscrow.ps1 -> Exit Code 1)
NON-COMPLIANT: Volume C: is encrypted (XtsAes256), but no Event ID 845 escrow confirmation was found for protector {4B9D1E2A-...}.

# 2. Remediation Execution (Remediate-BitLockerEscrow.ps1 -> Exit Code 0)
REMEDIATED: Escrowed RecoveryPassword protector {4B9D1E2A-...} to Entra ID and verified Event ID 845.

# 3. Post-Remediation Detection (Detect-BitLockerEscrow.ps1 -> Exit Code 0)
COMPLIANT: Volume C: ProtectionStatus=On, EncryptionPercentage=100%, Protector={4B9D1E2A-...} verified in Event ID 845.
```

### Operational Considerations (`SystemHealth-VSS-Patching`)
- **Selective VSS Restart:** `Remediate-SystemBackupAndPatchHealth.ps1` only restarts `VSS` and `CryptSvc` when `vssadmin list writers` reports at least one failed writer, preventing unnecessary disruption to running backups when the alert was triggered solely by low disk space or a disabled `wuauserv` service.
- **Forensic Preservation (`C:\Windows\Temp`):** Because `C:\Windows\Temp` is frequently used by threat actors for staging, automatic temp file cleanup is disabled by default (`$PurgeTempOnLowDisk = $false`) and is also skipped if an incident-response hold file (`%ProgramData%\SecOps\IR_HOLD.lock`) exists.

---

## Tools

| Script | Purpose |
| :--- | :--- |
| `tools/Invoke-EndpointSupportAndInventory.ps1` | Support diagnostics (uptime, WinRM/WMI service state, hung services) and a hardware inventory record (serial, model, memory, OS) that maps to a CMDB such as Snipe-IT. Supports `-DemoMode`. Not a remediation pair. |

---

## Deployment Settings

| Setting | Recommended Configuration |
| :--- | :--- |
| **Run this script using the logged-on credentials** | `No` (`SYSTEM` context) |
| **Enforce script signature check** | `No` (or `Yes` when signed by internal PKI Code Signing CA) |
| **Run script in 64-bit PowerShell** | `Yes` (Required to prevent `Sysnative` registry/cmdlet redirection issues) |
| **Schedule** | Daily (Prior to nightly VSS backup and maintenance windows) |

---

## Testing

```powershell
Invoke-Pester -Path ./tests -Output Detailed
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
