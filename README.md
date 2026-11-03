# Intune-Proactive-Remediations

PowerShell detection and remediation script pairs for **Microsoft Intune Proactive Remediations** and **MSP RMM platforms (Kaseya VSAx, Datto, Autotask)** across Windows 10, Windows 11, and Windows Server endpoints.

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Intune & RMM](https://img.shields.io/badge/Platform-Microsoft_Intune_%26_MSP_RMM-0078D4.svg)](https://github.com/Santiago-Agudelo-R/Intune-Proactive-Remediations)

---

## Overview

Microsoft Intune Remediations and centralized RMM policies allow endpoint and systems engineers to detect and fix compliance, backup, and security posture drift automatically before incidents escalate to the Service Desk.

Every script pair in this repository follows strict Intune Management Extension (IME) and RMM engineering conventions:
- **Deterministic Exit Codes:** Detection scripts return `exit 0` (Compliant / Healthy) or `exit 1` (Non-Compliant / Trigger Remediation).
- **Single-Line `STDOUT` Telemetry:** Outputs a concise, structured summary string on the final line so Intune and RMM operational dashboards can parse pre- and post-remediation status cleanly.
- **Zero Hardcoded Tenant Data:** No tenant IDs, domain names, or credentials are embedded in scripts.
- **Offline Testability:** Script evaluation logic is modularized so functions can be unit-tested offline with **Pester 5** prior to production rollout.

---

## Remediation Catalog

| Package | Detection Script | Remediation Script | Run Context | Target Issue |
| :--- | :--- | :--- | :--- | :--- |
| **BitLocker-Escrow** | `Detect-BitLockerEscrow.ps1` | `Remediate-BitLockerEscrow.ps1` | `SYSTEM` (64-bit) | Detects encrypted OS volumes with suspended protection or missing a `RecoveryPassword` key protector escrowed to Entra ID. |
| **LocalAdmin-Hygiene** | `Detect-UnauthorizedLocalAdmins.ps1` | `Remediate-UnauthorizedLocalAdmins.ps1` | `SYSTEM` (64-bit) | Audits local `Administrators` (`S-1-5-32-544`) membership against an approved baseline (LAPS, Domain Admins) and removes unauthorized accounts. |
| **SystemHealth-VSS-Patching** | `Detect-SystemBackupAndPatchHealth.ps1` | `Remediate-SystemBackupAndPatchHealth.ps1` | `SYSTEM` (64-bit) | Pre-backup and patch window checklist: detects failed Volume Shadow Copy (VSS) writers, disabled Windows Update (`wuauserv`/`BITS`/`CryptSvc`) services, and system drive disk pressure. |

---

## Intune & RMM Deployment Settings

| Setting | Recommended Configuration |
| :--- | :--- |
| **Run this script using the logged-on credentials** | `No` (`SYSTEM` context) |
| **Enforce script signature check** | `No` (or `Yes` when signed by internal PKI Code Signing CA) |
| **Run script in 64-bit PowerShell** | `Yes` (Required to prevent `Sysnative` registry/cmdlet redirection issues) |
| **Schedule** | Daily (Prior to nightly VSS backup and maintenance windows) |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
