# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-11-21

### Fixed
- **Inventory tool:** The output no longer invents an asset tag (`AST-<serial>`) or a `Deployed` status that did not come from any system. `SnipeItAssetPayload` is renamed `HardwareInventory` and contains only facts collected from the device.

## [1.2.1] - 2026-11-21

### Security
- **LocalAdmin-Hygiene:** RID `-500`, `-512` and `-519` are now approved only for this machine's SID and the configured `$ApprovedDomainSid`. Previously any domain's Domain Admins, Enterprise Admins or built-in Administrator was approved.
- **LocalAdmin-Hygiene:** Local accounts are no longer approved by name by default. A name such as `LAPS_Admin` can be created by anyone with local admin rights; extra local accounts must be listed in `$ApprovedLocalAccounts` and their SID must belong to this machine.
- **LocalAdmin-Hygiene:** Plain entries in `$ApprovedSids` are compared exactly instead of as unanchored regex, so one SID can no longer match a longer SID that starts with it.

### Fixed
- **LocalAdmin-Hygiene:** Detection and remediation share a byte-identical `Test-IsApprovedLocalAdmin`; removed test-only logic that guessed the computer name from hard-coded domain names.
- **LocalAdmin-Hygiene:** Both scripts fail closed when the machine SID cannot be resolved.
- **Defender-SensorHealth:** Onboarding to Defender for Endpoint is now read from `OnboardingState`; the `Sense` service ships with Windows 10/11 and its presence alone caused false positives on devices that are not onboarded.
- **Defender-SensorHealth:** Real-time and behavior monitoring are not flagged when Defender Antivirus runs in Passive or EDR Block mode, and an unreadable Tamper Protection status is reported as `TamperProtectionUnknown` instead of being assumed on.
- **Defender-SensorHealth:** Remediation no longer hides `Set-MpPreference` failures; it re-reads Defender status and exits 1 if protection is still off, so Intune does not report a false success.
- **SystemHealth-VSS-Patching:** The Temp cleanup counts only files actually removed, and the IR hold marker path uses `%ProgramData%` instead of a hard-coded `C:` drive.

## [1.2.0] - 2026-11-21

### Fixed
- **LocalAdmin-Hygiene:** Unified `Detect-UnauthorizedLocalAdmins.ps1` and `Remediate-UnauthorizedLocalAdmins.ps1` around the same SID-first evaluation function (`Test-IsApprovedLocalAdmin`). Both scripts now evaluate `.Sid` against `$ApprovedSids` (eliminating detection/remediation loops on Entra ID role SIDs), approve built-in Local Administrator (`RID -500`) and Domain/Enterprise Admins (`RID -512` / `-519`) by SID across Spanish (`Administrador`, `Admins. del dominio`) and multilingual Windows builds, and scope local management accounts (`LAPS_Admin`) to `<ComputerName>\LAPS_Admin` to prevent cross-domain name spoofing.
- **SystemHealth-VSS-Patching:** `Remediate-SystemBackupAndPatchHealth.ps1` no longer deletes files from `C:\Windows\Temp` by default (`$PurgeTempOnLowDisk = $false`) to prevent destroying forensic staging artifacts, respects `C:\ProgramData\SecOps\IR_HOLD.lock`, and only restarts `VSS` when a VSS writer is actually in a failed state.
- **Inventory Tool:** Aligned `tools/Invoke-EndpointSupportAndInventory.ps1` comment-based help with its exact implementation scope.

### Added
- **Defender-SensorHealth (`Detect-DefenderSensorHealth.ps1` / `Remediate-DefenderSensorHealth.ps1` — MITRE `T1562.001`):** Audits Microsoft Defender Antivirus (`WinDefend`) and Microsoft Defender for Endpoint sensor (`Sense`) service state, Real-Time Protection, Behavior Monitoring, Tamper Protection, and signature freshness (`MaxSignatureAgeDays = 7`).
- Added Pester unit tests covering Spanish Windows SID approval, Entra ID role SID parity between detection and remediation, cross-domain name-spoofing rejection, selective VSS restart, and `Defender-SensorHealth`.

## [1.1.0] - 2026-11-09

### Fixed
- **LocalAdmin-Hygiene:** Removed the `^AzureAD\\` allowlist pattern, which approved every Entra ID user as a local administrator. Entra ID role SIDs are now added explicitly.
- **LocalAdmin-Hygiene:** Added an ADSI fallback for error 1789 when the group contains orphaned or unresolvable SIDs.
- **BitLocker-Escrow:** Detection now requires an escrow confirmation (Event ID 845) for the RecoveryPassword protector instead of only checking that the protector exists.
- **BitLocker-Escrow:** An initial encryption still in progress is reported as `PENDING` instead of non-compliant.
- **SystemHealth-VSS-Patching:** `vssadmin` parsing no longer depends on English labels; failed writers are now detected on Spanish and other non-English Windows builds.
- **Inventory tool:** Replaced a WMI repository check that was always reported as healthy with a real Winmgmt service check.

### Changed
- **LocalAdmin-Hygiene:** The remediation is report-only by default (`$Enforce = $false`) and reports partial failures per account.
- **BitLocker-Escrow:** The remediation no longer enables BitLocker on decrypted drives; initial encryption belongs to the Intune disk encryption policy.
- Moved `Invoke-EndpointSupportAndInventory.ps1` to `tools/` because it is not a detection/remediation pair.
- Remediation messages now describe exactly what was changed, including `WHATIF` output.

### Added
- GitHub Actions CI: PSScriptAnalyzer and Pester on Windows PowerShell 5.1 and PowerShell 7.
- Tests for escrow confirmation, pending encryption, Entra ID users, and Spanish `vssadmin` output.

## [1.0.0] - 2026-10-23

### Added
- Initial release of `BitLocker-Escrow`, `LocalAdmin-Hygiene`, and `SystemHealth-VSS-Patching` remediation pairs with Pester 5 test suite.
