<div align="center">

# Check-DeviceGuard

**Kernel Security Posture & DSE Bypass Assessment**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

*Assess the kernel security posture of a Windows system and generate a concrete, step-by-step attack path for DSE bypass. Know the lock before you pick it.*

*Developed in close collaboration with [opus](https://claude.ai).*

---

</div>

## Table of Contents

- [Overview](#overview)
- [Demo Output](#demo-output)
- [How It Works](#how-it-works)
  - [Data Collection](#data-collection)
  - [Difficulty Classification](#difficulty-classification)
  - [UEFI Lock Detection](#uefi-lock-detection)
  - [WDAC Policy Detection](#wdac-policy-detection)
  - [VM Detection](#vm-detection)
- [Output Sections](#output-sections)
  - [Controls](#controls)
  - [Enforcement](#enforcement)
  - [Warnings](#warnings)
  - [Capability Matrix](#capability-matrix)
  - [Attack Paths](#attack-paths)
- [Attack Path Details](#attack-path-details)
  - [TRIVIAL: BCD Already Relaxed](#trivial-bcd-already-relaxed)
  - [EASY: Secure Boot Off](#easy-secure-boot-off)
  - [MODERATE: BYOVD + g_CiOptions Patch](#moderate-byovd--gcioptions-patch)
  - [HARD: HVCI On, No UEFI Lock](#hard-hvci-on-no-uefi-lock)
  - [VERY HARD: HVCI UEFI Locked](#very-hard-hvci-uefi-locked)
- [Technical Reference](#technical-reference)
  - [g_CiOptions](#g_cioptions)
  - [VBS / HVCI Architecture](#vbs--hvci-architecture)
  - [Secure Boot and BCD Flags](#secure-boot-and-bcd-flags)
  - [Credential Guard vs HVCI Lock](#credential-guard-vs-hvci-lock)
- [OPSEC Notes](#opsec-notes)
- [Usage](#usage)
- [Supported Windows Versions](#supported-windows-versions)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

---

## Overview

Check-DeviceGuard is a read-only PowerShell assessment script for red teamers and penetration testers. It silently collects the full kernel security configuration from WMI, registry, BCD store, and firmware, then produces:

1. **Controls** -- current state of Secure Boot, VBS, HVCI, WDAC, Credential Guard, System Guard
2. **Enforcement** -- BCD flags, driver blocklist status, GPO enforcement, UEFI lock state
3. **Warnings** -- non-obvious configuration conflicts that affect the attack path
4. **Capability Matrix** -- what kernel operations are possible under each security tier, with the current state highlighted
5. **Attack Path** -- concrete, step-by-step instructions tailored to the detected configuration, including exact registry commands, BCD modifications, and BYOVD exploitation guidance
6. **Legend** -- reference definitions for every security control assessed

The script answers one question: **how hard is it to load an unsigned or vulnerable kernel driver on this target, and what are the exact steps?**

---

## Demo Output

```
  ══════════════════════════════════════════════════════════════════════════════
   KERNEL SECURITY POSTURE          DC01 | 2026-07-04 14:22
  ══════════════════════════════════════════════════════════════════════════════

   CONTROLS
   ─────────────────────────────────────────────────────────────────────────────
    Secure Boot                  ENABLED
    VBS                          2 (Running)
    HVCI                         RUNNING [UEFI LOCKED]
    WDAC KMCI                    0 (Off)
    WDAC UMCI                    0 (Off)
    Credential Guard             RUNNING [UEFI LOCKED]
    System Guard                 OFF

   ENFORCEMENT
   ─────────────────────────────────────────────────────────────────────────────
    BCD testsigning              No
    BCD debug                    No
    BCD nointegrity              No
    Blocklist                    ACTIVE (42391B, 2026-06-12)
    GPO                          ENFORCING VBS
    Local EnableVBS              1 (enabled)
    Platform Security            3 (SecureBoot+DMA)

   WARNINGS
   ─────────────────────────────────────────────────────────────────────────────
    ! GPO enforcing VBS
      Group Policy refreshes every ~90min and on reboot, overwriting local
      registry changes to EnableVBS. Any manual registry disable will be
      reverted unless GP Client is stopped or SYSVOL access is blocked.
      Fix: sc stop gpsvc && sc config gpsvc start= disabled

   DSE BYPASS: VERY HARD

  ══════════════════════════════════════════════════════════════════════════════
   CAPABILITY MATRIX                                     [*] = current state
  ══════════════════════════════════════════════════════════════════════════════

                                      SB Off  SB+NoHV  SB+HVCI  SB+Lock*
    ──────────────────────────────────────────────────────────────────────
    DSE bypass available               YES      YES       no       no
      via BCD flags                    YES       no       no       no
      via g_CiOptions patch            YES      YES       no       no
      via WinRE Safe Mode              n/a      n/a      YES      YES
    Unsigned driver (post-bypass)      YES      YES       1)       1)
    BYOVD driver load                  YES*     YES*     YES*     YES*
    Token swap (EPROCESS.Token)        YES      YES      YES      YES
    PPL zero (EPROCESS.Protection)     YES      YES      YES      YES
    Callback removal (Notify)          YES      YES      YES      YES
    ETW blind (provider patch)         YES      YES      YES      YES
    Kernel code exec (W^X)             YES      YES       no       no
    Disable HVCI (registry)            n/a      n/a      YES       no
    Disable HVCI (firmware)            n/a      n/a      YES      YES
    Disable HVCI (WinRE SafeMode)      n/a      n/a      YES      YES
    ──────────────────────────────────────────────────────────────────────
    * BYOVD requires valid Authenticode sig + RFC3161 timestamp
    1) Only via WinRE Safe Mode (HVCI inactive), requires physical access

  ══════════════════════════════════════════════════════════════════════════════
   ATTACK PATH
  ══════════════════════════════════════════════════════════════════════════════

    Maximum hardening. HVCI is UEFI locked.

    Option A: Data-only BYOVD (same as HARD path above)
    1. Load validly-signed BYOVD driver
    2. Token swap, PPL bypass, callback removal, ETW blind via arbitrary R/W

    Option B: WinRE Safe Mode bypass (physical access required)
    1. Hard power-off during boot 2x consecutively to trigger WinRE
    2. In WinRE: skip encrypted OS volume (if BitLocker), open Command Prompt
    3. bcdedit /set {default} safeboot minimal
    ...
```

---

## How It Works

### Data Collection

All data is collected silently before any output is produced. The script queries five sources:

| Source | Method | Data |
|--------|--------|------|
| **WMI** | `Get-CimInstance Win32_DeviceGuard` | VBS status, HVCI/CG/SG running state, KMCI/UMCI enforcement, configured vs running services |
| **Registry** | `Get-ItemProperty` across DeviceGuard, CI, LSA hives | EnableVBS, HVCI/CG scenario locks, LsaCfgFlags, blocklist override, GPO policy values |
| **BCD Store** | `bcdedit /enum "{current}"` | testsigning, debug, nointegritychecks flags |
| **Firmware** | `Confirm-SecureBootUEFI`, `Get-SecureBootUEFI dbx` | Secure Boot state, DBX revocation list size |
| **Filesystem** | `Test-Path`, `Get-ChildItem` | driversipolicy.p7b (blocklist), SIPolicy.p7b, CiPolicies\Active\*.cip (WDAC) |

No registry writes. No BCD modifications. No network activity. No driver loading.

### Difficulty Classification

The script classifies the target into one of five difficulty tiers. Only the HVCI UEFI lock state drives the base difficulty. Credential Guard UEFI lock is tracked separately but does not inflate the rating because it protects LSASS credentials, not driver loading.

| Rating | Conditions | What It Means |
|--------|-----------|---------------|
| **TRIVIAL** | Secure Boot off, BCD flags already set | DSE is effectively disabled. Load any driver directly. |
| **EASY** | Secure Boot off, BCD flags not yet set | Set `testsigning` via BCD, reboot, load any driver. |
| **MODERATE** | Secure Boot on, HVCI off | BYOVD driver + g_CiOptions kernel patch. Live, no reboot. |
| **HARD** | Secure Boot on, HVCI on, no UEFI lock | Data-only attacks live, or disable HVCI via registry + reboot. |
| **VERY HARD** | Secure Boot on, HVCI on, UEFI locked | Data-only attacks live, or WinRE Safe Mode bypass (physical access). |

WDAC KMCI enforcement is shown as an independent qualifier (`[+WDAC]` or `[WDAC:Audit]`) since it operates as a separate blocking layer above DSE.

<details>
<summary><b>Why only HVCI lock determines difficulty</b></summary>

HVCI and Credential Guard each have their own UEFI lock mechanism, and the script tracks them independently. However, only the HVCI lock affects whether an attacker can load unsigned kernel drivers:

- **HVCI lock** prevents disabling code integrity enforcement via registry. This directly gates DSE bypass and unsigned driver loading.
- **CG lock** prevents disabling LSASS credential isolation. This protects credentials in VTL1 but has no effect on driver loading or g_CiOptions.

A system with CG UEFI locked but HVCI unlocked is rated **HARD**, not VERY HARD, because HVCI can still be disabled via registry + reboot. The CG lock is displayed in the output as informational context but does not change the attack path for driver loading.

</details>

### UEFI Lock Detection

The script checks three independent sources for UEFI lock state:

```
HVCI Lock:
  Registry: DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Locked = 1

CG Lock (checked independently):
  Registry: DeviceGuard\Scenarios\CredentialGuard\Locked = 1
  LSA:      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags = 1
            (0 = Disabled, 1 = Enabled WITH UEFI Lock, 2 = Enabled WITHOUT Lock)
```

### WDAC Policy Detection

When `CodeIntegrityPolicyEnforcementStatus = 2` (KMCI enforced), the script detects both policy formats:

| Format | Location | Detection |
|--------|----------|-----------|
| Single policy | `CodeIntegrity\SIPolicy.p7b` | `Test-Path` |
| Multiple policy | `CodeIntegrity\CiPolicies\Active\*.cip` | `Get-ChildItem -Filter "*.cip"` |

The script distinguishes `SIPolicy.p7b` (WDAC KMCI policy) from `driversipolicy.p7b` (Microsoft Vulnerable Driver Blocklist). These are separate enforcement mechanisms and require different bypass approaches.

### VM Detection

The script identifies virtual machines by checking `Win32_ComputerSystemProduct.Name` and `Win32_BIOS.Manufacturer` against known hypervisor strings (Hyper-V, VMware, VirtualBox, Xen, QEMU, KVM). When a VM is detected:

- WinRE hard-shutdown guidance is flagged as potentially non-functional (no physical power button)
- Hyper-V Gen2 VMs get host-side PowerShell commands for Secure Boot control
- VMware/VirtualBox get VM settings guidance

---

## Output Sections

### Controls

Displays the current state of every kernel security control. Color coding from the attacker's perspective: green means the control is off (favorable), yellow/red means it is active (obstacle).

| Control | Values | Impact on DSE Bypass |
|---------|--------|---------------------|
| Secure Boot | ENABLED / DISABLED | Enabled: BCD flags ignored, must use BYOVD path |
| VBS | Off / Configured / Running | Infrastructure only. Without HVCI, no direct security effect. |
| HVCI | OFF / RUNNING / RUNNING [UEFI LOCKED] | Running: g_CiOptions in VTL1, unpatchable. Data-only attacks remain. |
| WDAC KMCI | Off / Audit / Enforced | Enforced: independent driver blocking above DSE |
| WDAC UMCI | Off / Audit / Enforced | Enforced: usermode code integrity policy active |
| Credential Guard | OFF / RUNNING / RUNNING [UEFI LOCKED] | Protects LSASS credentials. Does NOT affect driver loading. |
| System Guard | OFF / CONFIGURED / RUNNING | VBS consumer. Keeps hypervisor alive even with EnableVBS=0. |

### Enforcement

Shows BCD flags, driver blocklist status, GPO enforcement state, and platform security requirements.

| Item | Significance |
|------|-------------|
| BCD testsigning / debug / nointegritychecks | Silently ignored when Secure Boot is enabled |
| Blocklist | Microsoft Vulnerable Driver Blocklist (driversipolicy.p7b). Active = known BYOVD drivers may be blocked by hash/certificate. Disable via registry requires reboot. |
| GPO | If enforcing VBS: Group Policy refresh (~90min) overwrites manual registry changes |
| Local EnableVBS | Boot-time VBS enable state. May conflict with GPO policy key. |
| Platform Security | 1 = SecureBoot required, 3 = SecureBoot + DMA Protection required |

### Warnings

The script detects and warns about non-obvious configurations. These are situations where the expected attack path will fail due to hidden dependencies or conflicts:

| Warning | Problem | Why It Matters |
|---------|---------|----------------|
| GPO / Registry Conflict | GPO sets EnableVBS=0 but boot key has EnableVBS=1 | Boot manager reads SYSTEM hive, not policy hive. VBS stays running despite GPO. |
| SystemGuard keeping VBS alive | ConfigureSystemGuardLaunch is a VBS consumer | Hypervisor stays loaded even with EnableVBS=0. Must disable separately. |
| BCD flags nullified by Secure Boot | testsigning/debug/nointegritychecks set but SB on | Flags are silently ignored. Attacker may think DSE is disabled when it is not. |
| VBS without HVCI | Hypervisor active, HVCI not consuming it | g_CiOptions is in VTL0 and patchable. VBS alone is not a barrier. |
| GPO enforcing VBS | GP refresh overwrites manual registry changes | Must stop gpsvc or block SYSVOL before registry modifications persist. |
| CG UEFI locked, HVCI not | CG lock does not protect driver loading | Avoids false impression that UEFI lock prevents DSE bypass. |
| WDAC KMCI enforced | Independent blocking layer above DSE | Even with g_CiOptions=0, WDAC policy blocks unlisted drivers. |
| GPO requests HVCI but inactive | Incompatible driver or missing hardware | Current posture is MODERATE, but resolving the blocker shifts to HARD/VERY HARD. |

### Capability Matrix

Maps kernel attack primitives against four security tiers. The current system state is marked with `*`. The matrix answers: "what can I do at each hardening level?"

Key takeaway: data-only attacks (token swap, PPL zero, callback removal, ETW blind) work at **every** tier because EPROCESS and kernel data structures reside in VTL0 regardless of HVCI state.

### Attack Paths

Generated dynamically based on the detected configuration. Each path includes exact commands, prerequisites, cleanup steps, and warnings about GPO re-enablement, BitLocker recovery key prompts, and VM-specific limitations.

---

## Attack Path Details

### TRIVIAL: BCD Already Relaxed

Secure Boot is off and BCD flags (testsigning or nointegritychecks) are already set. `ci.dll` still runs but accepts any or no signature due to the active BCD override.

```
sc create Drv type= kernel binPath= C:\path\to\driver.sys
sc start Drv
```

### EASY: Secure Boot Off

Secure Boot is off, so the boot manager does not validate BCD integrity. Set `testsigning`, reboot, load any driver. If kernel debug mode is already active, attach a remote debugger and patch `g_CiOptions` directly without reboot.

```
bcdedit /set testsigning on
shutdown /r /t 0
sc create Drv type= kernel binPath= C:\path\to\driver.sys && sc start Drv
```

<details>
<summary><b>Debug mode variant (no reboot)</b></summary>

If BCD debug is already enabled, attach from a second machine on the same network:

```
Host:   WinDbg -k net:port=50000,key=<KEY>
Target: (break in)
        ed ci!g_CiOptions 0          // resolve: x ci!g_CiOptions
        g                             // resume
        sc create Drv type= kernel binPath= C:\path\to\driver.sys && sc start Drv
Cleanup: restore g_CiOptions to original value from debugger
```

</details>

### MODERATE: BYOVD + g_CiOptions Patch

Secure Boot locks BCD flags, but HVCI is off so `g_CiOptions` resides in VTL0 kernel memory. A vulnerable signed driver provides arbitrary R/W to patch `g_CiOptions`, temporarily disabling DSE for the target driver load. Live, no reboot needed.

```
Load signed BYOVD driver (sc create / sc start)
  |
  NtQuerySystemInformation(SystemModuleInformation) -> ci.dll base address
  |
  Map ci.dll from disk in usermode, pattern scan CiInitialize
  for g_CiOptions RVA (RIP-relative LEA, NOT exported)
  |
  Kernel VA = ci.dll base + scanned RVA
  |
  Read g_CiOptions via driver R/W primitive (save original value)
  |
  Write 0x0 -> all CI enforcement disabled
  |
  sc create Target type= kernel binPath= C:\path\to\target.sys
  sc start Target
  |
  Restore g_CiOptions to saved value, stop and delete BYOVD driver
```

If the Vulnerable Driver Blocklist is active, the script shows a two-phase approach: disable blocklist via registry (reboot required), then proceed with BYOVD. Alternative: use a BYOVD driver not on the blocklist ([loldrivers.io](https://www.loldrivers.io/)).

<details>
<summary><b>g_CiOptions resolution details</b></summary>

`g_CiOptions` is an internal global variable in `ci.dll`. It is **not exported** and must be resolved via pattern scanning. The common approach:

1. `NtQuerySystemInformation(SystemModuleInformation)` to get `ci.dll` base address in kernel
2. Map `ci.dll` from disk in usermode (`LoadLibrary` or file read)
3. Scan `CiInitialize` for a `MOV` to the global (RIP-relative `LEA` pattern)
4. Compute kernel VA: `ci.dll base + scanned RVA`

Common observed values:

| Value | Meaning |
|-------|---------|
| 0x0 | All CI enforcement disabled |
| 0x6 | Default enforcement (DSE active) |
| 0xE | Enforcement with UMCI enabled |

The internal bit layout is undocumented and varies by build. SDK constants (`CODEINTEGRITY_OPTION_*`) describe `NtQuerySystemInformation` return values, not necessarily the internal `g_CiOptions` layout. For bypass: read, zero, load, restore.

</details>

<details>
<summary><b>Known BYOVD drivers (when blocklist is inactive)</b></summary>

| Driver | Vendor | Capability |
|--------|--------|------------|
| RTCore64.sys | MSI | Arbitrary physical R/W |
| gdrv.sys | Gigabyte | Arbitrary physical R/W |
| dbutil_2_3.sys | Dell | Arbitrary physical R/W |
| Eneio64.sys | ENE Technology | Arbitrary physical R/W, MSR/port I/O |
| AsrDrv106.sys | ASRock | Arbitrary physical R/W |
| HwRwDrv.sys | Huawei | Arbitrary physical R/W |

Full catalog: [loldrivers.io](https://www.loldrivers.io/)

</details>

### HARD: HVCI On, No UEFI Lock

HVCI delegates code integrity enforcement to the Secure Kernel (`skci.dll`) in VTL1. Patching `g_CiOptions` in VTL0 `ci.dll` has no effect. Code pages are EPT W^X enforced. Three options:

**Option A: Data-only BYOVD (live, no reboot, HVCI stays on)**

Load a validly-signed BYOVD driver (HVCI does not block signed drivers) and use arbitrary R/W for data-only kernel attacks:

| Technique | Target | Effect |
|-----------|--------|--------|
| Token Swap | `EPROCESS.Token` | Copy SYSTEM token to attacker process. Full privilege escalation. |
| PPL Bypass | `EPROCESS.Protection` | Write 0x0. Allows `OpenProcess(PROCESS_ALL_ACCESS)` on LSASS/protected processes. |
| Callback Removal | `PspCreateProcessNotifyRoutine` | Zero entries. Blinds EDR kernel callbacks for process/thread/image events. |
| ETW Blind | Provider EnableInfo | Patch `EtwpEventTracingProvGuid` or provider structures. Disables kernel ETW tracing. |

Cannot load unsigned drivers. Cannot patch `g_CiOptions`.

**Option B: Disable HVCI via registry + BCD (requires reboot)**

Without UEFI lock, HVCI enablement is controlled by a registry scenario key. Disabling it unloads the Secure Kernel on reboot:

```
reg add "HKLM\SYSTEM\...\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\...\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
bcdedit /set vsmlaunchtype off
bcdedit /set hypervisorlaunchtype off
shutdown /r /t 0
```

After reboot: HVCI off, proceed with MODERATE path (BYOVD + g_CiOptions patch).

<details>
<summary><b>GPO re-enablement prevention</b></summary>

If GPO enforces VBS, Group Policy refresh (~90min) will overwrite the registry changes:

```
sc stop gpsvc && sc config gpsvc start= disabled
```

Alternative: block SYSVOL access to prevent policy download:

```
netsh advfirewall firewall add rule name=BlockSYSVOL dir=out action=block protocol=tcp remoteport=445
```

</details>

**Option C: WinRE Safe Mode bypass (physical access required)**

Force Windows Recovery Environment via 2 consecutive hard shutdowns during boot. VBS/HVCI do not run in Safe Mode.

```
1. Hard power-off during boot 2x -> WinRE triggers
2. In WinRE: Command Prompt
3. bcdedit /set {default} safeboot minimal
4. Reboot -> Safe Mode (hypervisor does not load)
5. Disable VBS/HVCI via registry + BCD (see Option B commands)
6. bcdedit /deletevalue {default} safeboot
7. shutdown /r /t 0
8. After reboot: HVCI off, use BYOVD + g_CiOptions patch
```

<details>
<summary><b>BitLocker considerations</b></summary>

- **TPM-only**: Safe Mode may trigger recovery key prompt (PCR mismatch from BCD change)
- **TPM+PIN**: Recovery key required (BCD change invalidates PCR seal)
- **BCD store location**: Unencrypted EFI System Partition, always writable from WinRE regardless of BitLocker

</details>

### VERY HARD: HVCI UEFI Locked

Maximum hardening. UEFI lock persists the HVCI enable state in Secure Boot UEFI variables. Registry changes to the HVCI scenario key are ignored at boot.

**Option A: Data-only BYOVD**

Same as HARD Option A. All data-only techniques work. No unsigned driver loading possible. The blocklist registry key is NOT UEFI locked and can still be disabled.

**Option B: WinRE Safe Mode bypass (physical access required)**

Even with UEFI-locked HVCI, the hypervisor does not load in Safe Mode. UEFI lock prevents registry changes from taking effect on **normal** boot, but Safe Mode skips hypervisor initialization entirely regardless of lock state. This is a per-session bypass: UEFI lock re-enables HVCI on normal reboot.

**Option C: Firmware intervention (physical or BMC access)**

```
1. Access UEFI setup: physical console, IPMI, iLO, iDRAC, or vPro AMT
2. Clear Secure Boot keys (PK/KEK/db/dbx) or use SecConfig.efi
   SecConfig.efi removes the UEFI lock variable, requires physical presence confirmation
3. Reboot into Windows, HVCI is now registry-disableable
4. Disable VBS + HVCI via registry + BCD (see HARD Option B commands)
5. Reboot -> use BYOVD + g_CiOptions patch
```

---

## Technical Reference

### g_CiOptions

`g_CiOptions` is the global variable in `ci.dll` that controls Driver Signature Enforcement. When HVCI is off, it resides in VTL0 kernel memory and is the sole enforcer of code integrity. When HVCI is on, `skci.dll` in VTL1 performs validation independently, making `g_CiOptions` patches ineffective.

### VBS / HVCI Architecture

```
  +-------------------------------------------------+
  |  VTL1 (Secure World)                            |
  |  +-------------+  +--------------------------+  |
  |  | skci.dll    |  | Isolated LSA (CG)        |  |
  |  | Code        |  | LSASS credential         |  |
  |  | Integrity   |  | isolation                |  |
  |  +-------------+  +--------------------------+  |
  +-------------------------------------------------+
  |  Windows Hypervisor (hvix64.exe)                |
  |  EPT enforcement: W^X on kernel code pages      |
  +-------------------------------------------------+
  |  VTL0 (Normal World)                            |
  |  +-------------+  +--------------------------+  |
  |  | ci.dll      |  | EPROCESS, tokens,        |  |
  |  | g_CiOptions |  | callbacks, ETW providers |  |
  |  | (DSE)       |  | (data-only targets)      |  |
  |  +-------------+  +--------------------------+  |
  +-------------------------------------------------+
```

When HVCI is active, `skci.dll` in VTL1 validates every driver load. EPT marks kernel code pages as writable XOR executable, never both. Patching `g_CiOptions` in VTL0 has no effect because `skci.dll` performs validation independently.

However, all kernel **data** structures remain in VTL0: EPROCESS, tokens, notification callbacks, ETW provider structures, minifilter chains. These are writable via arbitrary R/W primitives from a signed BYOVD driver at every hardening level.

### Secure Boot and BCD Flags

Secure Boot firmware validates the boot chain (bootloader, kernel, boot drivers) against the db/dbx signature database. When active, BCD flags (`testsigning`, `debug`, `nointegritychecks`) are silently ignored because the boot manager detects the integrity violation and suppresses the flags.

Secure Boot does **not** block validly-signed BYOVD drivers. It only prevents BCD-based DSE disable. This is why the MODERATE path (BYOVD + g_CiOptions patch) works even with Secure Boot enabled.

### Credential Guard vs HVCI Lock

| Property | HVCI Lock | CG Lock |
|----------|-----------|---------|
| What it protects | Driver loading, code integrity enforcement | LSASS credential isolation |
| UEFI variable | Separate per scenario key | Separate per scenario key + LsaCfgFlags |
| Effect on DSE bypass | **Direct**: prevents HVCI registry disable | **None**: does not affect driver loading |
| Effect on credential extraction | None | Prevents cleartext credential extraction from LSASS |
| Removal | SecConfig.efi or SB key clear | SecConfig.efi or SB key clear |
| Safe Mode behavior | Irrelevant (hypervisor never starts) | Irrelevant (hypervisor never starts) |

---

## OPSEC Notes

- **Read-only**: no registry writes, no BCD modifications, no driver loading, no file drops
- **Standard APIs only**: WMI (`Win32_DeviceGuard`), `Get-ItemProperty`, `bcdedit /enum`, `Confirm-SecureBootUEFI`
- **No network activity**: everything is local
- **EDR visibility**: `bcdedit /enum` and WMI queries to `Win32_DeviceGuard` may generate telemetry. Run from an elevated PowerShell session where administrative activity is expected.
- **No dependencies**: no modules, no external scripts, no internet access required

---

## Usage

```powershell
# Run as Administrator (WMI and registry access required)
powershell -ExecutionPolicy Bypass -File Check-DeviceGuard.ps1
```

Requires local administrator privileges for WMI `Win32_DeviceGuard`, BCD enumeration, and Secure Boot UEFI variable access.

---

## Supported Windows Versions

| Version | Build | Tested | Notes |
|---------|-------|--------|-------|
| Windows 10 1507+ | 10240+ | Yes | All controls assessed |
| Windows 11 21H2-24H2 | 22000-26200 | Yes | UEFI lock, WDAC multi-policy format |
| Windows Server 2016 | 14393 | Yes | VBS/HVCI support varies by edition |
| Windows Server 2019 | 17763 | Yes | |
| Windows Server 2022 | 20348 | Yes | |
| Windows Server 2025 | 26100 | Yes | |

> **Note:** Secure Boot UEFI variable access (`Confirm-SecureBootUEFI`) may not work in all VM environments. The script handles failures gracefully and reports Secure Boot as disabled if the firmware query fails.

---

## Credits

- [**loldrivers.io**](https://www.loldrivers.io/) -- comprehensive catalog of known vulnerable drivers for BYOVD research
- Microsoft documentation on [Virtualization-Based Security](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity), [WDAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/), and [Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Use it only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

---

<div align="center">

*PowerShell 5.1+ | No dependencies | Read-only assessment | Single script*

</div>
