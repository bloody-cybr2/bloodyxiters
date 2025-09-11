# =====================================================================
# BLOODY PC OPTIMIZER - DANGEROUS / HARDCORE EDITION
# 29 features + Turbo + Restore Defaults + Export Report + Restore Point
# WinForms GUI, Admin auto-elevate, Status/Progress/Log
# =====================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# -------------------------------
# Auto-elevate to Administrator
# -------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    Start-Process -FilePath 'powershell.exe' -ArgumentList $args -Verb RunAs | Out-Null
    return
}

# -------------------------------
# Globals
# -------------------------------
$script:Applied = New-Object System.Collections.Generic.List[string]
$script:Errors  = New-Object System.Collections.Generic.List[string]
$global:OptimizationLog = @()
$global:StopOnError = $false

function Append-Applied([string]$msg){ $script:Applied.Add($msg); Write-Log $msg }
function Append-Error([string]$msg){ $script:Errors.Add($msg); Write-Log $msg 'ERROR' }

# -------------------------------
# UI Helpers
# -------------------------------
function Write-Log($Message, $Level = 'INFO') {
    $timestamp = (Get-Date).ToString('HH:mm:ss')
    $line = "[$timestamp][$Level] $Message"
    $global:OptimizationLog += $line
    if ($LogBox) {
        $LogBox.AppendText($line + [Environment]::NewLine)
        $LogBox.ScrollToCaret()
    }
}
function Update-Status($text, [int]$stepInc = 0){
    if ($StatusLabel) { $StatusLabel.Text = "Status: $text" }
    if ($ProgressBar) {
        $ProgressBar.Value = [Math]::Min($ProgressBar.Value + $stepInc, $ProgressBar.Maximum)
    }
    Write-Log $text
}

# -------------------------------
# Helpers
# -------------------------------
function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('DWord','QWord','String','ExpandString','Binary')]
        [string]$Type = 'DWord',
        $Value
    )
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Append-Applied ("Reg set -> {0}\{1} = {2} ({3})" -f $Path,$Name,$Value,$Type)
    } catch {
        Append-Error ("Reg set FAIL -> {0}\{1} : {2}" -f $Path,$Name,$_.Exception.Message)
        if($global:StopOnError){ throw }
    }
}
function Disable-ServiceStrong([string]$svcName) {
    try {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 150
        sc.exe config $svcName start= disabled | Out-Null
        $svcReg = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
        if (Test-Path $svcReg) { Set-ItemProperty -Path $svcReg -Name Start -Value 4 -ErrorAction SilentlyContinue }
        Append-Applied ("Service disabled -> {0}" -f $svcName)
    } catch {
        Append-Error ("Service disable FAIL -> {0} : {1}" -f $svcName,$_.Exception.Message)
        if($global:StopOnError){ throw }
    }
}
function Set-ServiceManualSafe([string]$svcName) {
    try {
        sc.exe config $svcName start= demand | Out-Null
        Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
        Append-Applied ("Service set Manual -> {0}" -f $svcName)
    } catch {
        Append-Error ("Service manual FAIL -> {0} : {1}" -f $svcName,$_.Exception.Message)
    }
}
function Disable-Tasks([string[]]$Tasks){
    foreach($t in $Tasks){
        try { schtasks /Change /TN "$t" /DISABLE | Out-Null; Append-Applied ("Task disabled -> {0}" -f $t) }
        catch { Write-Log ("Task not disabled -> {0} - {1}" -f $t,$_.Exception.Message) 'WARN' }
    }
}

# =========================================================
# 29 FEATURES (Do- functions)
# =========================================================

# 1. Disable Unnecessary Services
function Do-DisableUnnecessaryServices {
    $list = @(
        'DiagTrack','SysMain','WSearch',
        'wuauserv','UsoSvc','WaaSMedicSvc','BITS','DoSvc',
        'RemoteRegistry','WerSvc','RetailDemo',
        'PhoneSvc','dmwappushservice','TabletInputService',
        'Fax','XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc','xbgm'
    )
    foreach($s in $list){ Disable-ServiceStrong $s }
}

# 2. Games FPS boost (disable DVR, FSE tweaks)
function Do-FPSBoost {
    Set-RegValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Type DWord -Value 0
    Set-RegValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_FSEBehaviorMode' -Type DWord -Value 2
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Type DWord -Value 0
    Set-RegValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'ShowStartupPanel' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0
}

# 3. CPU Optimize
function Do-CPUOptimize {
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation' -Type DWord -Value 38
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'SystemResponsiveness' -Type DWord -Value 0
    try {
        powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
        powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
        powercfg -setactive SCHEME_CURRENT | Out-Null
        Append-Applied "CPU AC min/max 100%"
    } catch { Append-Error ("CPU powercfg FAIL: {0}" -f $_.Exception.Message) }
}

# 4. GPU Boost (HAGS)
function Do-GPUBoost {
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode' -Type DWord -Value 2
}

# 5. Gaming Power plan (Ultimate Performance)
function Do-GamingPower {
    try {
        $dup = (powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61) 2>$null
        $guid = if ($dup) { ($dup | Select-String -Pattern '[0-9a-f-]+' | ForEach-Object { $_.Matches[0].Value } | Select-Object -First 1) } else { 'e9a42b02-d5df-448d-aa00-03f14749eb61' }
        powercfg -setactive $guid | Out-Null
        powercfg -setacvalueindex $guid SUB_PROCESSOR PERFBOOSTMODE 2 | Out-Null
        Append-Applied "Power plan: Ultimate Performance"
    } catch {
        powercfg -setactive SCHEME_MIN | Out-Null
        Append-Applied "Power plan: High Performance (fallback)"
    }
}

# 6. Disk Cleanup
function Do-DiskCleanup {
    $paths = @(
        "$env:WINDIR\SoftwareDistribution\Download\*",
        "$env:WINDIR\Logs\CBS\*",
        "$env:WINDIR\Temp\*",
        "$env:TEMP\*",
        "$env:LOCALAPPDATA\Temp\*",
        "$env:WINDIR\Prefetch\*"
    )
    foreach($p in $paths){ try { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
    Append-Applied "Disk cleanup done"
}

# 7. Memory Optimize
function Do-MemoryOptimize {
    try {
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
        Start-Process -FilePath "rundll32.exe" -ArgumentList "advapi32.dll,ProcessIdleTasks" -WindowStyle Hidden -Wait
        Append-Applied "Memory GC + idle tasks signaled"
    } catch { Append-Error ("Memory optimize FAIL: {0}" -f $_.Exception.Message) }
}

# 8. Disable Windows Update (services+tasks+policies)
function Do-DisableWindowsUpdate {
    foreach($svc in 'wuauserv','UsoSvc','WaaSMedicSvc','BITS','DoSvc'){ Disable-ServiceStrong $svc }
    $tasks = @(
        '\Microsoft\Windows\WindowsUpdate\Scheduled Start',
        '\Microsoft\Windows\WindowsUpdate\sih',
        '\Microsoft\Windows\WindowsUpdate\sihboot',
        '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
        '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker',
        '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask',
        '\Microsoft\Windows\UpdateOrchestrator\Reboot',
        '\Microsoft\Windows\DeliveryOptimization\MaintenanceTask'
    )
    Disable-Tasks -Tasks $tasks
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DoNotConnectToWindowsUpdateInternetLocations' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableWindowsUpdateAccess' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 1
}

# 9. Disable Microsoft Copilot
function Do-DisableCopilot {
    Set-RegValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Type DWord -Value 1
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -Type DWord -Value 0
}

# 10. Disable Delivery Optimization
function Do-DisableDeliveryOptimization {
    Disable-ServiceStrong 'DoSvc'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Type DWord -Value 0
}

# 11. Disable File Sharing
function Do-DisableFileSharing {
    Disable-ServiceStrong 'LanmanServer'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Type DWord -Value 0
}

# 12. Disable Network Navigation Pane
function Do-DisableNetworkPane {
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum' -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Type DWord -Value 1
}

# 13. Disable Hibernation
function Do-DisableHibernation { powercfg -hibernate off | Out-Null; Append-Applied "Hibernation OFF" }

# 14. Disable Location
function Do-DisableLocation {
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value 1
}

# 15. Disable Mobile Device Services
function Do-DisableMobile {
    foreach($svc in 'PhoneSvc','dmwappushservice'){ Disable-ServiceStrong $svc }
}

# 16. Disable Search Indexing
function Do-DisableSearchIndex { Disable-ServiceStrong 'WSearch' }

# 17. Disable Sleep (AC)
function Do-DisableSleep {
    powercfg -change -standby-timeout-ac 0 | Out-Null
    powercfg -change -hibernate-timeout-ac 0 | Out-Null
    Append-Applied "Sleep disabled (AC)"
}

# 18. Disable Sleep Study
function Do-DisableSleepStudy { Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'SleepStudyEnabled' -Type DWord -Value 0 }

# 19. Disable Notifications
function Do-DisableNotifications {
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled' -Type DWord -Value 0
    Set-RegValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1
}

# 20. Disable Widgets
function Do-DisableWidgets {
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarDa' -Type DWord -Value 0
}

# 21. Disable Windows Spotlight
function Do-DisableSpotlight {
    Set-RegValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Type DWord -Value 1
    Set-RegValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSpotlightCollectionOnDesktop' -Type DWord -Value 1
}

# 22. Disable Visual Effects (best perf)
function Do-DisableVisualEffects {
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Type DWord -Value 2
}

# 23. Disable Core Isolation (VBS/HVCI)
function Do-DisableVBS {
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Type DWord -Value 0
}

# 24. Disable CPU Mitigations (security risk)
function Do-DisableMitigations {
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverride' -Type DWord -Value 3
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverrideMask' -Type DWord -Value 3
    Append-Applied "CPU mitigations disabled (risk!)"
}

# 25. Network Optimize
function Do-NetworkOptimize {
    $ifRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    Get-ChildItem $ifRoot | ForEach-Object {
        try {
            New-ItemProperty -Path $_.PSPath -Name 'TcpAckFrequency' -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $_.PSPath -Name 'TCPNoDelay' -Value 1 -PropertyType DWord -Force | Out-Null
        } catch {}
    }
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Type DWord -Value 0xFFFFFFFF
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' -Name 'NonBestEffortLimit' -Type DWord -Value 0
}

# 26. Disable Startup Apps (HKCU Run)
function Do-DisableStartupApps {
    try {
        $rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        if (Test-Path $rk) {
            (Get-Item $rk).Property | ForEach-Object { Remove-ItemProperty -Path $rk -Name $_ -ErrorAction SilentlyContinue }
        }
        Append-Applied "Startup apps cleared (HKCU Run)"
    } catch { Append-Error ("Startup app cleanup FAIL: {0}" -f $_.Exception.Message) }
}

# 27. Disable Background Apps
function Do-DisableBackgroundApps {
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Name 'GlobalUserDisabled' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -Type DWord -Value 2
}

# 28. Keyboard & Mouse Tweaks
function Do-InputTweaks {
    # Mouse accel OFF
    Set-RegValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Type String -Value '0'
    Set-RegValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Type String -Value '0'
    Set-RegValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Type String -Value '0'
    # Keyboard repeat faster
    Set-RegValue -Path 'HKCU:\Control Panel\Keyboard' -Name 'KeyboardDelay' -Type String -Value '0'
    Set-RegValue -Path 'HKCU:\Control Panel\Keyboard' -Name 'KeyboardSpeed' -Type String -Value '31'
    Append-Applied "Keyboard & Mouse tuned"
}

# 29. Clean Temp Files
function Do-CleanTemp {
    $paths = @(
        "$env:TEMP\*",
        "$env:WINDIR\Temp\*",
        "$env:LOCALAPPDATA\Temp\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*",
        "$env:WINDIR\Prefetch\*"
    )
    foreach ($p in $paths) { try { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
    Append-Applied "Temp/cache cleaned"
}

# =========================================================
# Utilities: Restore Point, Restore Defaults, Export Report
# =========================================================
function Do-CreateRestorePoint {
    try {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue | Out-Null
        Checkpoint-Computer -Description 'BLOODY-PC-OPTIMIZER' -RestorePointType 'MODIFY_SETTINGS'
        Write-Log 'System Restore Point created.'
    } catch { Write-Log ("Restore point FAIL: {0}" -f $_.Exception.Message) 'WARN' }
}

function Do-RestoreDefaults {
    Update-Status 'Restoring defaults...'
    foreach($svc in 'wuauserv','UsoSvc','BITS','WaaSMedicSvc','WSearch','SysMain','LanmanServer','DoSvc'){
        Set-ServiceManualSafe $svc
    }
    try { powercfg -setactive SCHEME_BALANCED | Out-Null } catch {}
    # Undo some policies (best-effort)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableWindowsUpdateAccess' -Type DWord -Value 0
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Type DWord -Value 3
    Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1
    Write-Log 'Defaults restored (core items). Some changes require reboot.'
}

function Do-ExportReport {
    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $path = Join-Path $desktop ("BloodyOptimizer-Report-{0}.txt" -f (Get-Date -f 'yyyyMMdd-HHmmss'))
        $content = @()
        $content += 'BLOODY PC OPTIMIZER - REPORT'
        $content += ("Date: {0}" -f (Get-Date))
        $content += ''
        $content += 'Applied Items:'
        $content += ($script:Applied | Sort-Object)
        if ($script:Errors.Count -gt 0) {
            $content += ''
            $content += 'Errors:'
            $content += ($script:Errors | Sort-Object)
        }
        $content += ''
        $content += 'Log:'
        $content += $global:OptimizationLog
        $content -join [Environment]::NewLine | Set-Content -Path $path -Encoding UTF8
        Write-Log ("Report saved: {0}" -f $path)
    } catch { Write-Log ("Report export FAIL: {0}" -f $_.Exception.Message) 'WARN' }
}

# =========================================================
# GUI - Dark / Hacker vibe (no particles)
# =========================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = 'BLOODY PC OPTIMIZER - DANGEROUS MODE'
$form.Size = New-Object System.Drawing.Size(1020,720)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::Black
$form.ForeColor = [System.Drawing.Color]::Lime
$form.Font = New-Object System.Drawing.Font('Consolas',10,[System.Drawing.FontStyle]::Bold)

$banner = New-Object System.Windows.Forms.Label
$banner.Text = 'BLOODY PC OPTIMIZER'
$banner.AutoSize = $true
$banner.Font = New-Object System.Drawing.Font('Consolas',20,[System.Drawing.FontStyle]::Bold)
$banner.ForeColor = [System.Drawing.Color]::Lime
$banner.Location = New-Object System.Drawing.Point(20,15)
$form.Controls.Add($banner)

$StatusLabel = New-Object System.Windows.Forms.Label
$StatusLabel.Text = 'Status: Idle'
$StatusLabel.AutoSize = $true
$StatusLabel.Font = New-Object System.Drawing.Font('Consolas',10)
$StatusLabel.Location = New-Object System.Drawing.Point(22,50)
$form.Controls.Add($StatusLabel)

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Minimum = 0; $ProgressBar.Maximum = 100; $ProgressBar.Value = 0
$ProgressBar.Style = 'Continuous'
$ProgressBar.Location = New-Object System.Drawing.Point(20,70)
$ProgressBar.Size = New-Object System.Drawing.Size(970,18)
$form.Controls.Add($ProgressBar)

# Scroll panel for checkboxes
$panel = New-Object System.Windows.Forms.Panel
$panel.Location = New-Object System.Drawing.Point(20,100)
$panel.Size = New-Object System.Drawing.Size(480,520)
$panel.AutoScroll = $true
$panel.BackColor = [System.Drawing.Color]::FromArgb(20,20,20)
$form.Controls.Add($panel)

# Live log
$LogBox = New-Object System.Windows.Forms.TextBox
$LogBox.Multiline = $true
$LogBox.ScrollBars = 'Vertical'
$LogBox.ReadOnly = $true
$LogBox.BackColor = [System.Drawing.Color]::Black
$LogBox.ForeColor = [System.Drawing.Color]::Lime
$LogBox.Font = New-Object System.Drawing.Font('Consolas',9)
$LogBox.Location = New-Object System.Drawing.Point(520,100)
$LogBox.Size = New-Object System.Drawing.Size(470,520)
$form.Controls.Add($LogBox)

# Buttons
$btnRunSelected = New-Object System.Windows.Forms.Button
$btnRunSelected.Text = 'RUN SELECTED'
$btnRunSelected.BackColor = [System.Drawing.Color]::Black
$btnRunSelected.ForeColor = [System.Drawing.Color]::Lime
$btnRunSelected.Location = New-Object System.Drawing.Point(20,640)
$btnRunSelected.Size = New-Object System.Drawing.Size(180,35)
$form.Controls.Add($btnRunSelected)

$btnTurbo = New-Object System.Windows.Forms.Button
$btnTurbo.Text = 'AUTO-TURBO (ALL)'
$btnTurbo.BackColor = [System.Drawing.Color]::Black
$btnTurbo.ForeColor = [System.Drawing.Color]::Lime
$btnTurbo.Location = New-Object System.Drawing.Point(210,640)
$btnTurbo.Size = New-Object System.Drawing.Size(180,35)
$form.Controls.Add($btnTurbo)

$btnRestore = New-Object System.Windows.Forms.Button
$btnRestore.Text = 'RESTORE DEFAULTS'
$btnRestore.BackColor = [System.Drawing.Color]::Black
$btnRestore.ForeColor = [System.Drawing.Color]::Yellow
$btnRestore.Location = New-Object System.Drawing.Point(400,640)
$btnRestore.Size = New-Object System.Drawing.Size(180,35)
$form.Controls.Add($btnRestore)

$btnRestorePoint = New-Object System.Windows.Forms.Button
$btnRestorePoint.Text = 'CREATE RESTORE POINT'
$btnRestorePoint.BackColor = [System.Drawing.Color]::Black
$btnRestorePoint.ForeColor = [System.Drawing.Color]::Lime
$btnRestorePoint.Location = New-Object System.Drawing.Point(590,640)
$btnRestorePoint.Size = New-Object System.Drawing.Size(200,35)
$form.Controls.Add($btnRestorePoint)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = 'EXPORT REPORT'
$btnExport.BackColor = [System.Drawing.Color]::Black
$btnExport.ForeColor = [System.Drawing.Color]::Cyan
$btnExport.Location = New-Object System.Drawing.Point(800,640)
$btnExport.Size = New-Object System.Drawing.Size(190,35)
$form.Controls.Add($btnExport)

# Checkbox items (29)
$items = @(
    @{Text='Disable Unnecessary Services'; Fn={ Do-DisableUnnecessaryServices }},
    @{Text='Games FPS Boost'; Fn={ Do-FPSBoost }},
    @{Text='CPU Optimize'; Fn={ Do-CPUOptimize }},
    @{Text='GPU Boost (HAGS)'; Fn={ Do-GPUBoost }},
    @{Text='Gaming Power Plan'; Fn={ Do-GamingPower }},
    @{Text='Disk Cleanup'; Fn={ Do-DiskCleanup }},
    @{Text='Memory Optimize'; Fn={ Do-MemoryOptimize }},
    @{Text='Disable Windows Update (Permanent)'; Fn={ Do-DisableWindowsUpdate }},
    @{Text='Disable Microsoft Copilot'; Fn={ Do-DisableCopilot }},
    @{Text='Disable Delivery Optimization'; Fn={ Do-DisableDeliveryOptimization }},
    @{Text='Disable File Sharing'; Fn={ Do-DisableFileSharing }},
    @{Text='Disable Network Navigation Pane'; Fn={ Do-DisableNetworkPane }},
    @{Text='Disable Hibernation'; Fn={ Do-DisableHibernation }},
    @{Text='Disable Location'; Fn={ Do-DisableLocation }},
    @{Text='Disable Mobile Device Services'; Fn={ Do-DisableMobile }},
    @{Text='Disable Search Indexing'; Fn={ Do-DisableSearchIndex }},
    @{Text='Disable Sleep'; Fn={ Do-DisableSleep }},
    @{Text='Disable Sleep Study'; Fn={ Do-DisableSleepStudy }},
    @{Text='Disable Notifications'; Fn={ Do-DisableNotifications }},
    @{Text='Disable Widgets'; Fn={ Do-DisableWidgets }},
    @{Text='Disable Windows Spotlight'; Fn={ Do-DisableSpotlight }},
    @{Text='Disable Visual Effects'; Fn={ Do-DisableVisualEffects }},
    @{Text='Disable Core Isolation (VBS)'; Fn={ Do-DisableVBS }},
    @{Text='Disable CPU Mitigations (Risk)'; Fn={ Do-DisableMitigations }},
    @{Text='Network Optimize'; Fn={ Do-NetworkOptimize }},
    @{Text='Disable Startup Apps'; Fn={ Do-DisableStartupApps }},
    @{Text='Disable Background Apps'; Fn={ Do-DisableBackgroundApps }},
    @{Text='Keyboard and Mouse Tweaks'; Fn={ Do-InputTweaks }},
    @{Text='Clean Temp Files'; Fn={ Do-CleanTemp }}
)

# Render checkboxes
$y=10; $chkList = @()

# Select All at top
$chkAll = New-Object System.Windows.Forms.CheckBox
$chkAll.Text = 'Select All'
$chkAll.AutoSize = $true
$chkAll.ForeColor = [System.Drawing.Color]::White
$chkAll.Location = New-Object System.Drawing.Point(10, $y)
$panel.Controls.Add($chkAll)

$y = 40 # start list under Select All

foreach($it in $items){
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $it.Text
    $chk.AutoSize = $true
    $chk.ForeColor = [System.Drawing.Color]::Lime
    $chk.Location = New-Object System.Drawing.Point(10,$y)
    $panel.Controls.Add($chk)
    $chkList += @{Box=$chk; Fn=$it.Fn}
    $y += 26
}

# Select All handler
$chkAll.Add_CheckedChanged({ foreach($c in $chkList){ $c.Box.Checked = $chkAll.Checked } })

# Runners
function Run-Selected {
    $selected = $chkList | Where-Object { $_.Box.Checked }
    if(-not $selected){ Write-Log 'No items selected.'; return }
    $count = $selected.Count
    $ProgressBar.Value = 0; $ProgressBar.Maximum = 100
    $inc = [Math]::Ceiling(100 / [Math]::Max($count,1))
    foreach($item in $selected){
        try { $item.Fn.Invoke(); Update-Status ("Done: {0}" -f $item.Box.Text) $inc }
        catch { Append-Error ("Run FAIL: {0} : {1}" -f $item.Box.Text,$_.Exception.Message) }
    }
    Update-Status 'Selected optimizations completed.' 0
    Write-Log 'Reboot is recommended.'
}

function Run-All {
    foreach($c in $chkList){ $c.Box.Checked = $true }
    Run-Selected
}

# Button events
$btnRunSelected.Add_Click({ Run-Selected })
$btnTurbo.Add_Click({ Run-All })
$btnRestore.Add_Click({ Do-RestoreDefaults })
$btnRestorePoint.Add_Click({ Do-CreateRestorePoint })
$btnExport.Add_Click({ Do-ExportReport })

# ---------------------------
# RUN FORM (no auto-close)
# ---------------------------
[void][System.Windows.Forms.Application]::Run($form)
