#requires -Version 7.0
<#
================================================================================
 AEGIS H2-SHIELD  —  HTTP/2 Bomb (CVE-2026-49975) Defense Auditor & Hardener
================================================================================
 PUNKS / OSIRIS-CORE  |  Windows 11 server-surface hardening GUI

 WHAT THIS ACTUALLY DOES (and what it deliberately does NOT do):
   HTTP/2 Bomb is a SERVER-SIDE memory-exhaustion attack against processes that
   listen for inbound HTTP/2 and decode HPACK (IIS / nginx / Apache / Envoy /
   Pingora). It does NOT affect arbitrary GUI apps or non-HTTP/2 ports. So this
   tool does the things that genuinely reduce that class of risk:
     1. Inventory every LISTENING port + owning process (TCP/UDP, v4/v6)
     2. Flag anything bound beyond loopback (real inbound attack surface)
     3. Detect IIS + HTTP.SYS HTTP/2 state on this box
     4. HARDEN: disable HTTP/2 at the HTTP.SYS layer (chosen mitigation),
        since IIS has no vendor patch for CVE-2026-49975 at time of writing
     5. Clamp HTTP.SYS header/URL limits as defense-in-depth
     6. Apply a per-process memory ceiling concept via WSRM-style job limits
        for IIS worker pools (w3wp) so a flooded worker is killed, not swapped
     7. Verify + report, export JSON evidence
   Self-hosting: installs a scheduled task that re-runs the audit on a cadence
   and re-applies hardening if drift is detected (self-healing). Auto-update
   pulls a newer version of this script from a configurable URL if present.

 USAGE:  Open admin PowerShell 7  ->  paste this whole script  ->  Enter.
         It writes itself to C:\AEGIS_Source\H2Shield\ and launches the GUI.
================================================================================
#>

[CmdletBinding()]
param(
    [switch]$Headless,        # run audit+harden with no GUI (used by scheduled task)
    [switch]$AuditOnly,       # never mutate, just report
    [switch]$InstallTask,     # (re)install the self-healing scheduled task
    [string]$UpdateUrl = ''   # optional: raw URL to fetch a newer version of this script
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# 0. Self-installation: copy this script to a stable home so the task can find it
# ---------------------------------------------------------------------------
$AppRoot   = 'C:\AEGIS_Source\H2Shield'
$ScriptDst = Join-Path $AppRoot 'AEGIS_H2Shield.ps1'
$LogDir    = Join-Path $AppRoot 'logs'
$RepDir    = Join-Path $AppRoot 'reports'
$Version   = '1.2.0'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = (Get-Date -Format 's') + " [" + $Level + "] " + [string]$Msg
    Write-Host $line
    try { Add-Content -Path (Join-Path $LogDir 'h2shield.log') -Value $line -ErrorAction SilentlyContinue } catch {}
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning 'This must run in an ELEVATED PowerShell 7 session. Re-launch as Administrator.'
    return
}

foreach ($d in @($AppRoot, $LogDir, $RepDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Persist a copy of ourselves (idempotent)
try {
    $selfPath = $PSCommandPath
    if ($selfPath -and (Test-Path $selfPath) -and ($selfPath -ne $ScriptDst)) {
        Copy-Item $selfPath $ScriptDst -Force
    } elseif (-not (Test-Path $ScriptDst) -and $MyInvocation.MyCommand.Definition) {
        # pasted-into-console case: write our own source out
        $MyInvocation.MyCommand.ScriptBlock.ToString() | Set-Content -Path $ScriptDst -Encoding UTF8
    }
} catch { Write-Log "Self-persist skipped: $($_.Exception.Message)" 'WARN' }

# ---------------------------------------------------------------------------
# 1. Auto-update (optional, opt-in via -UpdateUrl)
# ---------------------------------------------------------------------------
function Invoke-SelfUpdate {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return }
    try {
        $tmp = Join-Path $env:TEMP 'h2shield_new.ps1'
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -TimeoutSec 20
        $newVer = (Select-String -Path $tmp -Pattern "^\s*\`$Version\s*=\s*'([0-9.]+)'" |
                   Select-Object -First 1).Matches.Groups[1].Value
        if ($newVer -and ([version]$newVer -gt [version]$Version)) {
            Copy-Item $tmp $ScriptDst -Force
            Write-Log "Self-updated $Version -> $newVer" 'INFO'
        }
    } catch { Write-Log "Self-update failed: $($_.Exception.Message)" 'WARN' }
}

# ===========================================================================
# 2. CORE AUDIT ENGINE
# ===========================================================================

function Get-Scope {
    param([string]$addr)
    if ($addr -in @('127.0.0.1','::1')) { return 'Loopback' }
    if ($addr -in @('0.0.0.0','::'))    { return 'All' }
    if ($addr -like 'fe80:*' -or $addr -like '169.254.*') { return 'LinkLocal' }
    return 'LAN'
}
function Get-Risk {
    param([string]$proto,[int]$port,[string]$scope)
    if ($proto -ne 'TCP') { return $false }
    if ($scope -in @('Loopback','LinkLocal')) { return $false }
    return ($port -in @(80,443,8080,8443,8000,8337,3210,5000,7000))
}
function Get-ListeningSurface {
    # Every listening TCP/UDP endpoint + owning process, classified by reachability.
    $rows = [System.Collections.Generic.List[object]]::new()

    # Resolve ALL processes once into a PID->name map (avoids per-socket Get-Process,
    # which is the slow path and triggers access-denied exceptions in a tight loop).
    $procMap = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procMap[[int]$p.Id] = $p.ProcessName }

    $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $tcp) {
        $name = if ($procMap.ContainsKey([int]$c.OwningProcess)) { $procMap[[int]$c.OwningProcess] } else { '?' }
        $sc = Get-Scope $c.LocalAddress
        $rows.Add([pscustomobject]@{
            Proto = 'TCP'; LocalAddr = $c.LocalAddress; Port = $c.LocalPort
            PID = $c.OwningProcess; Process = $name
            Scope = $sc; Risk = (Get-Risk 'TCP' $c.LocalPort $sc)
        })
    }
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($c in $udp) {
        $name = if ($procMap.ContainsKey([int]$c.OwningProcess)) { $procMap[[int]$c.OwningProcess] } else { '?' }
        $sc = Get-Scope $c.LocalAddress
        $rows.Add([pscustomobject]@{
            Proto = 'UDP'; LocalAddr = $c.LocalAddress; Port = $c.LocalPort
            PID = $c.OwningProcess; Process = $name
            Scope = $sc; Risk = (Get-Risk 'UDP' $c.LocalPort $sc)
        })
    }
    $rows | Sort-Object @{Expression='Risk';Descending=$true}, @{Expression='Port';Descending=$false}
}

function Get-IISState {
    $state = [ordered]@{
        IISInstalled   = $false
        HttpSysHttp2   = $null   # current EnableHttp2 effective state
        Sites          = @()
        W3wpRunning    = @()
    }
    $svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($svc) {
        $state.IISInstalled = $true
        try {
            $reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            $v = (Get-ItemProperty -Path $reg -Name 'EnableHttp2Tls' -ErrorAction SilentlyContinue).EnableHttp2Tls
            $c = (Get-ItemProperty -Path $reg -Name 'EnableHttp2Cleartext' -ErrorAction SilentlyContinue).EnableHttp2Cleartext
            $state.HttpSysHttp2 = [ordered]@{ Tls = $v; Cleartext = $c }
        } catch {}
        try {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            $state.Sites = @(Get-Website | Select-Object Name, State, @{n='Bindings';e={($_.bindings.Collection.bindingInformation) -join ', '}})
        } catch {}
        $state.W3wpRunning = @(Get-Process w3wp -ErrorAction SilentlyContinue | Select-Object Id, @{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}})
    }
    [pscustomobject]$state
}

function Test-HardeningDrift {
    # returns $true if hardening is NOT in place (i.e. needs re-apply)
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
    $tls = (Get-ItemProperty -Path $reg -Name 'EnableHttp2Tls' -ErrorAction SilentlyContinue).EnableHttp2Tls
    $clr = (Get-ItemProperty -Path $reg -Name 'EnableHttp2Cleartext' -ErrorAction SilentlyContinue).EnableHttp2Cleartext
    $svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if (-not $svc) { return $false }  # no IIS, nothing to drift
    return -not (($tls -eq 0) -and ($clr -eq 0))
}

# ===========================================================================
# 3. HARDENING ACTIONS  (chosen mitigation: HARD-DISABLE HTTP/2)
# ===========================================================================

function Invoke-Hardening {
    param([switch]$WhatIfOnly)
    $actions = [System.Collections.Generic.List[string]]::new()
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'

    $svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if (-not $svc) {
        $actions.Add('IIS/W3SVC not present on this box — no HTTP/2 server surface to harden.')
        return $actions
    }

    # --- (a) Disable HTTP/2 at the HTTP.SYS layer (closes the CVE-2026-49975 vector) ---
    if ($WhatIfOnly) {
        $actions.Add('[plan] Set HTTP\Parameters EnableHttp2Tls=0 and EnableHttp2Cleartext=0')
    } else {
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
        New-ItemProperty -Path $reg -Name 'EnableHttp2Tls'       -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $reg -Name 'EnableHttp2Cleartext' -Value 0 -PropertyType DWord -Force | Out-Null
        $actions.Add('HTTP/2 disabled at HTTP.SYS (EnableHttp2Tls=0, EnableHttp2Cleartext=0). Clients fall back to HTTP/1.1.')
    }

    # --- (b) Defense-in-depth: clamp HTTP.SYS header / field limits ---
    # Caps oversized header sets even on HTTP/1.1; harmless ceilings.
    $limits = @{ MaxFieldLength = 16384; MaxRequestBytes = 32768 }
    foreach ($k in $limits.Keys) {
        if ($WhatIfOnly) {
            $actions.Add("[plan] Set HTTP\Parameters $k=$($limits[$k])")
        } else {
            New-ItemProperty -Path $reg -Name $k -Value $limits[$k] -PropertyType DWord -Force | Out-Null
            $actions.Add("HTTP.SYS $k clamped to $($limits[$k]).")
        }
    }

    # --- (c) Per-pool memory ceiling: recycle w3wp on private-memory cap ---
    # Only attempt when IIS is actually running; IIS:\AppPools is unreadable otherwise.
    if (-not $WhatIfOnly) {
        if ($svc.Status -eq 'Running') {
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | ForEach-Object {
                    $pool = $_.Name
                    Set-ItemProperty "IIS:\AppPools\$pool" -Name recycling.periodicRestart.privateMemory -Value 1572864 -ErrorAction SilentlyContinue
                    $actions.Add("AppPool '$pool': private-memory recycle cap set to 1.5 GB.")
                }
            } catch { $actions.Add("AppPool memory cap step skipped: $($_.Exception.Message)") }
        } else { $actions.Add('AppPool memory caps skipped (W3SVC not running).') }
    } else {
        $actions.Add('[plan] Set every AppPool privateMemory recycle cap to 1.5 GB (only if IIS running)')
    }

    # --- (d) STATE-AWARE restart (v1.2.0 fix) ---
    # Restart the kernel HTTP.SYS driver ONLY when IIS is live and needs the change
    # applied immediately. When W3SVC is Stopped/Disabled, the registry values apply
    # on HTTP.SYS's next start by themselves — force-restarting the kernel driver in
    # that state can wedge it into StopPending, so we skip it entirely.
    if (-not $WhatIfOnly) {
        $sd = $svc.StartType
        if ($svc.Status -eq 'Running' -and $sd -ne 'Disabled') {
            try {
                Stop-Service W3SVC -Force -ErrorAction Stop
                Restart-Service HTTP -Force -ErrorAction Stop
                Start-Service W3SVC -ErrorAction Stop
                $actions.Add('IIS was running: restarted HTTP.SYS + W3SVC to apply HTTP/2 disable.')
            } catch { $actions.Add("Service restart issue (registry values still applied): $($_.Exception.Message)") }
        } else {
            $actions.Add("IIS is $($svc.Status)/$sd — registry values written; NO kernel restart performed (applies on next HTTP.SYS start).")
        }
    } else {
        $actions.Add('[plan] Restart HTTP.SYS + W3SVC only if IIS is currently running')
    }

    return $actions
}

# ===========================================================================
# 4. SELF-HEALING SCHEDULED TASK
# ===========================================================================
function Install-HealTask {
    $taskName = 'AEGIS_H2Shield_Heal'
    $pwsh = (Get-Command pwsh).Source
    $arg  = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptDst`" -Headless"
    if ($UpdateUrl) { $arg += " -UpdateUrl `"$UpdateUrl`"" }

    $action  = New-ScheduledTaskAction -Execute $pwsh -Argument $arg
    $trigger = New-ScheduledTaskTrigger -Daily -At 3am
    $trigger2= New-ScheduledTaskTrigger -AtStartup
    $set     = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger,$trigger2) `
        -Settings $set -Principal $princ -Force | Out-Null
    Write-Log "Self-healing task '$taskName' installed (daily 03:00 + at startup)." 'INFO'
}

# ===========================================================================
# 5. ORCHESTRATION (used by both GUI and headless)
# ===========================================================================
function Invoke-FullAudit {
    param([switch]$Harden)
    Invoke-SelfUpdate -Url $UpdateUrl
    $surface = Get-ListeningSurface
    $iis     = Get-IISState
    $drift   = Test-HardeningDrift
    $applied = @()
    if ($Harden) { $applied = Invoke-Hardening }
    elseif ($AuditOnly) { $applied = Invoke-Hardening -WhatIfOnly }

    $report = [ordered]@{
        Host       = $env:COMPUTERNAME
        Timestamp  = (Get-Date -Format 's')
        Version    = $Version
        DriftFound = $drift
        AtRisk     = @($surface | Where-Object Risk)
        Reachable  = @($surface | Where-Object { $_.Scope -in @('All','LAN') })
        AllPorts   = $surface
        IIS        = $iis
        Actions    = $applied
    }
    $repPath = Join-Path $RepDir ("audit_{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $repPath -Encoding UTF8
    Write-Log "Audit report -> $repPath (drift=$drift, at-risk=$(@($surface | Where-Object Risk).Count))" 'INFO'
    [pscustomobject]$report
}

# ---- Headless path (scheduled task): audit, self-heal on drift, exit -------
if ($Headless) {
    $r = Invoke-FullAudit
    if ($r.DriftFound) {
        Write-Log 'Drift detected — re-applying hardening.' 'WARN'
        Invoke-Hardening | ForEach-Object { Write-Log $_ 'HEAL' }
    }
    if ($InstallTask) { Install-HealTask }
    return
}
if ($InstallTask) { Install-HealTask }   # install, then fall through to launch the GUI

# ===========================================================================
# 6. WPF GUI
# ===========================================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AEGIS H2-SHIELD v1.2.0 — CVE-2026-49975 Defense" Height="640" Width="980"
        Background="#0d1117" WindowStartupLocation="CenterScreen">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" Text="AEGIS H2-SHIELD" FontSize="22" FontWeight="Bold" Foreground="#58a6ff"/>
    <TextBlock Grid.Row="0" Margin="170,8,0,0" Text="HTTP/2 Bomb (CVE-2026-49975) server-surface auditor + hardener" Foreground="#8b949e"/>
    <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,12,0,8">
      <Button x:Name="BtnAudit"  Content="Run Audit"        Width="120" Height="34" Margin="0,0,8,0" Background="#21262d" Foreground="White"/>
      <Button x:Name="BtnHarden" Content="Audit + Harden"   Width="140" Height="34" Margin="0,0,8,0" Background="#238636" Foreground="White"/>
      <Button x:Name="BtnVerify" Content="Verify"           Width="100" Height="34" Margin="0,0,8,0" Background="#1f6feb" Foreground="White"/>
      <Button x:Name="BtnTask"   Content="Install Self-Heal" Width="150" Height="34" Margin="0,0,8,0" Background="#21262d" Foreground="White"/>
      <Button x:Name="BtnReport" Content="Open Reports"     Width="120" Height="34" Background="#21262d" Foreground="White"/>
    </StackPanel>
    <Border Grid.Row="2" Margin="0,0,0,8" Padding="8" Background="#161b22" CornerRadius="4">
      <StackPanel>
        <Grid>
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBlock x:Name="StageTxt" Grid.Column="0" Text="Idle." Foreground="#c9d1d9" FontFamily="Consolas"/>
          <TextBlock x:Name="MetricTxt" Grid.Column="1" Text="" Foreground="#8b949e" FontFamily="Consolas"/>
        </Grid>
        <ProgressBar x:Name="Bar" Height="14" Margin="0,6,0,0" Minimum="0" Maximum="100" Value="0"
                     Background="#0d1117" Foreground="#238636"/>
      </StackPanel>
    </Border>
    <TabControl Grid.Row="3" Background="#0d1117">
      <TabItem Header="Listening Surface">
        <DataGrid x:Name="GridPorts" AutoGenerateColumns="True" IsReadOnly="True"
                  Background="#0d1117" Foreground="#c9d1d9" GridLinesVisibility="Horizontal"/>
      </TabItem>
      <TabItem Header="IIS / HTTP.SYS">
        <TextBox x:Name="TxtIIS" IsReadOnly="True" Background="#0d1117" Foreground="#c9d1d9"
                 FontFamily="Consolas" VerticalScrollBarVisibility="Auto" TextWrapping="Wrap"/>
      </TabItem>
      <TabItem Header="Actions / Log">
        <TextBox x:Name="TxtLog" IsReadOnly="True" Background="#0d1117" Foreground="#7ee787"
                 FontFamily="Consolas" VerticalScrollBarVisibility="Auto" TextWrapping="Wrap"/>
      </TabItem>
    </TabControl>
    <StatusBar Grid.Row="4" Background="#161b22">
      <TextBlock x:Name="StatusTxt" Text="Ready." Foreground="#8b949e"/>
    </StatusBar>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$win    = [Windows.Markup.XamlReader]::Load($reader)

$BtnAudit  = $win.FindName('BtnAudit')
$BtnHarden = $win.FindName('BtnHarden')
$BtnVerify = $win.FindName('BtnVerify')
$BtnTask   = $win.FindName('BtnTask')
$BtnReport = $win.FindName('BtnReport')
$GridPorts = $win.FindName('GridPorts')
$TxtIIS    = $win.FindName('TxtIIS')
$TxtLog    = $win.FindName('TxtLog')
$Status    = $win.FindName('StatusTxt')
$StageTxt  = $win.FindName('StageTxt')
$MetricTxt = $win.FindName('MetricTxt')
$Bar       = $win.FindName('Bar')

# Shared state object the background runspace writes and the UI timer reads.
$script:State = [hashtable]::Synchronized(@{
    Running = $false; Stage = 'Idle.'; Pct = 0; Metric = ''
    StartTicks = 0; Report = $null; Error = $null
})

# The ordered stages of an audit; each maps to a % checkpoint. These are REAL
# steps, not invented fractions — the bar advances as each one truly completes.
$script:Stages = @(
    @{ Name = 'Enumerating processes'; Pct = 15 }
    @{ Name = 'Scanning TCP listeners'; Pct = 40 }
    @{ Name = 'Scanning UDP endpoints'; Pct = 60 }
    @{ Name = 'Reading IIS / HTTP.SYS state'; Pct = 75 }
    @{ Name = 'Applying / checking hardening'; Pct = 90 }
    @{ Name = 'Writing report'; Pct = 100 }
)

function Start-AuditAsync {
    param([bool]$Harden)
    if ($script:State.Running) { return }
    $script:State.Running = $true
    $script:State.StartTicks = [DateTime]::UtcNow.Ticks
    $script:State.Report = $null; $script:State.Error = $null
    $script:State.Stage = 'Starting…'; $script:State.Pct = 0; $script:State.Metric = ''
    foreach ($b in @($BtnAudit,$BtnHarden,$BtnVerify,$BtnTask)) { $b.IsEnabled = $false }

    # Background runspace. We re-declare the worker logic inline (runspaces don't
    # inherit the parent's functions), writing progress into the shared state.
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='MTA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('S', $script:State)
    $rs.SessionStateProxy.SetVariable('DoHarden', $Harden)
    $rs.SessionStateProxy.SetVariable('RepDir', $RepDir)
    $rs.SessionStateProxy.SetVariable('Version', $Version)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $ps.AddScript({
        try {
            # --- classification helpers (inline; runspace doesn't inherit funcs) ---
            # Scope tiers by bind address, most-reachable first:
            #   All       = 0.0.0.0 / :: (reachable from anywhere routing allows)
            #   LAN       = a real private/CGNAT address bound to a NIC (LAN-reachable)
            #   LinkLocal = fe80:: (same segment only, effectively local)
            #   Loopback  = 127.0.0.1 / ::1 (this machine only)
            function Get-Scope([string]$addr) {
                if ($addr -in @('127.0.0.1','::1')) { return 'Loopback' }
                if ($addr -in @('0.0.0.0','::'))    { return 'All' }
                if ($addr -like 'fe80:*' -or $addr -like 'fe80::*') { return 'LinkLocal' }
                if ($addr -like '169.254.*')        { return 'LinkLocal' }
                return 'LAN'
            }
            # Ports that matter for the HTTP/2 Bomb class specifically (web listeners).
            $webPorts = @(80,443,8080,8443,8000,8337,3210,5000,7000)
            function Get-Risk([string]$proto,[int]$port,[string]$scope) {
                # Only TCP web listeners that are actually reachable count as in-scope
                # for CVE-2026-49975. UDP, loopback, and link-local are not.
                if ($proto -ne 'TCP') { return $false }
                if ($scope -in @('Loopback','LinkLocal')) { return $false }
                return ($port -in $webPorts)
            }

            # 1. processes
            $S.Stage='Enumerating processes'; $S.Pct=5
            $procMap=@{}; foreach($p in (Get-Process -ErrorAction SilentlyContinue)){$procMap[[int]$p.Id]=$p.ProcessName}
            $S.Metric="procs: $($procMap.Count)"; $S.Pct=15

            # 2. tcp
            $S.Stage='Scanning TCP listeners'
            $rows=[System.Collections.Generic.List[object]]::new()
            $tcp=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
            $i=0; foreach($c in $tcp){
                $i++; $S.Metric="TCP $i/$($tcp.Count) | procs: $($procMap.Count)"
                $S.Pct=[int](15+25*($i/[math]::Max(1,$tcp.Count)))
                $n=if($procMap.ContainsKey([int]$c.OwningProcess)){$procMap[[int]$c.OwningProcess]}else{'?'}
                $sc=Get-Scope $c.LocalAddress
                $rows.Add([pscustomobject]@{Proto='TCP';LocalAddr=$c.LocalAddress;Port=$c.LocalPort;PID=$c.OwningProcess;Process=$n;Scope=$sc;Risk=(Get-Risk 'TCP' $c.LocalPort $sc)})
            }
            # 3. udp
            $S.Stage='Scanning UDP endpoints'
            $udp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
            $j=0; foreach($c in $udp){
                $j++; $S.Metric="UDP $j/$($udp.Count) | TCP: $($tcp.Count)"
                $S.Pct=[int](40+20*($j/[math]::Max(1,$udp.Count)))
                $n=if($procMap.ContainsKey([int]$c.OwningProcess)){$procMap[[int]$c.OwningProcess]}else{'?'}
                $sc=Get-Scope $c.LocalAddress
                $rows.Add([pscustomobject]@{Proto='UDP';LocalAddr=$c.LocalAddress;Port=$c.LocalPort;PID=$c.OwningProcess;Process=$n;Scope=$sc;Risk=(Get-Risk 'UDP' $c.LocalPort $sc)})
            }
            $surface=$rows | Sort-Object @{Expression='Risk';Descending=$true},@{Expression='Scope';Descending=$false},@{Expression='Port';Descending=$false}

            # 4. iis state
            $S.Stage='Reading IIS / HTTP.SYS state'; $S.Pct=70
            $iisInstalled=$false; $iisJson='{}'
            $svc=Get-Service -Name W3SVC -ErrorAction SilentlyContinue
            if($svc){
                $iisInstalled=$true
                $reg='HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
                $tls=(Get-ItemProperty $reg -Name EnableHttp2Tls -ErrorAction SilentlyContinue).EnableHttp2Tls
                $clr=(Get-ItemProperty $reg -Name EnableHttp2Cleartext -ErrorAction SilentlyContinue).EnableHttp2Cleartext
                $w3=@(Get-Process w3wp -ErrorAction SilentlyContinue | Select-Object Id,@{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}})
                $iisJson=([ordered]@{IISInstalled=$true;EnableHttp2Tls=$tls;EnableHttp2Cleartext=$clr;W3wp=$w3}|ConvertTo-Json -Depth 5)
            } else { $iisJson=([ordered]@{IISInstalled=$false}|ConvertTo-Json) }
            $S.Metric="IIS: $iisInstalled | endpoints: $($surface.Count)"; $S.Pct=75

            # 5. hardening / drift
            $S.Stage='Applying / checking hardening'
            $drift=$false; $actions=@()
            if($svc){
                $reg='HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
                $tls=(Get-ItemProperty $reg -Name EnableHttp2Tls -ErrorAction SilentlyContinue).EnableHttp2Tls
                $clr=(Get-ItemProperty $reg -Name EnableHttp2Cleartext -ErrorAction SilentlyContinue).EnableHttp2Cleartext
                $drift = -not (($tls -eq 0) -and ($clr -eq 0))
                if($DoHarden){
                    if(-not(Test-Path $reg)){New-Item -Path $reg -Force|Out-Null}
                    # --- registry writes: the ACTUAL hardening, always safe, no restart needed ---
                    New-ItemProperty $reg -Name EnableHttp2Tls -Value 0 -PropertyType DWord -Force|Out-Null
                    New-ItemProperty $reg -Name EnableHttp2Cleartext -Value 0 -PropertyType DWord -Force|Out-Null
                    New-ItemProperty $reg -Name MaxFieldLength -Value 16384 -PropertyType DWord -Force|Out-Null
                    New-ItemProperty $reg -Name MaxRequestBytes -Value 32768 -PropertyType DWord -Force|Out-Null
                    $actions+='HTTP/2 disabled at HTTP.SYS (EnableHttp2Tls=0, EnableHttp2Cleartext=0); header limits clamped.'

                    # --- AppPool memory caps: only attempt if IIS is actually running ---
                    if($svc.Status -eq 'Running'){
                        try{Import-Module WebAdministration -ErrorAction SilentlyContinue
                            Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue|ForEach-Object{
                                Set-ItemProperty "IIS:\AppPools\$($_.Name)" -Name recycling.periodicRestart.privateMemory -Value 1572864 -ErrorAction SilentlyContinue
                                $actions+="AppPool '$($_.Name)': 1.5GB memory recycle cap."}}catch{$actions+="AppPool cap step skipped: $($_.Exception.Message)"}
                    } else { $actions+='AppPool memory caps skipped (W3SVC not running).' }

                    # --- STATE-AWARE RESTART: this is the v1.2.0 fix. ---
                    # A kernel HTTP.SYS restart is ONLY needed to make the change take
                    # effect on a LIVE server. If W3SVC is Stopped or Disabled there is
                    # nothing serving, HTTP.SYS will read the new values on its next
                    # start, and force-restarting the kernel driver here is exactly what
                    # wedged a box into StopPending. So: restart ONLY when IIS is running.
                    $sd = $svc.StartType
                    if($svc.Status -eq 'Running' -and $sd -ne 'Disabled'){
                        try{
                            Stop-Service W3SVC -Force -ErrorAction Stop
                            Restart-Service HTTP -Force -ErrorAction Stop
                            Start-Service W3SVC -ErrorAction Stop
                            $actions+='IIS was running: restarted HTTP.SYS + W3SVC to apply immediately.'
                        }catch{$actions+="Restart issue (registry values still applied): $($_.Exception.Message)"}
                    } else {
                        $actions+="IIS is $($svc.Status)/$sd — registry values written; NO kernel restart performed. Values apply automatically when HTTP.SYS next starts."
                    }
                    $drift=$false
                }
            } else { $actions+='No IIS/W3SVC on this box — no HTTP/2 server surface.' }
            $S.Pct=90

            # 6. write report
            $S.Stage='Writing report'
            $atRisk=@($surface|Where-Object Risk)
            $reachable=@($surface|Where-Object {$_.Scope -in @('All','LAN')})
            $report=[ordered]@{Host=$env:COMPUTERNAME;Timestamp=(Get-Date -Format 's');Version=$Version;DriftFound=$drift;RiskCount=$atRisk.Count;ReachableCount=$reachable.Count;TotalCount=$surface.Count;AllPorts=$surface;IISJson=$iisJson;Actions=$actions}
            $repPath=Join-Path $RepDir ("audit_{0}_{1}.json" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
            ($report|ConvertTo-Json -Depth 6)|Set-Content -Path $repPath -Encoding UTF8
            $S.Pct=100; $S.Metric="total: $($surface.Count) | reachable: $($reachable.Count) | at-risk: $($atRisk.Count)"
            $S.Report=[pscustomobject]$report
        } catch { $S.Error=$_.Exception.Message }
        finally { $S.Running=$false; $S.Stage='Complete.' }
    })|Out-Null
    $script:AsyncHandle = $ps.BeginInvoke()
    $script:AsyncPs = $ps
}

function Apply-Report {
    param($report)
    $GridPorts.ItemsSource=@($report.AllPorts|Select-Object Proto,LocalAddr,Port,Process,PID,Scope,Risk)
    $TxtIIS.Text=$report.IISJson
    $TxtLog.AppendText("=== " + [string]$report.Host + " " + [string]$report.Timestamp + " (drift=" + [string]$report.DriftFound + ") ===`r`n")
    foreach($a in $report.Actions){$TxtLog.AppendText("  $a`r`n")}
    $Status.Text="Audit complete. Total: $($report.AllPorts.Count)  Reachable: $($report.ReachableCount)  At-risk (web/HTTP2): $($report.RiskCount)  Drift: $($report.DriftFound)."
}

# UI timer: reads shared state ~10x/sec, updates bar/stage/elapsed, and harvests
# the finished report. This is the only thing touching UI controls.
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(100)
$timer.Add_Tick({
    $s = $script:State
    $StageTxt.Text = $s.Stage
    $Bar.Value = [math]::Min(100,[math]::Max(0,$s.Pct))
    if ($s.StartTicks -gt 0) {
        $elapsed = [TimeSpan]::FromTicks([DateTime]::UtcNow.Ticks - $s.StartTicks)
        $elapsedStr = [math]::Round($elapsed.TotalSeconds,1)
        $eta = ''
        if ($s.Pct -gt 3 -and $s.Pct -lt 100) {
            $total = $elapsed.TotalSeconds * (100/$s.Pct)
            $rem = [math]::Max(0,[math]::Round($total - $elapsed.TotalSeconds))
            $eta = "  ETA ~" + $rem + "s"
        }
        # plain concatenation: $s.Metric may contain '{' or '}' (process names etc.)
        # which would break the -f operator, so never pass it through a format string
        $MetricTxt.Text = [string]$s.Metric + "  |  elapsed " + $elapsedStr + "s" + $eta
    }
    if (-not $s.Running -and ($s.Report -or $s.Error)) {
        $timer.Stop()
        if ($s.Error) { $TxtLog.AppendText("ERROR: $($s.Error)`r`n"); $Status.Text="Audit failed." }
        elseif ($s.Report) { Apply-Report $s.Report }
        foreach ($b in @($BtnAudit,$BtnHarden,$BtnVerify,$BtnTask)) { $b.IsEnabled = $true }
        try { $script:AsyncPs.EndInvoke($script:AsyncHandle); $script:AsyncPs.Runspace.Close(); $script:AsyncPs.Dispose() } catch {}
    }
})

$BtnAudit.Add_Click({ Start-AuditAsync $false; $timer.Start() })
$BtnHarden.Add_Click({
    $r=[System.Windows.MessageBox]::Show(
        ("This writes EnableHttp2Tls=0 / EnableHttp2Cleartext=0 and clamps header limits in HTTP.SYS." + [Environment]::NewLine + [Environment]::NewLine +
         "If IIS is RUNNING, it will also set AppPool memory caps and restart W3SVC/HTTP (brief outage)." + [Environment]::NewLine +
         "If IIS is STOPPED or DISABLED, it writes the registry values only and performs NO service restart." + [Environment]::NewLine + [Environment]::NewLine +
         "Proceed?"),
        'Confirm Hardening','YesNo','Warning')
    if($r -ne 'Yes'){return}
    Start-AuditAsync $true; $timer.Start()
})

# Verify: read-only confirmation that hardening landed. Checks the four registry
# values, reports IIS service state, and — only if a site is actually serving —
# runs a live curl --http2 negotiation to confirm the server refuses HTTP/2.
function Invoke-Verify {
    $reg='HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
    $TxtLog.AppendText("=== VERIFY $(Get-Date -Format 's') ===`r`n")
    $p = Get-ItemProperty $reg -ErrorAction SilentlyContinue
    $tls=$p.EnableHttp2Tls; $clr=$p.EnableHttp2Cleartext; $mf=$p.MaxFieldLength; $mr=$p.MaxRequestBytes
    $ok = ($tls -eq 0 -and $clr -eq 0)
    $TxtLog.AppendText("  EnableHttp2Tls       = " + [string]$tls + "`r`n")
    $TxtLog.AppendText("  EnableHttp2Cleartext = " + [string]$clr + "`r`n")
    $TxtLog.AppendText("  MaxFieldLength       = " + [string]$mf + "`r`n")
    $TxtLog.AppendText("  MaxRequestBytes      = " + [string]$mr + "`r`n")
    $TxtLog.AppendText("  => HTTP/2 disabled at registry: " + $(if($ok){'YES'}else{'NO — values not set'}) + "`r`n")

    $svc = Get-Service W3SVC -ErrorAction SilentlyContinue
    $http = Get-Service HTTP -ErrorAction SilentlyContinue
    if ($svc) { $TxtLog.AppendText("  W3SVC: " + $svc.Status + "/" + $svc.StartType + "   HTTP.SYS: " + $(if($http){$http.Status}else{'?'}) + "`r`n") }
    else { $TxtLog.AppendText("  No IIS on this box — registry hardening is latent (no server surface).`r`n") }

    # live negotiation only makes sense if something is listening on 443
    $live = Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue
    if ($live) {
        try {
            $out = & curl.exe -sI --http2 https://127.0.0.1 --connect-timeout 4 -k 2>&1 | Out-String
            $neg = if ($out -match 'HTTP/2') { 'HTTP/2 (STILL NEGOTIATING H2 — restart HTTP.SYS!)' } elseif ($out -match 'HTTP/1') { 'HTTP/1.x (correct)' } else { 'inconclusive' }
            $TxtLog.AppendText("  Live curl --http2 to :443 negotiated: " + $neg + "`r`n")
        } catch { $TxtLog.AppendText("  Live curl test error: $($_.Exception.Message)`r`n") }
    } else {
        $TxtLog.AppendText("  No listener on :443 — live negotiation test skipped (sites down). Registry value is what governs HTTP/2 when sites start.`r`n")
    }
    $Status.Text = if($ok){'Verify: HTTP/2 disabled at registry. ' + $(if($live){'See log for live test.'}else{'Sites down; applies on next HTTP.SYS start.'})}else{'Verify: registry values NOT set — run Harden.'}
    # surface IIS tab so user sees state
    $TxtIIS.Text = ([ordered]@{EnableHttp2Tls=$tls;EnableHttp2Cleartext=$clr;MaxFieldLength=$mf;MaxRequestBytes=$mr;W3SVC=$(if($svc){"$($svc.Status)/$($svc.StartType)"}else{'absent'});HTTPSYS=$(if($http){$http.Status}else{'?'})}|ConvertTo-Json)
}
$BtnVerify.Add_Click({ try { Invoke-Verify } catch { $TxtLog.AppendText("Verify error: $($_.Exception.Message)`r`n") } })

$BtnTask.Add_Click({
    try { Install-HealTask; $Status.Text='Self-healing task installed.' }
    catch { $TxtLog.AppendText("Task install error: $($_.Exception.Message)`r`n") }
})
$BtnReport.Add_Click({ Start-Process explorer.exe $RepDir })

# initial passive audit, async, kicked off once the window has rendered
$win.Add_ContentRendered({ Start-AuditAsync $false; $timer.Start() })

$win.ShowDialog() | Out-Null
