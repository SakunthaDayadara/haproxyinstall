# =============================================================================
#
#    ##    ##  ######  #### ##    ##  ######      ###
#    ###   ## ##    ##  ##  ###   ## ##    ##    ## ##
#    ####  ## ##        ##  ####  ## ##         ##   ##
#    ## ## ## ##        ##  ## ## ## ##   #### ##     ##
#    ##  #### ##        ##  ##  #### ##    ##  #########
#    ##   ### ##    ##  ##  ##   ### ##    ##  ##     ##
#    ##    ##  ######  #### ##    ##  ######   ##     ##
#
#    NCINGA INTERNAL  -  Bindplane air-gapped deployment tooling
#
# =============================================================================
#  bp-agent-install-windows.ps1  -  offline Bindplane agent install for Windows log sources
# -----------------------------------------------------------------------------
#  Copyright (c) 2026 NCINGA. All rights reserved.
#
#  NCINGA INTERNAL - PROPRIETARY AND CONFIDENTIAL. This script, including its
#  design, logic, messages and accompanying documentation, is the intellectual
#  property of NCINGA. It is provided solely for use by NCINGA personnel and
#  NCINGA-authorised implementation partners on NCINGA engagements. Copying,
#  distributing, modifying, sublicensing or disclosing it, in whole or in part,
#  for any other purpose requires the prior written permission of NCINGA.
#
#  Provided "AS IS", without warranty of any kind, express or implied. NCINGA
#  accepts no liability for loss or damage arising from its use. Test it in a
#  non-production environment first and follow the change-management process of
#  the environment it is run in.
#
#  Third-party software: it installs and configures software that NCINGA does
#  not own - the Bindplane / OpenTelemetry collector (observIQ, Apache License
#  2.0) - subject to its own licence. Product names are trademarks of their
#  respective owners; no affiliation or endorsement is implied.
# =============================================================================
#  Runbook Stage 9 (Windows log sources) without internet access. The offline
#  counterpart of the vendor's install_windows.ps1: the MSI comes from the
#  gateway of this host's segment - the LIVE gateway's mirror, or the DMZ
#  gateway's repository - built by bp-live-setup.sh / bp-dmz-setup.sh:
#
#    http://<gateway>:8080/   windows/*.msi  SHA256SUMS  VERSION-INFO
#    ws://<gateway>:3001/v1/opamp          the OpAMP relay the agent connects to
#
#  Steps (each is recorded; a re-run resumes at the first unfinished one):
#    preflight  Windows version, architecture, Windows Installer, disk, reboot
#    gateway    repository reachable, chosen version present, ports 3001/4317
#    download   the MSI (resumable)
#    verify     SHA256SUMS + publisher checksum + Authenticode (observIQ, Inc.)
#    install    msiexec - fresh install, upgrade, or uninstall-first where the
#               MSI cannot upgrade in place (same version number, downgrade,
#               v2 -> v1); the MSI log is explained when msiexec fails
#    configure  manager.yaml (v1) or supervisor.yaml (v2) written by this script
#               (the MSI writes none on upgrades); file ACL: SYSTEM + Administrators
#    start      service set to Automatic, started, crash-loop detection
#    connect    stable OpAMP session to the gateway, console confirmation
#
#  The secret key is never passed to msiexec (it would land in the MSI log and
#  the process list) and never saved by this script: it is written only into
#  the collector's configuration file.
#
#  Usage (elevated PowerShell):
#    Invoke-WebRequest http://<gateway>:8080/windows/bp-agent-install-windows.ps1 -OutFile bp-agent-install-windows.ps1 -UseBasicParsing
#    powershell -ExecutionPolicy Bypass -File .\bp-agent-install-windows.ps1          (then follow the prompts)
#    powershell -ExecutionPolicy Bypass -File .\bp-agent-install-windows.ps1 -Help    (all options)
# =============================================================================

<#
.SYNOPSIS
    NCINGA internal: offline install of the Bindplane agent (v1 observiq-otel-collector or
    v2 bindplane-otel-collector) on a Windows log source, from the segment's gateway repository.

.DESCRIPTION
    Interactive by default: asks for the gateway, lists the MSI versions it holds for this host,
    asks for the secret key and labels, then downloads, verifies, installs, configures, starts and
    checks the agent. Re-running resumes at the first unfinished step. Run with -Help for options.
#>
[CmdletBinding()]
param(
    [string]$Gateway,
    [string]$Endpoint,
    [string]$CollectorVersion,
    [string]$Labels,
    [string]$Zone,
    [string]$AgentName,
    [string]$SecretFile,
    [string]$SecretKey,
    [string]$InstallDir,
    [Alias('Yes')][switch]$Unattended,
    [switch]$Reconfigure,
    [string]$From,
    [string]$Only,
    [switch]$Reinstall,
    [switch]$AllowFamilySwitch,
    [switch]$SkipSignatureCheck,
    [string]$TrustedSigner = 'O=observIQ, Inc.',
    [switch]$Status,
    [switch]$Diagnose,
    [switch]$Upgrade,
    [switch]$Uninstall,
    [switch]$Reset,
    [switch]$ListSteps,
    [switch]$PauseBetweenSteps,
    [switch]$NoColor,
    [switch]$Help,
    [switch]$ShowVersion
)

Set-StrictMode -Version 1.0     # uninitialised variables are errors (catches typos); properties of absent objects are not
$ErrorActionPreference = 'Stop'

# ---- Constants -----------------------------------------------------------------
$ScriptVersion = '1.0.0'
$ScriptName = 'bp-agent-install-windows'
$ProgramDataDir = $env:ProgramData; if (-not $ProgramDataDir) { $ProgramDataDir = 'C:\ProgramData' }
$Root = [IO.Path]::Combine($ProgramDataDir, 'NCINGA\bp-agent-install')
if ($env:BP_STATE_DIR) { $Root = $env:BP_STATE_DIR }
$ConfFile = [IO.Path]::Combine($Root, 'agent.conf')
$ProgressFile = [IO.Path]::Combine($Root, 'progress')
$VerifyFile = [IO.Path]::Combine($Root, 'verify.result')
$RestartFlag = [IO.Path]::Combine($Root, 'restart-needed')
$LogMarkFile = [IO.Path]::Combine($Root, 'log-mark')
$LogDir = [IO.Path]::Combine($Root, 'logs')
$CacheDir = [IO.Path]::Combine($Root, 'cache')
$EvidenceDir = [IO.Path]::Combine($LogDir, 'evidence')

$UpgradeCode = '{D67CCA1A-6708-4096-8BDE-5069739FB861}'   # shared by v1 and v2 MSIs (stable across renames)
$RepoPortDefault = 8080
$OpampPortDefault = 3001
$OtlpPort = 4317
$BenignLogRe = 'Capabilities is deprecated|Using legacy service\.telemetry\.resource'
$Families = @{
    v1 = @{ Pkg = 'observiq-otel-collector';  Svc = 'observiq-otel-collector';  Conf = 'manager.yaml';    Log = 'log\collector.log'
            Proc = 'observiq-otel-collector'; Label = 'v1 (observiq-otel-collector, manager.yaml)' }
    v2 = @{ Pkg = 'bindplane-otel-collector'; Svc = 'bindplane-otel-collector'; Conf = 'supervisor.yaml'; Log = 'supervisor_storage\supervisor.log'
            Proc = 'opampsupervisor';         Label = 'v2 (bindplane-otel-collector, OpAMP supervisor, supervisor.yaml)' }
}
$Steps = @('preflight', 'gateway', 'download', 'verify', 'install', 'configure', 'start', 'connect')
$StepTitle = @{
    preflight = 'Pre-flight checks on this host'
    gateway   = 'Gateway repository and ports'
    download  = 'Download the MSI from the gateway'
    verify    = 'Verify checksums and the Authenticode signature'
    install   = 'Install the collector (msiexec)'
    configure = 'Write the collector configuration'
    start     = 'Start the collector service'
    connect   = 'Verify the agent is connected through the gateway'
}
$StepRef = @{ preflight = 'Stage 9, pre-flight'; gateway = 'Stage 9.1'; download = 'Stage 9.2'; verify = 'Stage 9.2'
              install = 'Stage 9.2'; configure = 'Stage 9.3'; start = 'Stage 9.3'; connect = 'Stage 9.4' }
$ConfKeys = @('GATEWAY', 'REPO_PORT', 'OPAMP_ENDPOINT', 'BP_VERSION', 'AGENT_LABELS', 'AGENT_NAME', 'INSTALL_DIR')
# a changed answer sends these steps round again
$Depends = @{
    GATEWAY = @('gateway', 'download', 'verify', 'connect'); REPO_PORT = @('gateway', 'download', 'verify')
    OPAMP_ENDPOINT = @('gateway', 'configure', 'start', 'connect')
    BP_VERSION = @('gateway', 'download', 'verify', 'install', 'configure', 'start', 'connect')
    AGENT_LABELS = @('configure', 'start', 'connect'); AGENT_NAME = @('configure', 'start', 'connect')
    INSTALL_DIR = @('install', 'configure', 'start', 'connect')
}

# ---- Runtime state ---------------------------------------------------------------
$script:Conf = @{}
$script:OldConf = @{}
$script:Forced = @{}
$script:Secret = ''
$script:SecretSource = ''
$script:FailWhat = ''; $script:FailWhy = ''; $script:FailFix = ''
$script:LogFile = $null
$script:RunTs = (Get-Date).ToString('yyyyMMdd-HHmmss')
$script:Interactive = $false
$script:RepoSums = $null      # hashtable rel -> sha256 (the gateway's SHA256SUMS)
$script:RepoInfo = @{}        # VERSION-INFO
$script:RepoMsis = @{}        # tag -> rel of the MSI for this architecture
$script:Arch = ''
$script:CurrentStep = ''
$script:ConfigChanged = $false
$script:SigResult = ''

# =============================================================================
#  Output, logging and prompts
# =============================================================================
function Write-RunLog([string]$Text) {
    if (-not $script:LogFile) { return }
    if ($script:Secret) { $Text = $Text.Replace($script:Secret, '***REDACTED***') }
    try { [IO.File]::AppendAllText($script:LogFile, ('{0} {1}{2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Text, [Environment]::NewLine)) } catch { }
}
function Write-Line([string]$Tag, [string]$Text, [string]$Color) {
    if ($NoColor -or -not $Color) { Write-Host ("$Tag $Text") }
    else { Write-Host -NoNewline $Tag -ForegroundColor $Color; Write-Host " $Text" }
    Write-RunLog "$Tag $Text"
}
function Write-Info([string]$t) { Write-Line '[INFO]' $t 'Cyan' }
function Write-Ok([string]$t)   { Write-Line '[ OK ]' $t 'Green' }
function Write-Warn([string]$t) { Write-Line '[WARN]' $t 'Yellow' }
function Write-Err([string]$t)  { Write-Line '[FAIL]' $t 'Red' }
function Write-Hint([string]$t) { if ($NoColor) { Write-Host "       -> $t" } else { Write-Host "       -> $t" -ForegroundColor DarkGray }; Write-RunLog "HINT $t" }
function Write-Say([string]$t)  { Write-Host $t; Write-RunLog "     $t" }
function Write-Banner([string]$t) { Write-Host ''; if ($NoColor) { Write-Host $t } else { Write-Host $t -ForegroundColor White }; Write-RunLog "==== $t" }
function Write-Section([string]$t) { Write-Host ''; Write-Host "--- $t ---"; Write-RunLog "---- $t" }
function Write-Rule { Write-Host ('-' * 78) }

function Show-Brand([string]$Title) {
    $art = @(
        '   ##    ##  ######  #### ##    ##  ######      ###',
        '   ###   ## ##    ##  ##  ###   ## ##    ##    ## ##',
        '   ####  ## ##        ##  ####  ## ##         ##   ##',
        '   ## ## ## ##        ##  ## ## ## ##   #### ##     ##',
        '   ##  #### ##        ##  ##  #### ##    ##  #########',
        '   ##   ### ##    ##  ##  ##   ### ##    ##  ##     ##',
        '   ##    ##  ######  #### ##    ##  ######   ##     ##')
    Write-Host ''
    foreach ($l in $art) { if ($NoColor) { Write-Host $l } else { Write-Host $l -ForegroundColor Cyan } }
    Write-Host ''
    Write-Host '   NCINGA internal implementation tool - Bindplane air-gapped deployment'
    Write-Host "   $Title"
    Write-Host '   (c) 2026 NCINGA. All rights reserved. Proprietary and confidential: for use on NCINGA'
    Write-Host '   engagements by authorised personnel only. Provided as is, without warranty (see the header).'
    Write-RunLog "NCINGA $ScriptName v$ScriptVersion - $Title"
}

function Set-Fail([string]$What, [string]$Why = '', [string]$Fix = '') {
    $script:FailWhat = $What; $script:FailWhy = $Why; $script:FailFix = $Fix
}
function Write-Block([string]$Label, [string]$Text) {
    if (-not $Text) { return }
    $first = $true
    foreach ($line in ($Text -split "`n")) {
        if ($first) { Write-Host ('  {0,-14} {1}' -f $Label, $line); $first = $false }
        else { Write-Host ('  {0,-14} {1}' -f '', $line) }
    }
}
function Show-Failure([string]$Step) {
    Write-Host ''
    Write-Rule
    if ($NoColor) { Write-Host ("  STEP FAILED: {0}  (runbook {1})" -f $StepTitle[$Step], $StepRef[$Step]) }
    else { Write-Host ("  STEP FAILED: {0}  (runbook {1})" -f $StepTitle[$Step], $StepRef[$Step]) -ForegroundColor Red }
    Write-Rule
    $what = $script:FailWhat; if (-not $what) { $what = 'The step returned an error (see the output above).' }
    Write-Block 'What happened' $what
    Write-Block 'Likely cause' $script:FailWhy
    Write-Block 'How to fix' $script:FailFix
    Write-Block 'Full log' $script:LogFile
    Write-Rule
    Write-RunLog "STEP FAILED $Step | what: $($script:FailWhat) | why: $($script:FailWhy) | fix: $($script:FailFix)"
}
function Get-Masked([string]$s) { if ($s.Length -gt 10) { return $s.Substring(0, 4) + '****' + $s.Substring($s.Length - 4) } return '****' }
function Format-Size([double]$b) {
    $u = @('B', 'KB', 'MB', 'GB', 'TB'); $i = 0
    while ($b -ge 1024 -and $i -lt 4) { $b = $b / 1024; $i++ }
    if ($i -eq 0) { return ('{0} {1}' -f [int]$b, $u[$i]) } return ('{0:N1} {1}' -f $b, $u[$i])
}

# Read-Answer PROMPT DEFAULT VALIDATOR -> the answer ($null when it cannot be obtained)
#   VALIDATOR: scriptblock returning an error message, or nothing when the value is valid
function Read-Answer([string]$Prompt, [string]$Default = '', [scriptblock]$Validator = $null) {
    while ($true) {
        if (-not $script:Interactive) {
            $ans = $Default
            if ($ans) { Write-Host ("  {0}: {1} (default)" -f $Prompt, $ans) } else { Write-Host ("  {0}: <none>" -f $Prompt) }
        }
        else {
            if ($Default) { $ans = Read-Host ("  {0} [{1}]" -f $Prompt, $Default) } else { $ans = Read-Host ("  {0}" -f $Prompt) }
            $ans = "$ans".Trim(); if (-not $ans) { $ans = $Default }
        }
        $msg = $null
        if ($Validator) { $msg = & $Validator $ans }
        if ($msg) {
            Write-Warn "  $msg"
            if (-not $script:Interactive) { return $null }
            continue
        }
        Write-RunLog "ANSWER $Prompt = $ans"
        return $ans
    }
}
function Read-YesNo([string]$Prompt, [string]$Default = 'n') {
    if (-not $script:Interactive) { Write-Host ("  {0} ({1}, default)" -f $Prompt, $Default); Write-RunLog "ANSWER $Prompt = $Default (default)"; return ($Default -eq 'y') }
    while ($true) {
        $hint = 'y/N'; if ($Default -eq 'y') { $hint = 'Y/n' }
        $a = "$(Read-Host ("  {0} [{1}]" -f $Prompt, $hint))".Trim().ToLower()
        if (-not $a) { $a = $Default }
        if ($a -in @('y', 'yes')) { Write-RunLog "ANSWER $Prompt = yes"; return $true }
        if ($a -in @('n', 'no')) { Write-RunLog "ANSWER $Prompt = no"; return $false }
        Write-Host '  Please answer y or n.'
    }
}
function Read-Choice([string]$Prompt, [string]$Allowed, [string]$Default = '') {
    if (-not $script:Interactive) { return 'q' }
    while ($true) {
        $c = "$(Read-Host $Prompt)".Trim().ToLower()
        if (-not $c) { $c = $Default }
        if ($c) { $c = $c.Substring(0, 1) }
        if ($c -and $Allowed.Contains($c)) { Write-RunLog "MENU $c"; return $c }
    }
}
function ConvertFrom-Secure([Security.SecureString]$s) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Read-SecretKey([string]$Prompt) {
    if (-not $script:Interactive) { return $null }
    while ($true) {
        $a = (ConvertFrom-Secure (Read-Host "  $Prompt" -AsSecureString)).Trim()
        if (-not $a) { Write-Warn '  The secret key cannot be empty (an empty key fails exactly like a wrong one).'; continue }
        $b = (ConvertFrom-Secure (Read-Host '  Re-enter to confirm' -AsSecureString)).Trim()
        if ($a -ne $b) { Write-Warn '  The two entries did not match - try again.'; continue }
        Write-RunLog "ANSWER secret key entered (length $($a.Length))"
        return $a
    }
}

# --- validators: return an error message, or nothing when valid -------------------
function Test-IPv4([string]$s) {
    if ($s -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $false }
    foreach ($o in 1..4) { if ([int]$Matches[$o] -gt 255) { return $false } }
    return $true
}
$VHost = {
    param($v)
    $h = $v
    if ($v -match '^(.+):(\d{1,5})$') { $h = $Matches[1] }
    elseif ($v -match ':') { return 'The port after '':'' must be a number, e.g. 10.20.30.40:8080' }
    if (Test-IPv4 $h) { return }
    if ($h -match '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') { return }
    return 'Enter the gateway''s IPv4 address (e.g. 10.20.30.40) or host name.'
}
$VEndpoint = { param($v) if ($v -notmatch '^wss?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s"'']*)?$') { return "Use the form ws://<gateway>:$OpampPortDefault/v1/opamp" } }
$VLabelValue = { param($v) if (-not $v) { return 'A value is required.' }; if ($v -notmatch '^[A-Za-z0-9_.-]+$') { return 'Letters, digits, ''.'', ''_'' or ''-'' only (no spaces, commas or ''='').' } }
$VLabels = { param($v) if ($v -notmatch '^[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+)*$') { return 'Use key=value pairs separated by commas, e.g. site=primary,segment=prod-live,zone=web,os=windows,role=source' } }
$VAgentName = { param($v) if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') { return 'Letters, digits, ''.'', ''_'' or ''-'' only (max 63).' } }
$VVersion = { param($v) if ($v -notmatch '^v?\d+\.\d+\.\d+([-.][0-9A-Za-z.]+)?$') { return "'$v' is not a release tag. Use the form v1.109.0" } }

# =============================================================================
#  State: answers (agent.conf) and step progress (progress)
# =============================================================================
function Initialize-StateDir {
    foreach ($d in @($Root, $LogDir, $CacheDir, $EvidenceDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null } }
    # the state folder holds logs and answers: SYSTEM and Administrators only
    & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
}
function Save-Config {
    $lines = @("# $ScriptName answers - written $((Get-Date).ToString('s')). SYSTEM/Administrators only.",
               '# The Bindplane secret key is NOT stored here (it is only in the collector''s config file).')
    foreach ($k in $ConfKeys) { $lines += ('{0}={1}' -f $k, $script:Conf[$k]) }
    $tmp = "$ConfFile.tmp"
    [IO.File]::WriteAllLines($tmp, $lines)
    Move-Item -Force $tmp $ConfFile
}
function Read-Config {
    $script:Conf = @{}
    foreach ($k in $ConfKeys) { $script:Conf[$k] = '' }
    if (-not (Test-Path $ConfFile)) { return $false }
    foreach ($l in [IO.File]::ReadAllLines($ConfFile)) {
        if ($l -match '^\s*#' -or $l -notmatch '=') { continue }
        $i = $l.IndexOf('='); $k = $l.Substring(0, $i).Trim(); $v = $l.Substring($i + 1)
        if ($ConfKeys -contains $k) { $script:Conf[$k] = $v }
    }
    return $true
}
function Get-StepState([string]$Step) {
    if (-not (Test-Path $ProgressFile)) { return '' }
    $st = ''
    foreach ($l in [IO.File]::ReadAllLines($ProgressFile)) { $p = $l -split '\|'; if ($p[0] -eq $Step) { $st = $p[1] } }
    return $st
}
function Set-StepState([string]$Step, [string]$State) {
    $lines = @()
    if (Test-Path $ProgressFile) { $lines = @([IO.File]::ReadAllLines($ProgressFile) | Where-Object { ($_ -split '\|')[0] -ne $Step }) }
    $lines += ('{0}|{1}|{2}' -f $Step, $State, (Get-Date).ToString('s'))
    $tmp = "$ProgressFile.tmp"
    [IO.File]::WriteAllLines($tmp, [string[]]$lines)
    Move-Item -Force $tmp $ProgressFile
    Write-RunLog "STATE $Step=$State"
}
function Get-StatusWord([string]$s) {
    switch ($s) { 'done' { 'done' } 'skipped' { 'SKIPPED' } 'failed' { 'FAILED' } 'running' { 'INTERRUPTED' } 'interrupted' { 'INTERRUPTED' } default { 'pending' } }
}
function Show-Progress {
    $i = 0
    foreach ($s in $Steps) { $i++; Write-Host ('   {0,2}. {1,-52} {2}' -f $i, $StepTitle[$s], (Get-StatusWord (Get-StepState $s))) }
}

# =============================================================================
#  Families, versions, installed product
# =============================================================================
function Get-FamilyOfTag([string]$t) { if ($t -match '^v?([2-9]|[1-9]\d+)\.') { return 'v2' } return 'v1' }
function Get-FamilyOfPkg([string]$p) { if ($p -eq 'bindplane-otel-collector') { return 'v2' } return 'v1' }
function Test-PreRelease([string]$t) { return ($t -match '-') }
# Compare-Tag A B -> -1 / 0 / 1 (v1.108.1 < v1.109.0; v2.0.1-beta.5 < v2.0.1-beta.6 < v2.0.1)
function Compare-Tag([string]$a, [string]$b) {
    $pa = $a.TrimStart('v') -split '-', 2; $pb = $b.TrimStart('v') -split '-', 2
    $c = ([version]$pa[0]).CompareTo([version]$pb[0]); if ($c -ne 0) { return [Math]::Sign($c) }
    $ra = ''; $rb = ''; if ($pa.Count -gt 1) { $ra = $pa[1] }; if ($pb.Count -gt 1) { $rb = $pb[1] }
    if ($ra -eq $rb) { return 0 }; if (-not $ra) { return 1 }; if (-not $rb) { return -1 }
    $xa = $ra -split '\.'; $xb = $rb -split '\.'
    for ($i = 0; $i -lt [Math]::Max($xa.Count, $xb.Count); $i++) {
        if ($i -ge $xa.Count) { return -1 }; if ($i -ge $xb.Count) { return 1 }
        if ($xa[$i] -match '^\d+$' -and $xb[$i] -match '^\d+$') { $c = ([long]$xa[$i]).CompareTo([long]$xb[$i]) } else { $c = [string]::CompareOrdinal($xa[$i], $xb[$i]) }
        if ($c -ne 0) { return [Math]::Sign($c) }
    }
    return 0
}
# tags: v1 newest first, then v2 newest first
function Get-OrderedTags([string[]]$tags) {
    $out = @()
    foreach ($fam in @('v1', 'v2')) {
        $f = @($tags | Where-Object { $_ -and (Get-FamilyOfTag $_) -eq $fam })
        for ($i = 0; $i -lt $f.Count; $i++) { for ($j = $i + 1; $j -lt $f.Count; $j++) { if ((Compare-Tag $f[$j] $f[$i]) -gt 0) { $t = $f[$i]; $f[$i] = $f[$j]; $f[$j] = $t } } }
        $out += $f
    }
    return , $out
}
function Get-ArchName {
    $a = $env:PROCESSOR_ARCHITEW6432; if (-not $a) { $a = $env:PROCESSOR_ARCHITECTURE }
    switch ($a) { 'AMD64' { return 'amd64' } 'ARM64' { return 'arm64' } default { return "unsupported($a)" } }
}
function Get-DefaultInstallDir {
    $pf = $env:ProgramW6432; if (-not $pf) { $pf = $env:ProgramFiles }
    return (Join-Path $pf 'observIQ OpenTelemetry Collector')
}

# COM helpers (Windows Installer)
function Invoke-Com($obj, [string]$member, [string]$kind, [object[]]$argv) {
    return $obj.GetType().InvokeMember($member, [Reflection.BindingFlags]$kind, $null, $obj, $argv)
}
function Get-MsiInfo([string]$Path) {
    $inst = New-Object -ComObject WindowsInstaller.Installer
    $db = $null; $view = $null; $h = @{}
    try {
        $db = Invoke-Com $inst 'OpenDatabase' 'InvokeMethod' @($Path, 0)
        $view = Invoke-Com $db 'OpenView' 'InvokeMethod' @("SELECT ``Property``, ``Value`` FROM ``Property``")
        Invoke-Com $view 'Execute' 'InvokeMethod' $null | Out-Null
        while ($true) {
            $rec = Invoke-Com $view 'Fetch' 'InvokeMethod' $null
            if (-not $rec) { break }
            $h[(Invoke-Com $rec 'StringData' 'GetProperty' @(1))] = (Invoke-Com $rec 'StringData' 'GetProperty' @(2))
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
        }
        Invoke-Com $view 'Close' 'InvokeMethod' $null | Out-Null
    }
    finally {
        foreach ($o in @($view, $db, $inst)) { if ($o) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($o) } }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    return $h
}
# the installed collector (either family), found through the shared UpgradeCode
function Get-Installed {
    $codes = @()
    try { $inst = New-Object -ComObject WindowsInstaller.Installer; foreach ($c in $inst.RelatedProducts($UpgradeCode)) { if ($c) { $codes += $c } } }
    catch { return $null }
    if ($codes.Count -eq 0) { return $null }
    $code = $codes[0]
    $name = ''; $ver = ''; $loc = ''
    try { $name = $inst.ProductInfo($code, 'InstalledProductName') } catch { }
    try { $ver = $inst.ProductInfo($code, 'VersionString') } catch { }
    try { $loc = $inst.ProductInfo($code, 'InstallLocation') } catch { }
    $fam = 'v1'; if ($name -match 'BindPlane|BDOT') { $fam = 'v2' }
    $dir = Get-ServiceDir $Families[$fam].Svc
    if (-not $dir -and $loc) { $dir = $loc }
    if (-not $dir) { $dir = Get-DefaultInstallDir }
    $tag = ''
    $vf = Join-Path $dir 'VERSION.txt'
    if (Test-Path $vf) { $tag = "$((Get-Content $vf -TotalCount 1))".Trim() }
    if (-not $tag -and $ver) { $tag = "v$ver" }
    return [pscustomobject]@{ Code = $code; Name = $name; ProductVersion = $ver; Tag = $tag; Family = $fam; Dir = $dir; Count = $codes.Count; AllCodes = $codes }
}
# folder of a service's executable (from its ImagePath)
function Get-ServiceDir([string]$svc) {
    try {
        $ip = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name ImagePath -ErrorAction Stop).ImagePath
        if ($ip -match '^"([^"]+\\)[^\\"]+"') { return $Matches[1].TrimEnd('\') }
        if ($ip -match '^([^"]+\\)[^\\ ]+\.exe') { return $Matches[1].TrimEnd('\') }
    } catch { }
    return $null
}
function Get-InstalledSummary {
    $i = Get-Installed
    if (-not $i) { return 'none' }
    return ('{0} {1} ({2})' -f $i.Family, $i.Tag, $Families[$i.Family].Pkg)
}
function Get-CollectorDir { if ($script:Conf['INSTALL_DIR']) { return $script:Conf['INSTALL_DIR'] }; return (Get-DefaultInstallDir) }
function Get-ActiveFamily { if ($script:Conf['BP_VERSION']) { return (Get-FamilyOfTag $script:Conf['BP_VERSION']) }; $i = Get-Installed; if ($i) { return $i.Family }; return 'v1' }
function Get-ConfPath([string]$fam = (Get-ActiveFamily)) { return (Join-Path (Get-CollectorDir) $Families[$fam].Conf) }
function Get-LogPath([string]$fam = (Get-ActiveFamily)) { return (Join-Path (Get-CollectorDir) $Families[$fam].Log) }

# read a value from a collector config (v1 manager.yaml / v2 supervisor.yaml)
function Get-ConfValue([string]$Key, [string]$fam = (Get-ActiveFamily)) {
    $f = Get-ConfPath $fam
    if ($fam -eq 'v2' -and $Key -eq 'agent_id') {
        $p = Join-Path (Get-CollectorDir) 'supervisor_storage\persistent_state.yaml'
        if (Test-Path $p) { foreach ($l in Get-Content $p) { if ($l -match '^instance_id:\s*(\S+)') { return $Matches[1].Trim('"', "'") } } }
        return ''
    }
    if (-not (Test-Path $f)) { return '' }
    $text = Get-Content $f
    foreach ($l in $text) {
        if ($fam -eq 'v2') {
            switch ($Key) {
                'endpoint'   { if ($l -match '^\s+endpoint:\s*["'']?([^"''\s]+)') { return $Matches[1] } }
                'secret_key' { if ($l -match 'Authorization:\s*["'']?Secret-Key\s+([^"''\s]+)') { return $Matches[1] } }
                'labels'     { if ($l -match 'service\.labels:\s*["'']?([^"'']*)') { return $Matches[1].Trim() } }
            }
        }
        elseif ($l -match ('^' + [regex]::Escape($Key) + ':\s*(.*)$')) { return $Matches[1].Trim().Trim('"', "'").Trim() }
    }
    return ''
}

# =============================================================================
#  The gateway: repository (http://GATEWAY:REPO_PORT/) and relay (OPAMP_ENDPOINT)
# =============================================================================
function Get-RepoUrl([string]$rel) { return ('http://{0}:{1}/{2}' -f $script:Conf['GATEWAY'], $script:Conf['REPO_PORT'], $rel.TrimStart('/')) }
function Get-OpampHost { $h = $script:Conf['OPAMP_ENDPOINT'] -replace '^wss?://', ''; $h = ($h -split '/')[0]; return ($h -split ':')[0] }
function Get-OpampPort {
    $h = $script:Conf['OPAMP_ENDPOINT'] -replace '^wss?://', ''; $h = ($h -split '/')[0]
    if ($h -match ':(\d+)$') { return [int]$Matches[1] }
    if ($script:Conf['OPAMP_ENDPOINT'] -like 'wss:*') { return 443 } return 80
}
function Resolve-IPv4([string]$h) {
    if (Test-IPv4 $h) { return $h }
    try { foreach ($a in [Net.Dns]::GetHostAddresses($h)) { if ($a.AddressFamily -eq 'InterNetwork') { return $a.ToString() } } } catch { }
    return $null
}

# Test-Tcp HOST PORT -> open | refused | timeout | unreachable | noname | error
function Test-Tcp([string]$h, [int]$p, [int]$ms = 6000) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($h, $p, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms)) { return 'timeout' }
        $c.EndConnect($iar); return 'open'
    }
    catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        if ($e -is [Net.Sockets.SocketException]) {
            switch ([string]$e.SocketErrorCode) {
                'ConnectionRefused' { return 'refused' } 'HostUnreachable' { return 'unreachable' } 'NetworkUnreachable' { return 'unreachable' }
                'HostNotFound' { return 'noname' } 'NoData' { return 'noname' } 'TryAgain' { return 'noname' } 'TimedOut' { return 'timeout' }
            }
        }
        return 'error'
    }
    finally { $c.Close() }
}
# Show-Tcp HOST PORT STATE PURPOSE -> result line + hint; $true when open
function Show-Tcp([string]$h, [int]$p, [string]$st, [string]$what) {
    switch ($st) {
        'open'        { Write-Ok "TCP ${h}:$p reachable ($what)"; return $true }
        'timeout'     { Write-Err "TCP ${h}:$p timed out ($what)"; Write-Hint "A firewall silently drops this host -> $h tcp/$p (Windows Firewall outbound policy, or the network firewall rule for this log source is missing). Raise it with the network team." }
        'refused'     { Write-Err "TCP ${h}:$p refused ($what)"; Write-Hint "The gateway answered but nothing listens on port ${p}: the service there is stopped. On the gateway: bp-live-setup.sh --diagnose (LIVE) or bp-dmz-setup.sh --diagnose (DMZ)." }
        'unreachable' { Write-Err "TCP ${h}:$p unreachable ($what)"; Write-Hint "No route from this host to ${h}: wrong address, or a routing problem (route print / tracert -d $h)." }
        'noname'      { Write-Err "$h does not resolve ($what)"; Write-Hint 'Use the gateway''s IP address - isolated segments usually have no DNS for it.' }
        default       { Write-Err "TCP ${h}:$p could not be tested ($what)"; Write-Hint "Test-NetConnection $h -Port $p" }
    }
    return $false
}

# Invoke-RepoGet REL OUTFILE [resume] -> @{ Ok; Code; Status; Error } (resumable; proxy bypassed)
function Invoke-RepoGet([string]$rel, [string]$out, [switch]$Resume, [switch]$Progress) {
    $url = Get-RepoUrl $rel
    $res = @{ Ok = $false; Code = 0; Status = ''; Error = ''; Url = $url }
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $have = 0; if ($Resume -and (Test-Path $out)) { $have = (Get-Item $out).Length }
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Proxy = $null; $req.Timeout = 15000; $req.ReadWriteTimeout = 60000; $req.KeepAlive = $false
        if ($have -gt 0) { $req.AddRange([long]$have) }
        $resp = $null; $fs = $null; $stream = $null
        try {
            $resp = $req.GetResponse()
            $res.Code = [int]$resp.StatusCode
            $mode = [IO.FileMode]::Create
            if ($have -gt 0 -and $res.Code -eq 206) { $mode = [IO.FileMode]::Append } else { $have = 0 }
            $total = $resp.ContentLength; if ($total -gt 0) { $total += $have }
            $fs = New-Object IO.FileStream($out, $mode, [IO.FileAccess]::Write)
            $stream = $resp.GetResponseStream()
            $buf = New-Object byte[] 262144; $done = $have; $last = [DateTime]::Now; $shown = $false
            while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
                $fs.Write($buf, 0, $n); $done += $n
                if ($Progress -and ([DateTime]::Now - $last).TotalSeconds -ge 1) {
                    $last = [DateTime]::Now; $shown = $true
                    if ($total -gt 0) { Write-Host -NoNewline ("`r      downloading {0} ... {1} of {2} ({3}%)   " -f (Split-Path $rel -Leaf), (Format-Size $done), (Format-Size $total), [int]($done * 100 / $total)) }
                    else { Write-Host -NoNewline ("`r      downloading {0} ... {1}   " -f (Split-Path $rel -Leaf), (Format-Size $done)) }
                }
            }
            if ($Progress -and $shown) { Write-Host -NoNewline ("`r" + (' ' * 90) + "`r") }
            $res.Ok = $true
            Write-RunLog "GET $url -> $($res.Code) ($done bytes)"
            return $res
        }
        catch [Net.WebException] {
            $ex = $_.Exception
            $res.Status = [string]$ex.Status; $res.Error = $ex.Message
            if ($ex.Response) { $res.Code = [int]([Net.HttpWebResponse]$ex.Response).StatusCode }
            Write-RunLog "GET $url -> status=$($res.Status) code=$($res.Code) $($res.Error)"
            if ($res.Code -eq 416 -and $attempt -eq 1) { if ($fs) { $fs.Dispose(); $fs = $null }; Remove-Item -Force $out -ErrorAction SilentlyContinue; continue }
            return $res
        }
        catch {
            $res.Status = 'Error'; $res.Error = $_.Exception.Message
            Write-RunLog "GET $url -> $($res.Error)"
            return $res
        }
        finally {
            if ($stream) { $stream.Dispose() }; if ($fs) { $fs.Dispose() }; if ($resp) { $resp.Close() }
        }
    }
    return $res
}
# Set-RepoFail RESULT WHAT -> Set-Fail with the reason a request to the gateway failed
function Set-RepoFail($r, [string]$what) {
    $gw = $script:Conf['GATEWAY']; $port = $script:Conf['REPO_PORT']; $url = $r.Url
    # classify: .NET Framework and .NET (Core) report connection failures differently - test the port when unsure
    $kind = 'other'
    switch ($r.Status) {
        'ProtocolError' { $kind = 'http' }
        'NameResolutionFailure' { $kind = 'noname' }
        'Timeout' { $kind = 'timeout' }
        { $_ -in @('ReceiveFailure', 'ConnectionClosed', 'KeepAliveFailure', 'PipelineFailure', 'SendFailure') } { $kind = 'cut' }
    }
    if ($kind -eq 'other') {
        $st = Test-Tcp $gw ([int]$port)
        if ($st -ne 'open') { $kind = $st } elseif ($r.Status -eq 'ConnectFailure') { $kind = 'error' }
    }
    switch ($kind) {
        'refused' { Set-Fail "The gateway $gw refused the connection on port $port." 'nginx (the repository) is not running on the gateway, or listens on another port.' "On the gateway: systemctl status nginx ; ss -lntp | grep :$port`nIf the repository uses another port, re-run with -Reconfigure and enter <gateway>:<port>." }
        { $_ -in @('timeout', 'unreachable', 'error') } { Set-Fail "Could not connect to the gateway repository ${gw}:$port ($kind)." "The firewall rule from this host to the gateway on tcp/$port is missing (a silent drop shows as a time-out), or the address is wrong." "Test: Test-NetConnection $gw -Port $port`nThe address is the gateway of THIS segment (LIVE log sources: the LIVE gateway). Raise a missing rule with the network team; change the address with -Reconfigure." }
        'noname' { Set-Fail "$gw does not resolve." 'There is no DNS for that name on this segment.' 'Use the gateway''s IP address: re-run with -Reconfigure.' }
        'cut' { Set-Fail "The connection to the gateway was cut during the transfer ($($r.Status))." 'An inline device reset the connection, or the gateway restarted.' 'Retry - downloads resume where they stopped.' }
        'http' {
            switch ($r.Code) {
                { $_ -eq 404 -and $what -eq 'SHA256SUMS' } { Set-Fail "${gw}:$port answers, but has no SHA256SUMS (HTTP 404) - it is not the gateway repository." 'A wrong port (the repository is on :8080; :3001 is the OpAMP relay), or another web server.' 'Re-run with -Reconfigure and enter the repository address (<gateway> or <gateway>:<port>).' }
                404 { Set-Fail "The gateway has no $what (HTTP 404)." 'The gateway''s repository does not hold this file: the version is not staged there, or the LIVE mirror is not in sync with the DMZ repository.' "On the DMZ host: bp-dmz-update-repo.sh --status (stage the version if missing)`nOn the LIVE gateway: bp-live-setup.sh --sync-mirror`nThen retry." }
                403 { Set-Fail "The gateway refused $what (HTTP 403)." 'File permissions in the repository on the gateway (nginx cannot read it).' 'On the gateway: chmod -R a+rX /srv/bindplane' }
                default { Set-Fail "The gateway answered HTTP $($r.Code) for $what." 'Unexpected response from the repository web server.' "Open $url in a browser on this host; on the gateway: tail /var/log/nginx/bindplane-repo.error.log" }
            }
        }
        default {
            if ($r.Error -eq 'not a SHA256SUMS file') { Set-Fail "$url did not return a SHA256SUMS file." 'This address/port is not the NCINGA Bindplane repository (another web service answered).' 'Check the gateway address and port (-Reconfigure).' }
            else { Set-Fail "The request to $url failed: $($r.Error)" "Port $port on $gw is open, but the HTTP request failed ($($r.Status)) - another service (not the repository web server) may listen there." "Open $url in a browser on this host; check the gateway address and port (-Reconfigure)." }
        }
    }
}

# Import-RepoIndex - the gateway's SHA256SUMS (what it serves) and VERSION-INFO; RepoMsis = tag -> MSI for this arch
function Import-RepoIndex {
    $f = Join-Path $CacheDir 'repo.SHA256SUMS'
    $r = Invoke-RepoGet 'SHA256SUMS' $f
    if (-not $r.Ok) { return $r }
    $sums = @{}
    foreach ($l in [IO.File]::ReadAllLines($f)) { if ($l -match '^([0-9a-f]{64})\s+\*?(\S.*)$') { $sums[$Matches[2].Trim()] = $Matches[1] } }
    if ($sums.Count -eq 0) { $r.Ok = $false; $r.Status = 'ProtocolError'; $r.Code = 0; $r.Error = 'not a SHA256SUMS file'; return $r }
    $script:RepoSums = $sums
    $script:RepoInfo = @{}
    $fi = Join-Path $CacheDir 'repo.VERSION-INFO'
    if ((Invoke-RepoGet 'VERSION-INFO' $fi).Ok) {
        foreach ($l in [IO.File]::ReadAllLines($fi)) { $i = $l.IndexOf('='); if ($i -gt 0) { $script:RepoInfo[$l.Substring(0, $i)] = $l.Substring($i + 1) } }
    }
    # windows/<package>[-arm64].msi = that family's current version; windows/<package>[-arm64]_<tag>.msi = others
    $suffix = ''; if ($script:Arch -eq 'arm64') { $suffix = '-arm64' }
    $msis = @{}
    foreach ($rel in $sums.Keys) {
        if ($rel -match ('^windows/(observiq-otel-collector|bindplane-otel-collector)' + [regex]::Escape($suffix) + '_(v\d[^/]*)\.msi$')) {
            $pkg = $Matches[1]; $tag = $Matches[2]
            if ((Get-FamilyOfPkg $pkg) -eq (Get-FamilyOfTag $tag)) { $msis[$tag] = $rel }
        }
    }
    foreach ($fam in @('v1', 'v2')) {
        $rel = 'windows/' + $Families[$fam].Pkg + $suffix + '.msi'
        $cur = $script:RepoInfo["current_$fam"]
        if (-not $cur -and $script:RepoInfo['current_package'] -eq $Families[$fam].Pkg) { $cur = $script:RepoInfo['current_collector_version'] }
        if ($sums.ContainsKey($rel) -and $cur -and -not $msis.ContainsKey($cur)) { $msis[$cur] = $rel }
    }
    $script:RepoMsis = $msis
    return $r
}
function Get-RepoVersions { return (Get-OrderedTags @($script:RepoMsis.Keys)) }   # callers wrap it in @()
function Get-RepoSum([string]$rel) { if ($script:RepoSums -and $script:RepoSums.ContainsKey($rel)) { return $script:RepoSums[$rel] }; return '' }
function Get-Sha256([string]$path) {
    $s = [Security.Cryptography.SHA256]::Create(); $f = [IO.File]::OpenRead($path)
    try { return (-join ($s.ComputeHash($f) | ForEach-Object { $_.ToString('x2') })) } finally { $f.Dispose(); $s.Dispose() }
}
function Get-CacheFile([string]$tag) {
    $suffix = ''; if ($script:Arch -eq 'arm64') { $suffix = '-arm64' }
    return (Join-Path $CacheDir ('{0}{1}_{2}.msi' -f $Families[(Get-FamilyOfTag $tag)].Pkg, $suffix, $tag))
}
function Get-AssetName([string]$tag) { $suffix = ''; if ($script:Arch -eq 'arm64') { $suffix = '-arm64' }; return ($Families[(Get-FamilyOfTag $tag)].Pkg + $suffix + '.msi') }
function Get-PubSumsRel([string]$tag) { return ('packages/{0}-{1}-SHA256SUMS' -f $Families[(Get-FamilyOfTag $tag)].Pkg, $tag) }
function Confirm-Index { if ($script:RepoSums) { return $true }; $r = Import-RepoIndex; if ($r.Ok) { return $true }; Set-RepoFail $r 'SHA256SUMS'; return $false }

# =============================================================================
#  Checks (pre-flight and -Diagnose); each prints its own line
# =============================================================================
$script:ChkFails = 0; $script:ChkWarns = 0
function Add-Ok([string]$t) { Write-Ok $t }
function Add-Warn([string]$t) { Write-Warn $t; $script:ChkWarns++ }
function Add-Fail([string]$t) { Write-Err $t; $script:ChkFails++ }

function Test-Platform {
    $v = [Environment]::OSVersion.Version
    $cap = ''
    try { $cap = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { try { $cap = (Get-WmiObject Win32_OperatingSystem).Caption } catch { $cap = 'Windows' } }
    if ($v -ge [version]'6.3') { Add-Ok "OS: $cap ($v)" }
    else { Add-Fail "OS: $cap ($v) - Windows Server 2012 R2 / Windows 8.1 or later is required"; Write-Hint 'The collector MSI only writes its configuration on Windows 6.3+.' }
    switch ($script:Arch) {
        'amd64' { Add-Ok 'Architecture: x64 (amd64)' }
        'arm64' { Add-Ok 'Architecture: ARM64' }
        default { Add-Fail "Architecture $($script:Arch) is not supported (x64 and ARM64 only)" }
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Add-Warn 'This is 32-bit PowerShell on 64-bit Windows - run the 64-bit one (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)'
    }
    Add-Ok "PowerShell $($PSVersionTable.PSVersion)"
}
function Test-WindowsInstaller {
    try {
        $s = Get-Service msiserver -ErrorAction Stop
        $mode = ''; try { $mode = [string](Get-CimInstance Win32_Service -Filter "Name='msiserver'" -ErrorAction Stop).StartMode } catch { }
        if ($mode -eq 'Disabled') { Add-Fail 'The Windows Installer service (msiserver) is disabled'; Write-Hint 'Set-Service msiserver -StartupType Manual (or ask the platform team - a policy may disable it)' }
        else { Add-Ok "Windows Installer service available ($($s.Status))" }
    } catch { Add-Fail 'The Windows Installer service (msiserver) was not found' }
}
function Test-PendingReboot {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $pending = $false
    foreach ($k in $keys) { if (Test-Path $k) { $pending = $true } }
    try { if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) { $pending = $true } } catch { }
    if ($pending) { Add-Warn 'A reboot is pending on this host - msiexec may fail (1603) or ask for a reboot (3010)'; Write-Hint 'Reboot first if the change window allows it.' }
    else { Add-Ok 'No reboot pending' }
}
function Test-Space([string]$path, [int]$minMb, [string]$label) {
    $drive = [IO.Path]::GetPathRoot($path)
    try {
        $d = New-Object IO.DriveInfo($drive)
        if ($d.AvailableFreeSpace -lt $minMb * 1MB) { Add-Fail "Only $(Format-Size $d.AvailableFreeSpace) free on $drive for $label - need ~$minMb MB" }
        else { Add-Ok "$(Format-Size $d.AvailableFreeSpace) free on $drive for $label" }
    } catch { Add-Warn "Could not read the free space of $drive" }
}
function Test-TimeSync {
    $out = ''
    try { $out = (& w32tm.exe /query /status 2>&1) -join "`n" } catch { }
    if ($out -match 'Source:\s*(.+)') {
        $src = $Matches[1].Trim()
        if ($src -match 'Local CMOS Clock|Free-running') { Add-Warn "The clock is not synchronised (source: $src) - TLS and OpAMP sessions fail on clock skew"; Write-Hint 'w32tm /query /status ; check the domain time hierarchy' }
        else { Add-Ok "Clock synchronised from $src" }
    } else { Add-Warn 'Could not read the time-sync state (w32tm /query /status)' }
}
function Test-Existing {
    $i = Get-Installed
    if (-not $i) { Add-Ok 'No collector installed yet'; return }
    $svc = Get-Service $Families[$i.Family].Svc -ErrorAction SilentlyContinue
    $st = 'not registered'; if ($svc) { $st = [string]$svc.Status }
    Add-Ok ("Installed: {0} {1} - '{2}' in {3} (service: {4})" -f $Families[$i.Family].Label, $i.Tag, $i.Name, $i.Dir, $st)
    if ($i.Count -gt 1) { Add-Warn "$($i.Count) collector products are registered (one upgrade code) - the install step removes the extras"; Write-Hint ($i.AllCodes -join ', ') }
}

# =============================================================================
#  Secret key: never saved by this script, never passed to msiexec
# =============================================================================
function Confirm-Secret {
    if ($script:Secret) { return $true }
    $fam = Get-ActiveFamily; $other = 'v1'; if ($fam -eq 'v1') { $other = 'v2' }
    $existing = Get-ConfValue 'secret_key' $fam
    $otherKey = Get-ConfValue 'secret_key' $other
    $cf = $Families[$fam].Conf
    if ($SecretFile) {
        if (-not (Test-Path $SecretFile)) { Set-Fail "Cannot read the secret key file $SecretFile." '' 'Check the path and its permissions.'; return $false }
        $script:Secret = "$((Get-Content $SecretFile -TotalCount 1))".Trim(); $script:SecretSource = "file $SecretFile"
        if (-not $script:Secret) { Set-Fail "$SecretFile is empty." '' 'Put the secret key on the first line.'; return $false }
        Write-Info "Using the secret key from $SecretFile ($(Get-Masked $script:Secret))"
    }
    elseif ($SecretKey) {
        $script:Secret = $SecretKey.Trim(); $script:SecretSource = 'parameter'
        Write-Warn "Using the secret key from -SecretKey ($(Get-Masked $script:Secret)) - command lines are visible to other processes; prefer -SecretFile or BP_SECRET"
    }
    elseif ($env:BP_SECRET) {
        $script:Secret = $env:BP_SECRET.Trim(); $script:SecretSource = 'environment'
        Write-Info "Using the secret key from the BP_SECRET environment variable ($(Get-Masked $script:Secret))"
    }
    elseif ($existing -and ((-not $Reconfigure) -or (Read-YesNo "Keep the secret key already in $cf ($(Get-Masked $existing))?" 'y'))) {
        $script:Secret = $existing; $script:SecretSource = $cf
        Write-Info "Using the secret key already in $cf ($(Get-Masked $existing)) - to replace it run with -Reconfigure"
    }
    elseif (-not $existing -and $otherKey -and (Read-YesNo "Use the secret key of the $other collector configuration on this host ($(Get-Masked $otherKey))?" 'y')) {
        $script:Secret = $otherKey; $script:SecretSource = "$other config"
    }
    else {
        Write-Say '  The agent needs the Bindplane secret key (Bindplane console -> Agents -> Install Agents).'
        Write-Say "  It is written only to $cf (readable by SYSTEM and Administrators) - this script keeps no copy."
        $k = Read-SecretKey 'Bindplane secret key'
        if (-not $k) {
            Set-Fail 'No secret key was provided.' "It is required in $cf." 'Run interactively, or for an unattended run pass -SecretFile PATH (a protected file) or set BP_SECRET in the environment.'
            return $false
        }
        $script:Secret = $k; $script:SecretSource = 'prompt'
    }
    Write-RunLog "secret key source: $($script:SecretSource)"
    if ($script:Secret -notmatch '^[0-9A-HJKMNP-TV-Z]{26}$') { Write-Warn 'The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one).' }
    return $true
}

# =============================================================================
#  msiexec
# =============================================================================
$MsiExitText = @{
    1601 = 'The Windows Installer service could not be accessed.'
    1602 = 'The installation was cancelled.'
    1603 = 'A fatal error occurred during installation.'
    1612 = 'The installation source is not available.'
    1618 = 'Another installation is already in progress.'
    1619 = 'The installation package could not be opened (missing, damaged or blocked).'
    1620 = 'The installation package is not a valid Windows Installer package.'
    1625 = 'This installation is forbidden by system policy.'
    1633 = 'This installation package is not supported on this processor type.'
    1638 = 'Another version of this product is already installed.'
    1639 = 'Invalid command-line argument.'
}
# Invoke-Msiexec ARGS LOG -> exit code (waits and retries while another installation is running)
function Invoke-Msiexec([string[]]$msiArgs, [string]$log) {
    $all = $msiArgs + @('/qn', '/norestart', '/l*v', "`"$log`"")
    for ($i = 1; $i -le 10; $i++) {
        Write-Info "msiexec $($all -join ' ')"
        Write-RunLog "CMD msiexec $($all -join ' ')"
        $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $all -Wait -PassThru
        $code = $p.ExitCode
        Write-RunLog "msiexec exit $code"
        if ($code -ne 1618) { return $code }
        Write-Warn "Another installation is running (Windows Update, SCCM...) - waiting 30s ($i/10)"
        Start-Sleep -Seconds 30
    }
    return 1618
}
# Set-MsiFail CODE LOG -> FAIL_* explaining a failed msiexec, from its log
function Set-MsiFail([int]$code, [string]$log) {
    $text = ''; if (Test-Path $log) { $text = [IO.File]::ReadAllText($log) }
    $errs = @([regex]::Matches($text, '(?m)^.*(?:Error \d{4}|Product: .* -- Error \d{4}).*$') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique -First 3)
    $ctx = ''
    $idx = $text.IndexOf('Return value 3')
    if ($idx -gt 0) { $start = [Math]::Max(0, $idx - 1500); $ctx = ($text.Substring($start, $idx - $start) -split "`r?`n" | Where-Object { $_ -match 'Error|error|failed|CustomAction|denied' } | Select-Object -Last 4) -join "`n" }
    $why = (@($errs + @($ctx -split "`n")) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique -First 4) -join "`n"
    $desc = $MsiExitText[$code]; if (-not $desc) { $desc = "msiexec exit code $code." }
    if ($text -match 'A newer version of this software is already installed') {
        Set-Fail 'The MSI refused to install: a newer version of the collector is installed.' 'Windows Installer does not downgrade in place.' 'Choose [r]: the install step uninstalls the newer version first (it asks).'
    }
    elseif ($text -match 'Error 1920|Error 1921') {
        Set-Fail 'The collector service failed to start during the installation (Error 1920) - the MSI rolled back.' "$why" 'Event Viewer -> Windows Logs -> System (Service Control Manager); antivirus or application control blocking the collector .exe is the usual cause.'
    }
    elseif ($text -match 'Error 1722|Error 1721') {
        Set-Fail 'A setup script inside the MSI failed (Error 1722).' "$why" 'The MSI runs cmd.exe /C ...install\generate-*.bat: application control (AppLocker/WDAC) or antivirus may block it. Ask for an exception, then choose [r].'
    }
    elseif ($text -match 'Error 1925|Error 1303|Error 1310|Access is denied') {
        Set-Fail 'msiexec was denied access to a file or folder.' "$why" 'Run from an elevated PowerShell (Run as administrator); check antivirus quarantine and folder permissions on the install directory.'
    }
    elseif ($code -eq 1625) {
        Set-Fail 'Group Policy forbids this installation (1625).' 'Software Restriction / AppLocker / "DisableMSI" policy.' 'Ask the platform team for an exception for the collector MSI (publisher observIQ, Inc.).'
    }
    elseif ($code -in @(1619, 1620)) {
        Set-Fail "msiexec could not use the MSI ($code): $desc" 'The cached file is damaged, or blocked (Zone.Identifier / antivirus).' "Delete the cached MSI and choose [r]: Remove-Item '$CacheDir\*.msi'"
    }
    elseif ($code -eq 1618) {
        Set-Fail 'Another installation kept running for 5 minutes (1618).' 'Windows Update, SCCM or another msiexec holds the installer mutex.' 'Wait for it to finish (Get-Process msiexec), then choose [r].'
    }
    else {
        Set-Fail "msiexec failed with exit code ${code}: $desc" "$why" "Read the MSI log: $log (search for 'Return value 3')"
    }
}

# =============================================================================
#  Collector configuration (written by this script: the MSI writes none on upgrades)
# =============================================================================
function Write-Utf8NoBom([string]$path, [string]$text) { [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $false)) }
# only SYSTEM (the service account) and Administrators may read the file that holds the secret key
function Protect-File([string]$path) {
    $out = & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warn "Could not restrict the permissions of ${path}: $out" ; return }
    Write-RunLog "ACL of $path set to SYSTEM + Administrators"
}
function Get-RedactedConfig([string]$path) {
    if (-not (Test-Path $path)) { return "(no $path)" }
    return ((Get-Content $path) -replace '^(secret_key:).*', '$1 ***REDACTED***' -replace '(Secret-Key )[^"'']*', '$1***REDACTED***') -join "`r`n"
}
function Save-ConfigBackup([string]$path) {
    $b = Join-Path $Root ('{0}.bak-{1}' -f (Split-Path $path -Leaf), $script:RunTs)
    Write-Utf8NoBom $b (Get-RedactedConfig $path)
    Write-Info "Previous $(Split-Path $path -Leaf) saved as $b (secret key redacted)"
}
function Get-ManagerYaml([string]$agentId) {
    $l = @("endpoint: `"$($script:Conf['OPAMP_ENDPOINT'])`"", "secret_key: `"$($script:Secret)`"")
    if ($agentId) { $l += "agent_id: `"$agentId`"" }
    $l += "labels: `"$($script:Conf['AGENT_LABELS'])`""
    $l += "agent_name: `"$($script:Conf['AGENT_NAME'])`""
    return (($l -join "`r`n") + "`r`n")
}
function Get-SupervisorYaml {
    # the layout the v2 MSI's generate-supervisor-yaml.bat writes
    $d = (Get-CollectorDir).TrimEnd('\') + '\'
    $v = $script:Conf['BP_VERSION']
    $l = @(
        'server:',
        "  endpoint: `"$($script:Conf['OPAMP_ENDPOINT'])`"",
        '  headers:',
        "    Authorization: `"Secret-Key $($script:Secret)`"",
        "    User-Agent: `"bindplane-otel-collector/$v`"",
        '  tls:',
        '    insecure: true',
        '    insecure_skip_verify: true',
        'capabilities:',
        '  accepts_remote_config: true',
        '  reports_remote_config: true',
        '  reports_available_components: true',
        'agent:',
        "  executable: '${d}bindplane-otel-collector.exe'",
        '  description:',
        '    non_identifying_attributes:',
        "      service.labels: `"$($script:Conf['AGENT_LABELS'])`"",
        "  args: ['--feature-gates', 'service.AllowNoPipelines']",
        'storage:',
        "  directory: '${d}supervisor_storage'",
        'telemetry:',
        '  logs:',
        '    level: 0',
        "    output_paths: ['${d}supervisor_storage\supervisor.log']")
    return (($l -join "`r`n") + "`r`n")
}

# =============================================================================
#  STEPS (each returns 0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
function Step-Preflight {
    $script:ChkFails = 0; $script:ChkWarns = 0
    $f = Join-Path $EvidenceDir "preflight-$($script:RunTs).txt"
    Write-Info "Recording the host baseline to $f"
    $base = @("# pre-flight $((Get-Date).ToString('s')) on $env:COMPUTERNAME - $ScriptName v$ScriptVersion",
              "## OS: $([Environment]::OSVersion.VersionString)", "## collector: $(Get-InstalledSummary)")
    try { $base += (& ipconfig.exe /all 2>&1 | Out-String); $base += (& route.exe print -4 2>&1 | Out-String) } catch { }
    [IO.File]::WriteAllLines($f, [string[]]$base)
    Test-Platform
    Test-WindowsInstaller
    Test-PendingReboot
    Test-TimeSync
    Test-Space $env:SystemDrive 800 'the collector'
    Test-Space $CacheDir 300 "the download cache ($CacheDir)"
    Test-Existing
    if ([Net.WebRequest]::DefaultWebProxy -and -not [Net.WebRequest]::DefaultWebProxy.IsBypassed([uri]'http://192.0.2.1/')) { Write-Info 'A system proxy is configured - this script bypasses it for the gateway' }
    if ($script:ChkFails -gt 0) {
        Set-Fail "$($script:ChkFails) pre-flight check(s) failed, $($script:ChkWarns) warning(s)." 'See the [FAIL] lines and hints above.' 'Fix the failing items, then choose [r] to re-check. Choose [s] only if you knowingly accept a failure.'
        return 1
    }
    if ($script:ChkWarns -gt 0) {
        Write-Warn "$($script:ChkWarns) warning(s) above."
        if (-not (Read-YesNo 'Continue despite the warnings?' 'y')) { Set-Fail 'Stopped at your request after pre-flight warnings.' '' 'Resolve the warnings, then re-run.'; return 1 }
    }
    Write-Ok 'Pre-flight passed'
    return 0
}

function Step-Gateway {
    $gw = $script:Conf['GATEWAY']; $port = [int]$script:Conf['REPO_PORT']; $v = $script:Conf['BP_VERSION']
    $st = Test-Tcp $gw $port
    if (-not (Show-Tcp $gw $port $st 'gateway repository')) { Set-Fail "The gateway repository ${gw}:$port is not reachable ($st)." 'See the hint above.' 'Fix the path and choose [r]. Wrong address? Re-run with -Reconfigure.'; return 1 }
    $script:RepoSums = $null
    $r = Import-RepoIndex
    if (-not $r.Ok) { Set-RepoFail $r 'SHA256SUMS'; return 1 }
    if ($script:RepoInfo.Count -gt 0) {
        Write-Ok ("Repository: {0} files; default {1}, current v1 {2}, current v2 {3} (updated {4})" -f $script:RepoSums.Count, $script:RepoInfo['current_collector_version'], $script:RepoInfo['current_v1'], $script:RepoInfo['current_v2'], $script:RepoInfo['updated'])
    } else { Write-Warn "The gateway serves no VERSION-INFO - is this the NCINGA Bindplane repository? ($($script:RepoSums.Count) files)" }
    $vers = @(Get-RepoVersions)
    if ($vers.Count -eq 0) {
        Set-Fail "The gateway has no Windows MSI for this host ($($script:Arch))." "Staged there: $($script:RepoInfo['staged_versions']). Windows MSIs (and ARM64 ones) are staged only when enabled on the DMZ host." "On the DMZ host: bp-dmz-setup.sh --reconfigure (stage Windows / ARM64), then bp-dmz-setup.sh --only collector_artefacts`nOn the LIVE gateway afterwards: bp-live-setup.sh --sync-mirror ; then choose [r] here."
        return 1
    }
    Write-Ok "MSI versions for this host ($($script:Arch)): $($vers -join ' ')"
    if (-not $script:RepoMsis.ContainsKey($v)) {
        Set-Fail "$v is not on the gateway as a Windows MSI for $($script:Arch)." 'It was removed, the LIVE mirror is not synced yet, or it is not the current version of its family (only current versions keep the plain MSI name when the DMZ staged it earlier).' "Pick one of: $($vers -join ' ')  ->  -Reconfigure`nOr stage it on the DMZ host (bp-dmz-update-repo.sh) and sync the LIVE mirror."
        return 1
    }
    Write-Ok "$($script:RepoMsis[$v]) holds $v - $($Families[(Get-FamilyOfTag $v)].Label)"
    $oh = Get-OpampHost; $op = Get-OpampPort
    $st = Test-Tcp $oh $op
    if (-not (Show-Tcp $oh $op $st 'OpAMP relay - how the agent is managed')) {
        Write-Warn "The agent cannot connect until tcp/$op to $oh is open; the MSI can still be installed now."
        if (-not (Read-YesNo 'Continue with the installation?' 'y')) { Set-Fail "Stopped: the OpAMP relay ${oh}:$op is not reachable ($st)." 'See the hint above.' 'Have the rule installed, then choose [r].'; return 1 }
    }
    $st = Test-Tcp $oh $OtlpPort
    if ($st -eq 'open') { Write-Ok "TCP ${oh}:$OtlpPort reachable (OTLP - where this agent's telemetry is sent once configured)" }
    else { Write-Warn "TCP ${oh}:$OtlpPort $st (OTLP) - management works without it, but telemetry from this agent will not flow until it is open (Stage 11)" }
    if ((Get-RepoSum 'windows/bp-agent-install-windows.ps1')) {
        $tmp = Join-Path $CacheDir 'remote-installer.ps1'
        if ((Invoke-RepoGet 'windows/bp-agent-install-windows.ps1' $tmp).Ok) {
            $remote = ''; foreach ($l in [IO.File]::ReadAllLines($tmp)) { if ($l -match "^\`$ScriptVersion = '([0-9.]+)'") { $remote = $Matches[1]; break } }
            if ($remote -and ([version]$remote -gt [version]$ScriptVersion)) {
                Write-Warn "The gateway has a newer version of this installer ($remote; this is $ScriptVersion)"
                Write-Hint "Download $(Get-RepoUrl 'windows/bp-agent-install-windows.ps1') and run that one (it resumes from the same progress)"
            }
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        }
    }
    return 0
}

function Step-Download {
    if (-not (Confirm-Index)) { return 1 }
    $v = $script:Conf['BP_VERSION']; $rel = $script:RepoMsis[$v]
    if (-not $rel) { Set-Fail "$v is not on the gateway as a Windows MSI." '' "Run: -Only gateway (lists what is available)"; return 1 }
    $want = Get-RepoSum $rel; $f = Get-CacheFile $v
    if ((Test-Path $f) -and (Get-Sha256 $f) -eq $want) { Write-Ok "$(Split-Path $f -Leaf) already downloaded ($(Format-Size (Get-Item $f).Length)) and matches SHA256SUMS" }
    else {
        Remove-Item -Force $f -ErrorAction SilentlyContinue
        $part = "$f.part"
        if ((Test-Path $part) -and (Get-Item $part).Length -gt 0) { Write-Info "Resuming the partial download ($(Format-Size (Get-Item $part).Length) so far)" }
        Write-Info "Downloading $(Get-RepoUrl $rel)"
        $r = Invoke-RepoGet $rel $part -Resume -Progress
        if (-not $r.Ok) {
            Set-RepoFail $r $rel
            if ((Test-Path $part) -and (Get-Item $part).Length -gt 0) { $script:FailFix += "`nThe partial file is kept: [r] resumes it." }
            return 1
        }
        Move-Item -Force $part $f
        Write-Ok "Downloaded $(Split-Path $f -Leaf) ($(Format-Size (Get-Item $f).Length))"
    }
    $ps = Get-PubSumsRel $v
    if (Get-RepoSum $ps) {
        $pf = Join-Path $CacheDir (Split-Path $ps -Leaf)
        if (-not ((Test-Path $pf) -and (Get-Sha256 $pf) -eq (Get-RepoSum $ps))) {
            $r = Invoke-RepoGet $ps $pf
            if (-not $r.Ok) { Set-RepoFail $r $ps; return 1 }
            Write-Ok "Downloaded $(Split-Path $ps -Leaf)"
        }
    }
    return 0
}

function Step-Verify {
    if (-not (Confirm-Index)) { return 1 }
    $v = $script:Conf['BP_VERSION']; $rel = $script:RepoMsis[$v]; $f = Get-CacheFile $v; $asset = Get-AssetName $v
    $want = Get-RepoSum $rel; $got = ''
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        if (-not (Test-Path $f)) { if ($attempt -eq 1) { Write-Info "$(Split-Path $f -Leaf) is not in the download cache - downloading it" }; if (@(Step-Download)[-1] -ne 0) { return 1 } }
        $got = Get-Sha256 $f
        if ($got -eq $want) { break }
        Remove-Item -Force $f
        if ($attempt -eq 1) { Write-Warn "$(Split-Path $f -Leaf) does not match the gateway's SHA256SUMS (corrupt, or changed during the transfer) - deleted, downloading it again"; continue }
        Set-Fail "$(Split-Path $f -Leaf) still does not match the gateway's SHA256SUMS after a fresh download." 'The file on the gateway differs from its SHA256SUMS: the repository is inconsistent (a partial mirror sync, or a manual change).' 'On the gateway: cd /srv/bindplane && sha256sum -c --quiet SHA256SUMS ; on the LIVE gateway: bp-live-setup.sh --sync-mirror'
        return 1
    }
    Write-Ok "$rel ($v) matches the gateway's SHA256SUMS ($got)"
    $pubMatch = ''
    $pf = Join-Path $CacheDir (Split-Path (Get-PubSumsRel $v) -Leaf)
    if (Test-Path $pf) {
        $pw = ''; foreach ($l in [IO.File]::ReadAllLines($pf)) { if ($l -match ('^([0-9a-f]{64})\s+\*?' + [regex]::Escape($asset) + '$')) { $pw = $Matches[1] } }
        if ($pw -and $pw -ne $got) {
            Remove-Item -Force $f
            Set-Fail "The MSI differs from the PUBLISHER's checksum for $asset $v." 'The repository holds a file that is not the published release - it was modified, replaced, or saved under the wrong version name.' 'Do not install it. Re-stage the version on the DMZ host (bp-dmz-update-repo.sh) and report the incident.'
            return 1
        }
        if ($pw) { Write-Ok "Matches the publisher's SHA256SUMS ($asset)"; $pubMatch = 'match' } else { Write-Info "$asset is not listed in the publisher's SHA256SUMS" }
    } else { Write-Info "The publisher's SHA256SUMS for $v is not on the gateway - skipped" }

    # what the MSI says it is
    try { $p = Get-MsiInfo $f }
    catch { Set-Fail "The MSI could not be read: $($_.Exception.Message)" 'The file is damaged, or Windows Installer is unavailable.' "Delete it and choose [r]: Remove-Item '$f'"; return 1 }
    $fam = Get-FamilyOfTag $v; $base = ($v.TrimStart('v') -split '-')[0]
    $isV2 = ($p['ProductName'] -match 'BindPlane|BDOT')
    if ($p['UpgradeCode'] -ne $UpgradeCode) { Set-Fail "The MSI is not the collector (UpgradeCode $($p['UpgradeCode']))." 'A wrong file in the repository.' 'Re-stage the version on the DMZ host.'; return 1 }
    if (($fam -eq 'v2') -ne $isV2) { Set-Fail "The MSI is '$($p['ProductName'])' - not a $fam collector." 'A renamed file in the repository.' 'Re-stage the version on the DMZ host.'; return 1 }
    if ($p['ProductVersion'] -ne $base) { Set-Fail "The MSI is version $($p['ProductVersion']), not $v." 'A renamed or stale file in the repository (the plain MSI name holds the family''s current version).' 'Re-stage on the DMZ host, sync the mirror, then choose [r].'; return 1 }
    Write-Ok "MSI: $($p['ProductName']) $($p['ProductVersion']) (product code $($p['ProductCode']))"

    $script:SigResult = ''
    if ($SkipSignatureCheck) { Write-Warn 'Authenticode check skipped (-SkipSignatureCheck) - only the checksums were verified'; $script:SigResult = 'skipped' }
    else {
        $sig = Get-AuthenticodeSignature -FilePath $f
        $subject = ''; if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
        # Windows quotes values that contain commas (O="observIQ, Inc.") - compare without the quotes
        $plain = $subject -replace '"', ''
        if ([string]$sig.Status -eq 'Valid' -and $plain -match [regex]::Escape($TrustedSigner)) {
            Write-Ok "Authenticode signature valid - signed by $TrustedSigner (issuer: $((($sig.SignerCertificate.Issuer -replace '"', '') -split ', ')[0]))"; $script:SigResult = 'good'
        }
        elseif ([string]$sig.Status -eq 'Valid') {
            Set-Fail "The MSI is validly signed, but by '$subject' - not '$TrustedSigner'." 'A package from another publisher.' 'Do not install it. If the publisher changed its certificate subject, verify that independently and re-run with -TrustedSigner ''<subject part>''.'
            return 1
        }
        elseif ([string]$sig.Status -in @('HashMismatch', 'NotSigned')) {
            Remove-Item -Force $f
            Set-Fail "The MSI signature check failed: $($sig.Status) - $($sig.StatusMessage)" 'The file was modified after the publisher signed it, or it is not the published MSI.' 'Do not install it. Re-stage the version on the DMZ host, sync the mirror and choose [r].'
            return 1
        }
        else {
            Write-Warn "The MSI signature could not be validated: $($sig.Status) - $($sig.StatusMessage)"
            Write-Say  '  On isolated hosts this usually means the DigiCert root (DigiCert Trusted Root G4) is not in the'
            Write-Say  '  machine''s Trusted Root store, or revocation could not be checked offline. The checksums matched.'
            if ($script:Interactive -and (Read-YesNo 'Install anyway, with checksum verification only (NOT recommended)?' 'n')) { $script:SigResult = "accepted-$($sig.Status)" }
            else {
                Set-Fail "The MSI signature could not be validated ($($sig.Status))." 'The signing chain is not trusted on this host (missing DigiCert Trusted Root G4), or the certificate status could not be checked offline.' 'Import the DigiCert Trusted Root G4 certificate into Local Machine\Trusted Root (via GPO), then choose [r]. To knowingly accept checksum-only verification: -SkipSignatureCheck'
                return 1
            }
        }
    }
    $lines = @("version=$v", "file=$(Split-Path $f -Leaf)", "sha256=$got", "publisher_sums=$pubMatch", "signature=$($script:SigResult)", "product_code=$($p['ProductCode'])", "product_version=$($p['ProductVersion'])", "checked=$((Get-Date).ToString('s'))")
    [IO.File]::WriteAllLines($VerifyFile, [string[]]$lines)
    return 0
}
function Get-VerifyValue([string]$k) {
    if (-not (Test-Path $VerifyFile)) { return '' }
    foreach ($l in [IO.File]::ReadAllLines($VerifyFile)) { if ($l -like "$k=*") { return $l.Substring($k.Length + 1) } }
    return ''
}

# Uninstall-Product CODE NAME -> $true when removed
function Uninstall-Product([string]$code, [string]$name) {
    $log = Join-Path $LogDir "msi-uninstall-$($script:RunTs).log"
    Write-Info "Uninstalling '$name' ($code)"
    $rc = Invoke-Msiexec @('/x', $code) $log
    if ($rc -in @(0, 3010, 1605)) { if ($rc -eq 3010) { Write-Warn 'Uninstalled - Windows asks for a reboot to finish' }; Write-Ok "'$name' uninstalled"; return $true }
    Set-MsiFail $rc $log
    return $false
}

function Step-Install {
    $v = $script:Conf['BP_VERSION']; $f = Get-CacheFile $v; $fam = Get-FamilyOfTag $v
    if (-not (Test-Path $f)) { Set-Fail "$(Split-Path $f -Leaf) is not in the download cache." 'The download step did not complete, or the cache was cleaned.' 'Re-run with: -From download'; return 1 }
    if ((Get-VerifyValue 'version') -ne $v -or (Get-VerifyValue 'sha256') -ne (Get-Sha256 $f)) {
        if ((Get-StepState 'verify') -eq 'skipped') { Write-Warn 'The verify step was skipped - installing an MSI whose checksums and signature were not checked' }
        else { Set-Fail "$(Split-Path $f -Leaf) has not been verified (or changed since)." 'The verify step must pass first.' 'Re-run with: -From verify'; return 1 }
    }
    $target = Get-VerifyValue 'product_code'; $targetVer = Get-VerifyValue 'product_version'
    $i = Get-Installed
    $uninstallFirst = $false; $mode = 'install'
    if ($i) {
        if ($i.Count -gt 1) {
            Write-Warn "$($i.Count) collector products are registered - removing all but the one being installed"
            foreach ($c in $i.AllCodes) { if ($c -ne $target -and $c -ne $i.Code) { if (-not (Uninstall-Product $c $c)) { return 1 } } }
            $i = Get-Installed
        }
    }
    if ($i) {
        if ($i.Code -eq $target -and $i.Tag -eq $v) {
            if ($Reinstall) { $mode = 'repair'; Write-Info "Reinstalling $v (-Reinstall)" }
            else { Write-Ok "$($Families[$fam].Pkg) $v is already installed ($($i.Name))"; return 0 }
        }
        else {
            $cmp = 0
            try { $cmp = ([version]$targetVer).CompareTo([version]$i.ProductVersion) } catch { $cmp = 0 }
            if ($i.Family -ne $fam) {
                Write-Warn "This host runs the $($Families[$i.Family].Label) collector $($i.Tag); $v is a $($Families[$fam].Label) release."
                Write-Say  '  Both families share one Windows product: the installed collector is REPLACED (no side-by-side install on Windows).'
                Write-Say  '  Its agent shows as disconnected in the console afterwards; the new one appears as a new agent.'
                if (-not $script:Interactive -and -not $AllowFamilySwitch) {
                    Set-Fail "A $($i.Family) collector is installed and switching families was not allowed." 'Unattended runs never replace the other family on their own.' 'Re-run interactively, or add -AllowFamilySwitch'
                    return 1
                }
                if ($script:Interactive -and -not (Read-YesNo "Replace $($i.Tag) with ${v}?" 'y')) { Set-Fail 'Family switch declined.' '' 'Pick a version of the installed family with -Reconfigure.'; return 1 }
            }
            if ($cmp -gt 0 -and $i.Family -ne $fam) { $mode = 'upgrade'; Write-Info "Replacing $($i.Tag) with $v (the MSI removes the $($i.Family) product; its $($Families[$i.Family].Conf) stays in the folder for a rollback)" }
            elseif ($cmp -gt 0) { $mode = 'upgrade'; Write-Info "Upgrading $($i.Tag) -> $v (the MSI replaces the installed product; configuration and agent identity are kept)" }
            else {
                $uninstallFirst = $true
                if ($cmp -lt 0) { Write-Warn "This is a DOWNGRADE ($($i.Tag) -> $v): Windows Installer cannot downgrade in place - the installed version is uninstalled first" }
                else { Write-Info "$($i.Tag) and $v carry the same MSI version ($targetVer): the installed one is uninstalled first (the MSI cannot upgrade between them)" }
                if ($script:Interactive -and -not (Read-YesNo "Uninstall $($i.Tag), then install ${v}?" 'y')) { Set-Fail 'Declined.' '' 'Pick another version with -Reconfigure.'; return 1 }
            }
        }
    }
    $dir = Get-CollectorDir
    if ($i) { $dir = $i.Dir; if ($script:Conf['INSTALL_DIR'] -ne $dir) { $script:Conf['INSTALL_DIR'] = $dir; Save-Config } }
    # the secret is read from the current config now - the uninstall below deletes supervisor.yaml
    if (-not (Confirm-Secret)) { return 1 }
    $cf = Get-ConfPath $fam
    if (Test-Path $cf) { Save-ConfigBackup $cf }
    if ($uninstallFirst) { if (-not (Uninstall-Product $i.Code $i.Name)) { return 1 } }
    $log = Join-Path $LogDir "msi-install-$v-$($script:RunTs).log"
    $msiArgs = @('/i', "`"$f`"", "INSTALLDIR=`"$($dir.TrimEnd('\'))`"")
    if ($mode -eq 'repair') { $msiArgs += @('REINSTALL=ALL', 'REINSTALLMODE=vomus') }
    Write-Info 'Installing from the local MSI - no secret key is passed to msiexec (this script writes the configuration itself)'
    $rc = Invoke-Msiexec $msiArgs $log
    switch ($rc) {
        0 { Write-Ok "msiexec finished (log: $log)" }
        3010 { Write-Warn "Installed - Windows asks for a reboot to finish (3010). The collector usually runs before the reboot." }
        1641 { Write-Warn 'Installed - Windows is restarting the machine (1641). Re-run this script after the reboot to finish.' }
        1638 {
            Set-Fail 'msiexec reports another version of the collector is installed (1638).' 'The installed product could not be upgraded by this MSI.' 'Choose [r] (the step uninstalls it first), or uninstall it: -Uninstall'
            return 1
        }
        default { Set-MsiFail $rc $log; return 1 }
    }
    $n = Get-Installed
    if (-not $n -or $n.Code -ne $target) { Set-Fail 'msiexec succeeded but the expected product is not registered.' "Registered: $(if ($n) { "$($n.Name) $($n.Code)" } else { 'none' })" "Read the MSI log: $log"; return 1 }
    if ($n.Dir -ne $script:Conf['INSTALL_DIR']) { $script:Conf['INSTALL_DIR'] = $n.Dir; Save-Config }
    if (-not (Get-Service $Families[$fam].Svc -ErrorAction SilentlyContinue)) { Set-Fail "The MSI installed but the $($Families[$fam].Svc) service is missing." 'The installation did not complete.' "Choose [r] (repairs the installation); read $log"; return 1 }
    Write-Ok "Installed $($n.Name) $($n.Tag) in $($n.Dir)"
    [IO.File]::WriteAllText($RestartFlag, 'install')
    return 0
}

function Step-Configure {
    if (-not (Confirm-Secret)) { return 1 }
    $fam = Get-ActiveFamily; $dir = Get-CollectorDir; $cf = Get-ConfPath $fam
    if (-not (Test-Path $dir)) { Set-Fail "$dir does not exist." 'The collector is not installed.' 'Re-run with: -From install'; return 1 }
    if ($fam -eq 'v1') {
        $aid = Get-ConfValue 'agent_id' 'v1'
        $new = Get-ManagerYaml $aid
    } else { $new = Get-SupervisorYaml }
    $old = ''; if (Test-Path $cf) { $old = [IO.File]::ReadAllText($cf) }
    $script:ConfigChanged = $true
    if ($old -eq $new) { $script:ConfigChanged = $false; Write-Ok "$($Families[$fam].Conf) already has the right endpoint, key and labels" }
    else {
        if ($old) {
            if (-not (Test-Path (Join-Path $Root "$($Families[$fam].Conf).bak-$($script:RunTs)"))) { Save-ConfigBackup $cf }
            $oe = Get-ConfValue 'endpoint' $fam; $ol = Get-ConfValue 'labels' $fam; $ok = Get-ConfValue 'secret_key' $fam
            if ($oe -ne $script:Conf['OPAMP_ENDPOINT']) { Write-Say "      endpoint: $(if ($oe) { $oe } else { '<none>' })  ->  $($script:Conf['OPAMP_ENDPOINT'])" }
            if ($ol -ne $script:Conf['AGENT_LABELS']) { Write-Say "      labels:   $(if ($ol) { $ol } else { '<none>' })  ->  $($script:Conf['AGENT_LABELS'])" }
            if ($ok -and $ok -ne $script:Secret) { Write-Say "      secret key: replaced ($(Get-Masked $ok) -> $(Get-Masked $script:Secret))" }
        }
        $tmp = "$cf.ncinga-tmp"
        Write-Utf8NoBom $tmp $new
        Protect-File $tmp
        Move-Item -Force $tmp $cf
        Protect-File $cf
        Write-Ok "Wrote $cf (endpoint $($script:Conf['OPAMP_ENDPOINT']); readable by SYSTEM and Administrators only)"
        if ($fam -eq 'v1') { if ($aid) { Write-Info "Kept the existing agent_id $aid - the console keeps this host as the same agent" } else { Write-Info 'No agent_id yet - the collector generates one when it starts' } }
        else { $id = Get-ConfValue 'agent_id' 'v2'; if ($id) { Write-Info "The agent identity ($id, supervisor_storage) is kept - the console keeps this host as the same agent" } }
        [IO.File]::WriteAllText($RestartFlag, 'config')
    }
    # the other family's config (left behind by a v1 <-> v2 switch) still holds the secret key: protect it too
    $ofam = 'v1'; if ($fam -eq 'v1') { $ofam = 'v2' }
    $ocf = Join-Path $dir $Families[$ofam].Conf
    if (Test-Path $ocf) { Protect-File $ocf; Write-Info "$($Families[$ofam].Conf) of the earlier $ofam collector is kept for a rollback (readable by SYSTEM and Administrators only)" }
    Write-Hint "Labels `"$($script:Conf['AGENT_LABELS'])`" decide which configuration the console assigns to this agent (Stage 11)."
    return 0
}

function Get-SvcStatus([string]$svc) { $s = Get-Service $svc -ErrorAction SilentlyContinue; if ($s) { return [string]$s.Status }; return '' }
function Get-ServicePid([string]$svc) { try { return [int](Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction Stop).ProcessId } catch { return 0 } }
function Get-LogLineCount([string]$path) { if (Test-Path $path) { return @(Get-Content $path -ErrorAction SilentlyContinue).Count }; return 0 }
function Get-LogMark { if (Test-Path $LogMarkFile) { $p = ([IO.File]::ReadAllText($LogMarkFile)).Trim() -split '\|'; if ($p.Count -eq 2 -and $p[0] -eq (Get-LogPath) -and [int]$p[1] -le (Get-LogLineCount (Get-LogPath))) { return [int]$p[1] } }; return 0 }
# problem lines in the collector log since line FROM
function Get-LogErrors([int]$from = 0, [int]$n = 6) {
    $path = Get-LogPath
    if (-not (Test-Path $path)) { return @() }
    $lines = @(Get-Content $path -ErrorAction SilentlyContinue)
    if ($from -gt 0 -and $from -lt $lines.Count) { $lines = $lines[$from..($lines.Count - 1)] } elseif ($from -gt 0) { $lines = @() } else { $lines = @($lines | Select-Object -Last 200) }
    return @($lines | Where-Object { $_ -match '"level":"error"|error|refused|denied|unauthor|forbidden|bad handshake|status=[45]\d\d' -and $_ -notmatch $BenignLogRe } |
             ForEach-Object { ($_ -replace '"resource":\{[^}]*\},?', '' -replace '"stacktrace":"[^"]*"', '' -replace '"caller":"[^"]*",?', '') } | Select-Object -Last $n |
             ForEach-Object { if ($_.Length -gt 230) { $_.Substring(0, 230) } else { $_ } })
}
function Get-LogHttpCode([int]$from = 0) {
    $path = Get-LogPath
    if (-not (Test-Path $path)) { return '' }
    $lines = @(Get-Content $path -ErrorAction SilentlyContinue); if ($from -gt 0 -and $from -lt $lines.Count) { $lines = $lines[$from..($lines.Count - 1)] }
    $code = ''
    foreach ($l in $lines) { if ($l -match 'status[ =:"]*([45]\d{2})') { $code = $Matches[1] } }
    return $code
}
function Get-StartProblem([string]$svc, [datetime]$since) {
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction Stop | Where-Object { $_.Message -match [regex]::Escape($svc) -or $_.Message -match 'BDOT|observIQ' } | Select-Object -First 3) } catch { }
    $text = (@($ev | ForEach-Object { $_.Message }) + @(Get-LogErrors (Get-LogMark) 5)) -join "`n"
    foreach ($e in $ev) { Write-Say "      | $($e.TimeCreated.ToString('s')) $(($e.Message -split "`n")[0])" }
    foreach ($l in (Get-LogErrors (Get-LogMark) 5)) { Write-Say "      | $l" }
    if ($text -match 'yaml|unmarshal|cannot parse|invalid config|failed to (load|read)') {
        Set-Fail 'The collector rejected its configuration file.' (($text -split "`n" | Where-Object { $_ -match 'yaml|unmarshal|parse|config' } | Select-Object -First 1)) 'Re-write it: -Only configure (check the labels); look at the collector log.'
    } elseif ($text -match 'Access is denied|permission denied') {
        Set-Fail 'The collector was denied access to a file it needs.' 'Antivirus / application control, or changed folder permissions.' 'Check the antivirus quarantine and the folder ACL, then choose [r].'
    } elseif ($text -match '1053|did not respond') {
        Set-Fail 'The service did not respond to the start request in time (1053).' 'The collector .exe is blocked or very slow to start (antivirus scanning on first run).' 'Choose [r]; exclude the collector folder from real-time scanning if the platform team agrees.'
    } else {
        Set-Fail "The $svc service does not stay running." 'See the event log and collector log lines above.' "Event Viewer -> System (Service Control Manager); Get-Content '$(Get-LogPath)' -Tail 50"
    }
}

function Step-Start {
    $fam = Get-ActiveFamily; $svc = $Families[$fam].Svc; $cf = Get-ConfPath $fam
    if (-not (Test-Path $cf)) { Set-Fail "$cf is missing." 'The configure step has not run.' 'Re-run with: -From configure'; return 1 }
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if (-not $s) { Set-Fail "The $svc service does not exist." 'The collector is not installed.' 'Re-run with: -From install'; return 1 }
    Set-Service -Name $svc -StartupType Automatic
    Write-Ok "$svc starts automatically at boot"
    $since = (Get-Date).AddSeconds(-2)
    if ((Test-Path $RestartFlag) -or $script:Forced['start'] -or $s.Status -ne 'Running') {
        [IO.File]::WriteAllText($LogMarkFile, "$(Get-LogPath)|$(Get-LogLineCount (Get-LogPath))")
        Write-Info "Restarting $svc"
        try { if ($s.Status -eq 'Running') { Restart-Service -Name $svc -Force } else { Start-Service -Name $svc } }
        catch { Write-Err "The service did not start: $($_.Exception.Message)"; Get-StartProblem $svc $since; return 1 }
    } else { Write-Ok "$svc is already running with the current configuration" }
    $pid0 = Get-ServicePid $svc
    Write-Info 'Watching the service for 10s (a bad configuration makes it exit) ...'
    for ($i = 0; $i -lt 10; $i++) { Start-Sleep -Seconds 1; if ((Get-SvcStatus $svc) -ne 'Running') { break } }
    $st = Get-SvcStatus $svc; $pid1 = Get-ServicePid $svc
    if ($st -ne 'Running' -or ($pid0 -and $pid1 -and $pid0 -ne $pid1)) {
        Write-Err "$svc is not stable (status $(if ($st) { $st } else { 'missing' }), process $pid0 -> $pid1)"
        Get-StartProblem $svc $since
        return 1
    }
    Remove-Item -Force $RestartFlag -ErrorAction SilentlyContinue
    Write-Ok "$svc is running and stable (pid $pid1)"
    return 0
}

# local address:port of the collector's established OpAMP session
function Get-OpampSession {
    $ip = Resolve-IPv4 (Get-OpampHost); $port = Get-OpampPort
    if (-not $ip) { return '' }
    $proc = $Families[(Get-ActiveFamily)].Proc
    $pids = @(Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    if ($pids.Count -eq 0) { return '' }
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $c = @(Get-NetTCPConnection -State Established -RemotePort $port -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq $ip -and $pids -contains $_.OwningProcess } | Select-Object -First 1)
        if ($c.Count -gt 0) { return ('{0}:{1}' -f $c[0].LocalAddress, $c[0].LocalPort) }
        return ''
    }
    foreach ($l in (& netstat.exe -ano -p tcp)) {
        if ($l -match '^\s*TCP\s+(\S+)\s+(\S+):(\d+)\s+ESTABLISHED\s+(\d+)') { if ($Matches[2] -eq $ip -and [int]$Matches[3] -eq $port -and $pids -contains [int]$Matches[4]) { return $Matches[1] } }
    }
    return ''
}

function Step-Connect {
    $fam = Get-ActiveFamily; $svc = $Families[$fam].Svc; $oh = Get-OpampHost; $op = Get-OpampPort; $v = $script:Conf['BP_VERSION']
    $name = $script:Conf['AGENT_NAME']; if ($fam -eq 'v2') { $name = $env:COMPUTERNAME }
    if ((Get-SvcStatus $svc) -ne 'Running') { Set-Fail 'The collector service is not running.' 'It stopped after the start step.' 'Re-run with: -From start'; return 1 }
    $i = Get-Installed
    if ($i -and $i.Tag -eq $v) { Write-Ok "Collector $v is running - $($Families[$fam].Label)" } else { Write-Warn "Installed collector reports '$(if ($i) { $i.Tag })' (chosen version $v)" }
    $aid = ''
    for ($k = 0; $k -lt 30; $k++) { $aid = Get-ConfValue 'agent_id' $fam; if ($aid) { break }; Start-Sleep -Seconds 1 }
    if ($aid) { Write-Ok "Agent identity $aid" } else { Write-Warn 'No agent identity recorded yet' }
    Write-Info "Waiting up to 60s for the OpAMP session to ${oh}:$op ..."
    $c1 = ''; $c2 = ''
    for ($k = 0; $k -lt 60; $k++) { $c1 = Get-OpampSession; if ($c1) { break }; Start-Sleep -Seconds 1 }
    if ($c1) { Write-Info "Session from $c1 - checking it holds for 15s ..."; Start-Sleep -Seconds 15; $c2 = Get-OpampSession }
    $mark = Get-LogMark
    $errs = @(Get-LogErrors $mark 6)
    $stable = ($c1 -and $c1 -eq $c2)
    if ($errs.Count -gt 0) { Write-RunLog "collector log errors since the start: $($errs -join ' | ')"; if (-not $stable) { Write-Warn 'Collector log errors since it was started:'; foreach ($e in $errs) { Write-Say "         $e" } } }
    $console = $false
    if ($stable) {
        Write-Ok "Stable OpAMP session to ${oh}:$op from $c1 (a rejected key would have dropped it)"
        Write-Say "  Check the Bindplane console now: Agents -> $name (identity $aid, labels $($script:Conf['AGENT_LABELS']))."
        $console = Read-YesNo "Is $name shown as Connected?" 'y'
    }
    $ev = Join-Path $EvidenceDir "agent-$env:COMPUTERNAME-$($script:RunTs).txt"
    $evl = @("# Agent install evidence - $env:COMPUTERNAME - $((Get-Date).ToString('s')) - $ScriptName v$ScriptVersion",
             "os=$([Environment]::OSVersion.VersionString) arch=$($script:Arch)",
             "collector=$($Families[$fam].Pkg) version=$v family=$fam identity=$aid name=$name dir=$(Get-CollectorDir)",
             "gateway_repo=$(Get-RepoUrl '/') opamp=$($script:Conf['OPAMP_ENDPOINT']) labels=$($script:Conf['AGENT_LABELS'])",
             "session=$c1 stable=$stable console_connected=$console", '## verification')
    if (Test-Path $VerifyFile) { $evl += [IO.File]::ReadAllLines($VerifyFile) }
    $evl += "## $($Families[$fam].Conf) (secret redacted)"; $evl += (Get-RedactedConfig (Get-ConfPath $fam))
    $evt = ($evl -join "`r`n"); if ($script:Secret) { $evt = $evt.Replace($script:Secret, '***REDACTED***') }
    [IO.File]::WriteAllText($ev, $evt)
    if ($console) {
        Write-Ok "PASS: the agent is managed from Bindplane through the gateway (evidence: $ev)"
        Clear-OldCache
        return 0
    }
    $code = Get-LogHttpCode $mark
    if (-not $stable -and $code) {
        switch ($code) {
            { $_ -in @('401', '403') } { Set-Fail "The gateway refused the agent's session with HTTP $code (collector log)." "The secret key in $($Families[$fam].Conf) was rejected by Bindplane - a wrong key, or a key of another Bindplane organisation." 'Copy the key again from the console (Agents -> Install Agents), then re-run with -Reconfigure (answer n to keeping the key).' }
            '404' { Set-Fail 'The session was answered with HTTP 404.' 'The endpoint path is wrong (it must end in /v1/opamp), or the relay forwards to the wrong place.' 'Check the endpoint; fix with -Reconfigure.' }
            { $_ -in @('502', '503') } { Set-Fail "The session was answered with HTTP $code by the gateway." 'The relay chain behind the gateway is down (LIVE hop 2 -> DMZ hop 1 -> Bindplane).' 'On the gateway: bp-live-setup.sh --diagnose (or bp-dmz-setup.sh --diagnose); then re-run with -Only connect.' }
            default { Set-Fail "The session was answered with HTTP $code." 'See the collector log lines above.' 'Run with -Diagnose' }
        }
    }
    elseif (-not $c1) {
        $st = Test-Tcp $oh $op
        if ($st -ne 'open') { [void](Show-Tcp $oh $op $st 'OpAMP relay'); Set-Fail "The agent cannot open a connection to ${oh}:$op ($st)." 'See the hint above.' 'Fix that (firewall rule, or the relay service on the gateway), then re-run with -Only connect.' }
        else { Set-Fail "The agent did not hold an OpAMP session to ${oh}:$op within 60s." 'The port is reachable, so the session is rejected at once (wrong secret key - the agent backs off), or the agent uses another endpoint.' "Check the endpoint in $(Get-ConfPath $fam) and the collector log $(Get-LogPath); then re-run with -Only connect." }
    }
    elseif ($c1 -ne $c2) { Set-Fail "The OpAMP session keeps reconnecting (local port $c1 -> $(if ($c2) { $c2 } else { 'none' }))." 'The session is closed after it is established - typically a wrong secret key, or an inline device between this host and the gateway.' 'Compare the key with the console; replace it with -Reconfigure. On the gateway: journalctl -u haproxy -n 30' }
    else { Set-Fail "The session is up but the console does not show $name as Connected." 'Authentication was rejected (wrong key or organisation), or the console was not refreshed.' 'Refresh the console and re-check the key; then re-run with -Only connect.' }
    return 1
}
function Clear-OldCache {
    $keep = Split-Path (Get-CacheFile $script:Conf['BP_VERSION']) -Leaf; $n = 0
    foreach ($f in @(Get-ChildItem $CacheDir -Filter '*-otel-collector*.msi*' -ErrorAction SilentlyContinue)) { if ($f.Name -ne $keep) { Remove-Item -Force $f.FullName; $n++ } }
    if ($n -gt 0) { Write-Info "Removed $n cached MSI(s) of other versions from $CacheDir" }
}

# =============================================================================
#  Answers
# =============================================================================
function Get-LabelValue([string]$k) { foreach ($p in ($script:Conf['AGENT_LABELS'] -split ',')) { if ($p -like "$k=*") { return $p.Substring($k.Length + 1) } }; return '' }

function Select-Version {
    $vers = @(Get-RepoVersions)
    if ($CollectorVersion) {
        $t = $CollectorVersion; if ($t -notlike 'v*') { $t = "v$t" }
        $m = & $VVersion $t; if ($m) { Write-Warn "  $m"; return $false }
        if ($vers.Count -gt 0 -and $vers -notcontains $t) { Write-Warn "  $t is not on the gateway as a Windows MSI for $($script:Arch). Available: $($vers -join ' ')"; return $false }
        $script:Conf['BP_VERSION'] = $t; Write-Info "  Collector version: $t - $($Families[(Get-FamilyOfTag $t)].Label)"; return $true
    }
    if ($vers.Count -eq 0) {
        Write-Warn '  The gateway''s versions could not be listed - enter the release tag'
        $t = Read-Answer 'Collector version (release tag, e.g. v1.109.0 or v2.0.1-beta.6)' $script:Conf['BP_VERSION'] $VVersion
        if (-not $t) { return $false }; if ($t -notlike 'v*') { $t = "v$t" }; $script:Conf['BP_VERSION'] = $t; return $true
    }
    $inst = Get-Installed; $instTag = ''; if ($inst) { $instTag = $inst.Tag }
    $dflt = $script:RepoInfo['current_collector_version']; $cur1 = $script:RepoInfo['current_v1']; $cur2 = $script:RepoInfo['current_v2']
    $def = $script:Conf['BP_VERSION']; if ($vers -notcontains $def) { $def = '' }
    foreach ($t in @($instTag, $dflt)) { if (-not $def -and $t -and $vers -contains $t) { $def = $t } }
    if (-not $def) { $def = $vers[0] }
    Write-Say "  Collector versions on the gateway for this host ($($script:Arch) MSI):"
    $idx = @{}; $n = 0; $defn = '1'
    foreach ($fam in @('v1', 'v2')) {
        $fv = @($vers | Where-Object { (Get-FamilyOfTag $_) -eq $fam }); if ($fv.Count -eq 0) { continue }
        if ($fam -eq 'v1') { Write-Say '     v1  observiq-otel-collector  - manager.yaml; the stable line the runbook describes' }
        else { Write-Say '     v2  bindplane-otel-collector - OpAMP supervisor + supervisor.yaml' }
        foreach ($t in $fv) {
            $n++; $idx["$n"] = $t; if ($t -eq $def) { $defn = "$n" }
            $flags = ''; if (Test-PreRelease $t) { $flags += ' pre-release' }
            if ($t -eq $dflt) { $flags += ' (gateway default)' }; if ($t -eq $cur1 -or $t -eq $cur2) { $flags += " (current $fam)" }
            if ($t -eq $instTag) { $flags += ' (installed here)' }
            Write-Say ('        {0,2}) {1,-16}{2}' -f $n, $t, $flags)
        }
    }
    while ($true) {
        $a = Read-Answer 'Collector version to install (number or tag)' $defn
        if (-not $a) { return $false }
        if ($idx.ContainsKey($a)) { $a = $idx[$a] }
        if ($a -notlike 'v*') { $a = "v$a" }
        if ($vers -contains $a) { $script:Conf['BP_VERSION'] = $a; break }
        Write-Warn "  $a is not on the gateway for this host - choose a number from the list"
        if (-not $script:Interactive) { return $false }
    }
    $t = $script:Conf['BP_VERSION']
    $msg = "  ${t}: $($Families[(Get-FamilyOfTag $t)].Label)"; if (Test-PreRelease $t) { $msg += ' - PRE-RELEASE: production use needs the customer''s approval' }
    Write-Info $msg
    if ($inst -and $inst.Family -ne (Get-FamilyOfTag $t)) { Write-Warn "  This host runs the $($inst.Family) collector $($inst.Tag) - on Windows it is replaced by the new one (the install step asks)" }
    return $true
}

function Read-Labels {
    if ($Labels) {
        $m = & $VLabels $Labels; if ($m) { Write-Warn "  -Labels: $m"; return $false }
        $script:Conf['AGENT_LABELS'] = $Labels; Write-Info "  Labels: $Labels"; return $true
    }
    $origin = $script:RepoInfo['origin_host']; $oip = ''
    if ($origin -match '\((\d+\.\d+\.\d+\.\d+)\)') { $oip = $Matches[1] }
    $defSite = Get-LabelValue 'site'
    if (-not $defSite) { $defSite = 'primary'; if ($origin -and ($origin -split ' ')[0] -match 'dr') { $defSite = 'dr' } }
    $defSeg = Get-LabelValue 'segment'
    if (-not $defSeg) { $tier = 'live'; if ($oip -and $oip -eq $script:Conf['GATEWAY']) { $tier = 'dmz' }; if ($defSite -eq 'dr') { $defSeg = "dr-$tier" } else { $defSeg = "prod-$tier" } }
    Write-Say '  Labels decide which configuration the console assigns to this agent (Stage 11) - they are not cosmetic.'
    $site = Read-Answer 'Site (primary or dr)' $defSite $VLabelValue; if (-not $site) { return $false }
    $seg = Read-Answer 'Network segment of this host' $defSeg $VLabelValue; if (-not $seg) { return $false }
    $defZone = $Zone; if (-not $defZone) { $defZone = Get-LabelValue 'zone' }
    if (-not $defZone -and -not $script:Interactive) { Write-Err '  The zone label has no default - unattended runs need -Zone NAME (or the full -Labels "...")'; return $false }
    $z = Read-Answer 'Zone / application group of this host (e.g. web, app, db, ad)' $defZone $VLabelValue; if (-not $z) { return $false }
    $lbl = "site=$site,segment=$seg,zone=$z,os=windows,role=source"
    $extras = @($script:Conf['AGENT_LABELS'] -split ',' | Where-Object { $_ -and $_ -notmatch '^(site|segment|zone|os|role)=' })
    if ($extras.Count -gt 0) { $lbl += ',' + ($extras -join ',') }
    $all = Read-Answer 'Labels (Enter to accept; edit to add more key=value pairs)' $lbl $VLabels; if (-not $all) { return $false }
    $script:Conf['AGENT_LABELS'] = $all
    return $true
}

function Set-ArgsIntoConfig {
    if ($Gateway) { $script:Conf['GATEWAY'] = ($Gateway -split ':')[0]; if ($Gateway -match ':(\d+)$') { $script:Conf['REPO_PORT'] = $Matches[1] } }
    if ($Endpoint) { $script:Conf['OPAMP_ENDPOINT'] = $Endpoint }
    if ($CollectorVersion) { $t = $CollectorVersion; if ($t -notlike 'v*') { $t = "v$t" }; $script:Conf['BP_VERSION'] = $t }
    if ($Labels) { $script:Conf['AGENT_LABELS'] = $Labels }
    if ($AgentName) { $script:Conf['AGENT_NAME'] = $AgentName }
    if ($InstallDir) { $script:Conf['INSTALL_DIR'] = $InstallDir.TrimEnd('\') }
    if (-not $script:Conf['REPO_PORT']) { $script:Conf['REPO_PORT'] = "$RepoPortDefault" }
    $i = Get-Installed
    if ($i -and -not $InstallDir) { $script:Conf['INSTALL_DIR'] = $i.Dir }
    if (-not $script:Conf['INSTALL_DIR']) { $script:Conf['INSTALL_DIR'] = Get-DefaultInstallDir }
}

function Read-AllAnswers {
    Write-Banner "Answers for this log source ($env:COMPUTERNAME)"
    $oldGw = $script:Conf['GATEWAY']
    $def = $script:Conf['GATEWAY']
    if (-not $def) { foreach ($f in @('v1', 'v2')) { $ep = Get-ConfValue 'endpoint' $f; if ($ep -match '^wss?://([^/:]+)') { $def = $Matches[1]; break } } }
    if ($def -and $script:Conf['REPO_PORT'] -and $script:Conf['REPO_PORT'] -ne "$RepoPortDefault") { $def = "${def}:$($script:Conf['REPO_PORT'])" }
    Write-Say '  The gateway of this host''s segment: the LIVE gateway for LIVE log sources, the DMZ gateway for DMZ ones.'
    while ($true) {
        $a = Read-Answer "Gateway address (IP; add :port if the repository is not on :$RepoPortDefault)" $def $VHost
        if (-not $a) { return $false }
        $script:Conf['GATEWAY'] = ($a -split ':')[0]; $script:Conf['REPO_PORT'] = "$RepoPortDefault"; if ($a -match ':(\d+)$') { $script:Conf['REPO_PORT'] = $Matches[1] }
        Write-Info "  Checking the repository at $(Get-RepoUrl '/') ..."
        $script:RepoSums = $null
        $r = Import-RepoIndex
        if ($r.Ok) { Write-Ok "  Repository found - MSI versions for this host: $(@(Get-RepoVersions) -join ' ')"; break }
        Set-RepoFail $r 'SHA256SUMS'
        Write-Block 'Problem' $script:FailWhat; Write-Block 'Likely cause' $script:FailWhy; Write-Block 'How to fix' $script:FailFix
        Set-Fail ''
        if (-not $script:Interactive) { return $false }
        if (Read-YesNo "Keep $($script:Conf['GATEWAY']) anyway (the version list cannot be shown; the gateway step checks again)?" 'n') { break }
        $def = $a
    }
    $def = $script:Conf['OPAMP_ENDPOINT']
    if (-not $def -or ($oldGw -and $oldGw -ne $script:Conf['GATEWAY'] -and $def -match ('://' + [regex]::Escape($oldGw) + '[:/]'))) { $def = "ws://$($script:Conf['GATEWAY']):$OpampPortDefault/v1/opamp" }
    $e = Read-Answer 'OpAMP endpoint the agent connects to (the gateway''s relay)' $def $VEndpoint; if (-not $e) { return $false }
    $script:Conf['OPAMP_ENDPOINT'] = $e
    if (-not (Select-Version)) { return $false }
    if (-not (Read-Labels)) { return $false }
    if ((Get-FamilyOfTag $script:Conf['BP_VERSION']) -eq 'v1') {
        $def = $script:Conf['AGENT_NAME']; if (-not $def) { $def = Get-ConfValue 'agent_name' 'v1' }; if (-not $def) { $def = $env:COMPUTERNAME }
        $n = Read-Answer 'Agent name shown in the console' $def $VAgentName; if (-not $n) { return $false }
        $script:Conf['AGENT_NAME'] = $n
    } else {
        $script:Conf['AGENT_NAME'] = $env:COMPUTERNAME
        Write-Info "  Agent name: $env:COMPUTERNAME (a v2 agent is named after the host)"
    }
    return $true
}
function Test-ConfigComplete { foreach ($k in @('GATEWAY', 'REPO_PORT', 'OPAMP_ENDPOINT', 'BP_VERSION', 'AGENT_LABELS', 'AGENT_NAME')) { if (-not $script:Conf[$k]) { return $false } }; return $true }
function Show-Config {
    $v = $script:Conf['BP_VERSION']; $vl = '?'
    if ($v) { $vl = "$v - $($Families[(Get-FamilyOfTag $v)].Label)"; if (Test-PreRelease $v) { $vl += '  PRE-RELEASE' } }
    $gwl = '?'; if ($script:Conf['GATEWAY']) { $gwl = Get-RepoUrl '/' }
    foreach ($row in @(@('Gateway repository', $gwl), @('OpAMP endpoint', $script:Conf['OPAMP_ENDPOINT']), @('Collector version', $vl),
                       @('Labels', $script:Conf['AGENT_LABELS']), @('Agent name', $script:Conf['AGENT_NAME']), @('Install folder', $script:Conf['INSTALL_DIR']),
                       @('This host', "$([Environment]::OSVersion.VersionString), $($script:Arch)"), @('Collector here now', (Get-InstalledSummary)))) {
        Write-Host ('  {0,-22} {1}' -f $row[0], $row[1])
    }
}

# =============================================================================
#  Diagnostics (read-only)
# =============================================================================
function Invoke-Diagnostics {
    $script:ChkFails = 0; $script:ChkWarns = 0
    Write-Banner "Diagnostics (read-only) - $env:COMPUTERNAME, $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Section 'This host'
    Test-Platform; Test-WindowsInstaller; Test-PendingReboot; Test-TimeSync; Test-Space $env:SystemDrive 800 'the collector'
    Write-Section 'Gateway'
    if ($script:Conf['GATEWAY']) {
        $st = Test-Tcp $script:Conf['GATEWAY'] ([int]$script:Conf['REPO_PORT'])
        if (-not (Show-Tcp $script:Conf['GATEWAY'] ([int]$script:Conf['REPO_PORT']) $st 'repository')) { $script:ChkFails++ }
        elseif ($true) {
            $script:RepoSums = $null; $r = Import-RepoIndex
            if ($r.Ok) {
                Add-Ok "Repository: $($script:RepoSums.Count) files; MSI versions for this host: $(@(Get-RepoVersions) -join ' '); default $($script:RepoInfo['current_collector_version'])"
                if ($script:Conf['BP_VERSION']) { if ($script:RepoMsis.ContainsKey($script:Conf['BP_VERSION'])) { Add-Ok "$($script:Conf['BP_VERSION']) is on the gateway" } else { Add-Warn "$($script:Conf['BP_VERSION']) is no longer on the gateway" } }
            } else { Set-RepoFail $r 'SHA256SUMS'; Add-Fail $script:FailWhat; Write-Hint (($script:FailFix -split "`n")[0]); Set-Fail '' }
        }
        if ($script:Conf['OPAMP_ENDPOINT']) {
            $oh = Get-OpampHost; $op = Get-OpampPort
            if (-not (Show-Tcp $oh $op (Test-Tcp $oh $op) 'OpAMP relay')) { $script:ChkFails++ }
            $st = Test-Tcp $oh $OtlpPort; if ($st -eq 'open') { Add-Ok "TCP ${oh}:$OtlpPort reachable (OTLP)" } else { Add-Warn "TCP ${oh}:$OtlpPort $st (OTLP - telemetry)" }
        }
    } else { Add-Warn 'No gateway saved yet - run the installer first (or pass -Gateway IP to -Diagnose)' }
    Write-Section 'Collector'
    $i = Get-Installed
    if (-not $i) { Add-Warn 'No collector is installed' }
    else {
        $fam = $i.Family; $svc = Get-Service $Families[$fam].Svc -ErrorAction SilentlyContinue
        $mode = ''; try { $mode = (Get-CimInstance Win32_Service -Filter "Name='$($Families[$fam].Svc)'" -ErrorAction Stop).StartMode } catch { }
        if ($svc -and $svc.Status -eq 'Running') { Add-Ok "$($i.Name) $($i.Tag): Running, start mode $mode" } else { Add-Warn "$($i.Name) $($i.Tag): $(if ($svc) { $svc.Status } else { 'service missing' }), start mode $mode" }
        $cf = Join-Path $i.Dir $Families[$fam].Conf
        if (Test-Path $cf) {
            $k = Get-ConfValue 'secret_key' $fam; $km = 'MISSING'; if ($k) { $km = Get-Masked $k }
            Add-Ok "$($Families[$fam].Conf): endpoint $(Get-ConfValue 'endpoint' $fam), key $km"
            Write-Say "         labels: $(Get-ConfValue 'labels' $fam)   identity: $(Get-ConfValue 'agent_id' $fam)"
            $acl = (& icacls.exe $cf 2>&1) -join ' '
            if ($acl -match 'BUILTIN\\Users|Everyone|S-1-5-32-545|S-1-1-0') { Add-Warn "$($Families[$fam].Conf) is readable by ordinary users (it holds the secret key) - run -Only configure to restrict it" }
            if ($script:Conf['OPAMP_ENDPOINT'] -and (Get-ConfValue 'endpoint' $fam) -ne $script:Conf['OPAMP_ENDPOINT']) { Add-Warn "Its endpoint differs from the saved answer ($($script:Conf['OPAMP_ENDPOINT'])) - run -Only configure" }
        } else { Add-Warn "$cf is missing - the agent has no endpoint/key (run -Only configure)" }
        if ($script:Conf['OPAMP_ENDPOINT']) {
            $s = Get-OpampSession
            if ($s) { Add-Ok "OpAMP session established from $s" } elseif ($svc -and $svc.Status -eq 'Running') { Add-Warn "No established OpAMP session to $(Get-OpampHost):$(Get-OpampPort)" }
        }
        $code = Get-LogHttpCode (Get-LogMark); if ($code -in @('401', '403')) { Add-Warn "The collector log shows HTTP $code on the OpAMP upgrade: the secret key is rejected" }
        $errs = @(Get-LogErrors (Get-LogMark) 5)
        if ($errs.Count -gt 0) { Write-Say "         log errors since the last start ($(Get-LogPath)):"; foreach ($e in $errs) { Write-Say "           $e" } }
    }
    Write-Section 'Result'
    if ($script:ChkFails -gt 0) { Write-Err "$($script:ChkFails) problem(s), $($script:ChkWarns) warning(s) - see the hints above" }
    elseif ($script:ChkWarns -gt 0) { Write-Warn "No failures, $($script:ChkWarns) warning(s)" }
    else { Write-Ok 'No problems found' }
    Write-Say "  Logs: this script $LogDir ; MSI logs $LogDir\msi-*.log ; collector $(Get-LogPath)"
}

# =============================================================================
#  Step runner
# =============================================================================
function Invoke-Steps([string[]]$list) {
    $total = $Steps.Count
    foreach ($step in $list) {
        $n = [array]::IndexOf($Steps, $step) + 1
        if ((Get-StepState $step) -eq 'done' -and -not $script:Forced[$step]) { Write-Host ('  [{0,2}/{1}] {2,-52} done - skipping' -f $n, $total, $StepTitle[$step]); continue }
        while ($true) {
            Write-Host ''
            if ($NoColor) { Write-Host ('=== [{0,2}/{1}] {2}   (runbook {3}) ===' -f $n, $total, $StepTitle[$step], $StepRef[$step]) }
            else { Write-Host ('=== [{0,2}/{1}] {2}   (runbook {3}) ===' -f $n, $total, $StepTitle[$step], $StepRef[$step]) -ForegroundColor White }
            Write-RunLog "==== STEP $step"
            $script:CurrentStep = $step; Set-Fail ''
            Set-StepState $step 'running'
            $rc = 1; $finished = $false
            try {
                $out = & "Step-$step"
                $rc = @($out)[-1]
                if ($rc -isnot [int]) { $rc = 1; if (-not $script:FailWhat) { Set-Fail 'The step ended without a result.' "Output: $($out -join ' ')" 'See the log.' } }
                $finished = $true
            }
            catch {
                $rc = 1; $finished = $true
                Set-Fail "Unexpected error: $($_.Exception.Message)" "At $($_.InvocationInfo.PositionMessage -replace '\s+', ' ')" 'See the log; choose [d] for diagnostics, [r] to retry.'
            }
            finally {
                if (-not $finished) { Set-StepState $step 'interrupted'; Write-Host ''; Write-Warn "Interrupted - progress is saved. Re-run the script to resume at: $($StepTitle[$step])" }
            }
            if ($rc -eq 0) { Set-StepState $step 'done'; $script:CurrentStep = ''; break }
            if ($rc -eq 3) { Set-StepState $step 'skipped'; $script:CurrentStep = ''; break }
            Set-StepState $step 'failed'
            Show-Failure $step
            $c = 'q'
            if ($script:Interactive) {
                while ($true) {
                    $c = Read-Choice '  What next?  [r] retry this step   [d] diagnostics   [s] skip this step   [q] quit, resume later' 'rdsq'
                    if ($c -ne 'd') { break }
                    Invoke-Diagnostics; Show-Failure $step
                }
            }
            switch ($c) {
                'r' { Write-Info "Retrying: $($StepTitle[$step])" }
                's' { Write-Warn "Skipping '$($StepTitle[$step])' at your request - later steps may fail because of it."; Set-StepState $step 'skipped'; $script:CurrentStep = '' }
                default { Write-Host ''; Write-Info "Stopped. Progress is saved - fix the cause, then re-run this script to resume at: $($StepTitle[$step])"; Write-Info "Log: $($script:LogFile)"; throw [System.OperationCanceledException]'stopped' }
            }
            if ($c -eq 's') { break }
        }
        if ($PauseBetweenSteps -and $script:Interactive -and $step -ne $list[-1]) {
            $c = Read-Choice '  [Enter] continue to the next step   [q] pause here (resume later by re-running)' 'cq' 'c'
            if ($c -eq 'q') { Write-Info "Paused after '$($StepTitle[$step])'. Re-run the script to continue."; throw [System.OperationCanceledException]'paused' }
        }
    }
}
function Test-AllDone { foreach ($s in $Steps) { if ((Get-StepState $s) -notin @('done', 'skipped')) { return $false } }; return $true }

# =============================================================================
#  Operations
# =============================================================================
function Show-Result {
    $fam = Get-ActiveFamily; $name = $script:Conf['AGENT_NAME']; if ($fam -eq 'v2') { $name = $env:COMPUTERNAME }
    Write-Banner 'Result'
    Show-Progress
    Write-Host ''
    $i = Get-Installed; $tag = ''; if ($i) { $tag = $i.Tag }
    Write-Say "  Agent          : $name - $($Families[$fam].Pkg) $tag ($fam)"
    Write-Say "  Gateway        : repository $(Get-RepoUrl '/')   OpAMP $($script:Conf['OPAMP_ENDPOINT'])"
    Write-Say "  Labels         : $($script:Conf['AGENT_LABELS'])"
    Write-Say "  Config / log   : $(Get-ConfPath $fam)  |  $(Get-LogPath $fam)"
    Write-Say "  Service        : Get-Service $($Families[$fam].Svc)"
    Write-Say "  This run's log : $($script:LogFile)"
    Write-Say "  Later          : -Diagnose | -Upgrade [-CollectorVersion TAG] | -Reconfigure | -Uninstall"
}

function Invoke-Install {
    $had = Read-Config
    Set-ArgsIntoConfig
    foreach ($k in $ConfKeys) { $script:OldConf[$k] = $script:Conf[$k] }
    if (-not $had -or $Reconfigure -or -not (Test-ConfigComplete)) {
        if ($had -and -not $Reconfigure) { Write-Info 'Some answers are missing - asking for them now.' }
        if (-not (Read-AllAnswers)) { Write-Err 'The answers were not completed - nothing was changed.'; throw [System.OperationCanceledException]'answers' }
        Write-Banner 'Summary'; Show-Config; Write-Host ''
        if (-not (Read-YesNo 'Proceed with these answers?' 'y')) { Write-Info 'Stopped before making changes.'; return }
        Save-Config; Write-Ok "Answers saved to $ConfFile (SYSTEM/Administrators only; the secret key is not stored there)"
    }
    else {
        Write-Banner "Using saved answers ($ConfFile)"; Show-Config
        Write-Say '  (run with -Reconfigure to change any of them)'
        if ($script:Interactive -and -not (Read-YesNo 'Continue with these values?' 'y')) {
            if (-not (Read-AllAnswers)) { Write-Err 'The answers were not completed - nothing was changed.'; throw [System.OperationCanceledException]'answers' }
            Write-Banner 'Summary'; Show-Config
            if (-not (Read-YesNo 'Proceed with these answers?' 'y')) { Write-Info 'Stopped before making changes.'; return }
            Save-Config; Write-Ok 'Answers saved'
        }
    }
    if ($had) {
        $changed = @()
        foreach ($k in $Depends.Keys) {
            if ($script:OldConf[$k] -eq $script:Conf[$k]) { continue }
            $changed += $k
            foreach ($s in $Depends[$k]) { if ((Get-StepState $s) -in @('done', 'skipped')) { Set-StepState $s 'pending' } }
        }
        if ($changed.Count -gt 0) { Write-Info "Changed: $($changed -join ' ') - dependent steps will run again." }
    }
    $list = $Steps
    if ($Only) { $list = @($Only); $script:Forced[$Only] = $true }
    elseif ($From) { $list = @($Steps[[array]::IndexOf($Steps, $From)..($Steps.Count - 1)]); foreach ($s in $list) { $script:Forced[$s] = $true } }
    if ($Reinstall) { foreach ($s in @('download', 'verify', 'install', 'configure', 'start', 'connect')) { if ((Get-StepState $s) -eq 'done') { Set-StepState $s 'pending' } } }
    Write-Banner 'Progress'; Show-Progress
    if (-not $Only -and -not $From -and (Test-AllDone) -and -not $Reconfigure) {
        Write-Host ''; Write-Ok 'Every step is already complete - the agent is installed and connected.'
        Write-Hint 'Health check: -Diagnose | upgrade: -Upgrade | change answers: -Reconfigure'
        return
    }
    $needSecret = ($Reconfigure -or $script:Forced['configure'] -or ((Get-StepState 'configure') -ne 'done'))
    if ($Only -and $Only -ne 'configure') { $needSecret = $false }
    if ($needSecret) {
        $oldKey = Get-ConfValue 'secret_key'
        if (-not (Confirm-Secret)) { Write-Block 'Problem' $script:FailWhat; Write-Block 'How to fix' $script:FailFix; throw [System.OperationCanceledException]'secret' }
        if ($oldKey -and $script:Secret -ne $oldKey) {
            foreach ($s in @('configure', 'start', 'connect')) { if ((Get-StepState $s) -eq 'done') { Set-StepState $s 'pending' } }
            Write-Info 'The secret key changed - the configure, start and connect steps run again'
        }
    }
    Invoke-Steps $list
    Show-Result
}

function Invoke-Upgrade {
    if (-not (Read-Config)) { Write-Err 'This host has no saved answers yet - run the installer without -Upgrade first.'; throw [System.OperationCanceledException]'noconf' }
    $target = ''; if ($CollectorVersion) { $target = $CollectorVersion; if ($target -notlike 'v*') { $target = "v$target" } }
    $CollectorVersionSaved = $script:Conf['BP_VERSION']
    Set-ArgsIntoConfig
    $script:Conf['BP_VERSION'] = $CollectorVersionSaved
    Write-Banner "Offline upgrade from the gateway $(Get-RepoUrl '/')"
    $script:RepoSums = $null; $r = Import-RepoIndex
    if (-not $r.Ok) { Set-RepoFail $r 'SHA256SUMS'; Write-Block 'Problem' $script:FailWhat; Write-Block 'How to fix' $script:FailFix; throw [System.OperationCanceledException]'repo' }
    $vers = @(Get-RepoVersions)
    $i = Get-Installed; $inst = ''; $fam = Get-FamilyOfTag $script:Conf['BP_VERSION']; if ($i) { $inst = $i.Tag; $fam = $i.Family }
    if (-not $target) {
        $c = @($vers | Where-Object { (Get-FamilyOfTag $_) -eq $fam })
        $stable = @($c | Where-Object { -not (Test-PreRelease $_) })
        if ($stable.Count -gt 0) { $target = $stable[0] } elseif ($c.Count -gt 0) { $target = $c[0] }
        Write-Info "Newest $fam version on the gateway for this host: $(if ($target) { $target } else { 'none' }) (installed: $(if ($inst) { $inst } else { 'none' }))"
    }
    if (-not $target) { Write-Err "The gateway has no Windows MSI for this host: $($vers -join ' ')"; throw [System.OperationCanceledException]'none' }
    if ($vers -notcontains $target) { Write-Err "$target is not on the gateway for this host. Available: $($vers -join ' ')"; throw [System.OperationCanceledException]'missing' }
    if ($target -eq $inst) { Write-Ok "$inst is already installed - nothing to do"; Write-Hint "Other versions on the gateway: $($vers -join ' ')"; return }
    if ((Get-FamilyOfTag $target) -ne $fam) {
        Write-Warn "$target is a $($Families[(Get-FamilyOfTag $target)].Label) release - this REPLACES the $fam collector on this host."
        if (-not $script:Interactive -and -not $AllowFamilySwitch) { Write-Err 'An unattended family switch needs -AllowFamilySwitch'; throw [System.OperationCanceledException]'switch' }
    }
    if (-not (Read-YesNo "Change $(if ($inst) { $inst } else { '<none>' }) -> ${target}?" 'y')) { Write-Info 'Nothing changed.'; return }
    if (-not (Confirm-Secret)) { Write-Block 'Problem' $script:FailWhat; Write-Block 'How to fix' $script:FailFix; throw [System.OperationCanceledException]'secret' }
    if ((Get-FamilyOfTag $target) -eq 'v1' -and -not $script:Conf['AGENT_NAME']) { $script:Conf['AGENT_NAME'] = $env:COMPUTERNAME }
    $script:Conf['BP_VERSION'] = $target; Save-Config
    foreach ($s in @('gateway', 'download', 'verify', 'install', 'configure', 'start', 'connect')) { Set-StepState $s 'pending' }
    Invoke-Steps $Steps
    Show-Result
}

function Invoke-Uninstall {
    [void](Read-Config); Set-ArgsIntoConfig
    Write-Banner "Uninstall the Bindplane collector from $env:COMPUTERNAME"
    $i = Get-Installed
    if (-not $i) { Write-Ok 'No collector is installed on this host' }
    elseif (Read-YesNo "Remove $($i.Name) $($i.Tag)?" 'y') {
        foreach ($c in $i.AllCodes) { if (-not (Uninstall-Product $c $i.Name)) { Write-Block 'Problem' $script:FailWhat; Write-Block 'Likely cause' $script:FailWhy; Write-Block 'How to fix' $script:FailFix; throw [System.OperationCanceledException]'uninstall' } }
        if ((Test-Path $i.Dir) -and $i.Dir -match '^[A-Za-z]:\\.+\\.+' ) {
            if (Read-YesNo "Also delete $($i.Dir) (configuration with the secret key, agent identity, queued telemetry)?" 'y') { Remove-Item -Recurse -Force $i.Dir; Write-Ok "Deleted $($i.Dir)" }
            else { Write-Warn "Kept $($i.Dir) - it may still hold the secret key" }
        }
        Write-Hint 'The agent now shows as disconnected in the console - delete it there (Agents).'
    }
    foreach ($f in @($ProgressFile, $RestartFlag, $VerifyFile, $LogMarkFile)) { Remove-Item -Force $f -ErrorAction SilentlyContinue }
    Write-Ok "Progress cleared ($ProgressFile)"
    if ((Test-Path $CacheDir) -and (Read-YesNo "Delete the downloaded MSIs in ${CacheDir}?" 'y')) { Get-ChildItem $CacheDir | Remove-Item -Force -Recurse; Write-Ok 'Cache emptied' }
    if ((Test-Path $ConfFile) -and (Read-YesNo "Forget the saved answers too ($ConfFile)?" 'n')) { Remove-Item -Force $ConfFile; Get-ChildItem $Root -Filter '*.bak-*' | Remove-Item -Force; Write-Ok 'Answers and configuration backups removed' }
}

function Invoke-Status {
    if (-not (Read-Config)) { Write-Info "No saved answers yet ($ConfFile)" }
    Set-ArgsIntoConfig
    Write-Banner 'Saved answers'; Show-Config
    Write-Banner 'Progress'; Show-Progress
    Write-Banner 'Collector service'
    $i = Get-Installed
    if (-not $i) { Write-Say '  not installed' }
    else {
        $s = Get-Service $Families[$i.Family].Svc -ErrorAction SilentlyContinue
        Write-Say "  $($i.Name) $($i.Tag) - service $($Families[$i.Family].Svc): $(if ($s) { $s.Status } else { 'missing' })"
        if ($script:Conf['OPAMP_ENDPOINT']) { $c = Get-OpampSession; Write-Say "  OpAMP session: $(if ($c) { $c } else { 'none' }) -> $(Get-OpampHost):$(Get-OpampPort)" }
        if (Test-Path $VerifyFile) { Write-Say "  Last verification: $(([IO.File]::ReadAllLines($VerifyFile)) -join ' ')" }
    }
}

function Show-Usage {
    @"
$ScriptName v$ScriptVersion - NCINGA internal: offline Bindplane agent install for Windows log sources (Stage 9)

Usage (elevated PowerShell):  powershell -ExecutionPolicy Bypass -File .\bp-agent-install-windows.ps1 [options]

Install (default): asks for the gateway, lists the MSI versions it holds for this host, asks for the
secret key and labels, then downloads, verifies, installs, configures, starts and checks the agent.
Re-running resumes at the first unfinished step; completed steps are skipped.

Answers (also usable unattended with -Unattended):
  -Gateway IP[:PORT]        the gateway of this segment (repository on :$RepoPortDefault unless PORT is given)
  -Endpoint URL             OpAMP endpoint (default ws://<gateway>:$OpampPortDefault/v1/opamp)
  -CollectorVersion TAG     e.g. v1.109.0 or v2.0.1-beta.6 (default: the gateway's default)
  -Labels "k=v,..."         all labels, e.g. site=primary,segment=prod-live,zone=web,os=windows,role=source
  -Zone NAME                only the zone label (site and segment are derived from the gateway)
  -AgentName NAME           v1 agent name (default: the computer name)
  -InstallDir PATH          install folder (default: C:\Program Files\observIQ OpenTelemetry Collector)
  -SecretFile PATH          read the secret key from a protected file (or set BP_SECRET in the environment;
                            -SecretKey KEY works too, but command lines are visible to other processes)
  -AllowFamilySwitch        unattended: allow replacing a v1 collector with v2 or the reverse

Run control:
  -Reconfigure              ask every question again (previous answers are the defaults)
  -From STEP | -Only STEP   re-run from / just one step      -ListSteps   the step names
  -Reinstall                install the same version again (repairs a damaged installation)
  -PauseBetweenSteps        pause between steps
  -Unattended (-Yes)        no questions: saved/default answers; stop at the first failure

Verification:
  -SkipSignatureCheck       accept checksum-only verification (no Authenticode check)
  -TrustedSigner TEXT       expected signer certificate subject part (default: '$TrustedSigner')

Operations:
  -Status | -Diagnose | -Upgrade [-CollectorVersion TAG] | -Uninstall | -Reset | -NoColor | -Help | -ShowVersion

Files: $Root  (answers agent.conf, progress, cache\, logs\ incl. the MSI logs; SYSTEM/Administrators only)
The secret key is never stored by this script and never passed to msiexec - only written into the collector's config.

(c) 2026 NCINGA. All rights reserved. NCINGA internal - proprietary and confidential; see the header.
"@ | Write-Host
}

# =============================================================================
#  Main
# =============================================================================
function Invoke-Main {
    if ($ShowVersion) { Write-Host "$ScriptName $ScriptVersion"; return }
    if ($Help) { Show-Brand "$ScriptName v$ScriptVersion - offline agent install (Windows)"; Show-Usage; return }
    if ($From -and $Steps -notcontains $From) { throw "Unknown step '$From'. Steps: $($Steps -join ' ')" }
    if ($Only -and $Steps -notcontains $Only) { throw "Unknown step '$Only'. Steps: $($Steps -join ' ')" }
    if ($Gateway) { $m = & $VHost $Gateway; if ($m) { throw "-Gateway: $m" } }
    if ($Endpoint) { $m = & $VEndpoint $Endpoint; if ($m) { throw "-Endpoint: $m" } }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This script must run as Administrator. Re-run it from an elevated PowerShell prompt (Run as administrator).' }
    $script:Interactive = (-not $Unattended) -and [Environment]::UserInteractive
    try { if ([Console]::IsInputRedirected) { $script:Interactive = $false } } catch { }
    $script:Arch = Get-ArchName
    Initialize-StateDir
    $action = 'install'
    if ($Status) { $action = 'status' } elseif ($Diagnose) { $action = 'diagnose' } elseif ($Upgrade) { $action = 'upgrade' } elseif ($Uninstall) { $action = 'uninstall' } elseif ($Reset) { $action = 'reset' } elseif ($ListSteps) { $action = 'list' }
    $script:LogFile = Join-Path $LogDir "run-$($script:RunTs)-$action.log"
    [IO.File]::WriteAllText($script:LogFile, '')
    $mutex = New-Object Threading.Mutex($false, 'Global\NCINGA-bp-agent-install')
    $owned = $false
    try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { throw 'Another run of this installer is in progress on this host. Wait for it to finish.' }
    try {
        Show-Brand "$ScriptName v$ScriptVersion - offline agent install for Windows log sources (Stage 9)"
        Write-Say "  Host: $env:COMPUTERNAME   Arch: $($script:Arch)   Collector here: $(Get-InstalledSummary)"
        Write-Say "  Action: $action   Log: $($script:LogFile)"
        Write-RunLog "args: $($PSBoundParameters.Keys -join ' ') interactive=$($script:Interactive)"
        switch ($action) {
            'install'   { Invoke-Install }
            'upgrade'   { Invoke-Upgrade }
            'uninstall' { Invoke-Uninstall }
            'status'    { Invoke-Status }
            'diagnose'  { [void](Read-Config); Set-ArgsIntoConfig; Invoke-Diagnostics }
            'reset'     { foreach ($f in @($ProgressFile, $RestartFlag)) { Remove-Item -Force $f -ErrorAction SilentlyContinue }; Write-Ok "Step progress forgotten (answers kept in $ConfFile)" }
            'list'      { $n = 0; foreach ($s in $Steps) { $n++; Write-Host ('  {0,2}. {1,-10} {2}' -f $n, $s, $StepTitle[$s]) } }
        }
    }
    finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        $script:Secret = ''
    }
}

# ---- Entry point -------------------------------------------------------------------
# As in the vendor's installer: errors are thrown and caught here, so an interactive window is not
# closed by 'exit'; a real exit code is set only when the script runs as a file (-File / .\script.ps1).
$exitCode = 0
try { Invoke-Main }
catch [System.OperationCanceledException] { $exitCode = 1 }
catch {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    if ($script:LogFile) { Write-RunLog "FATAL $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)"; Write-Host "       Log: $($script:LogFile)" }
    $exitCode = 1
}
if ($PSCommandPath) { exit $exitCode }