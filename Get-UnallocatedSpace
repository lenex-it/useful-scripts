<#
.SYNOPSIS
    Detects unallocated (raw/free) space on physical disks.

.DESCRIPTION
    Queries all physical disks via Get-Disk and compares total disk size
    against the sum of partition sizes. Reports any disk with unallocated
    space exceeding the configured threshold (default: 1 MB). Excludes
    removable media (USB, CD/DVD, SD card, FireWire, MMC) but INCLUDES
    VMware virtual disks (SCSI/NVMe) and Hyper-V virtual disks.
    Ends with an [ALERT TRIGGER] log block if unallocated space is found,
    or an INFO message if all disks are clean.
    Designed to run as SYSTEM via Level.io RMM.

.NOTES
    Author  : Lenex IT
    Version : 1.3
    Date    : 2026-03-04
#>

# ============================================================
# CONFIGURATION
# ============================================================
$ThresholdMB = 512          # Minimum unallocated space (MB) to trigger alert
$LogPath     = "C:\ProgramData\Lenex\logs\UnallocatedSpace.log"

# Bus types to exclude — strictly removable/optical media only.
# VMware VMDKs   → BusType: SCSI or NVMe              (INCLUDED)
# Hyper-V vDisks → BusType: Virtual/FileBackedVirtual  (INCLUDED)
$ExcludedBusTypes = @(
    'USB',      # USB flash drives, external HDDs
    'SD',       # SD card readers
    '1394',     # FireWire / i.LINK
    'MMC'       # MultiMediaCard readers
)
# ============================================================

$ErrorActionPreference = 'Stop'

# ── Logging ──────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS','ALERT')]
        [string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts [$Level] $Message"

    $color = switch ($Level) {
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
        'WARNING' { 'Yellow'  }
        'ALERT'   { 'Magenta' }
        default   { 'Cyan'    }
    }
    Write-Host $line -ForegroundColor $color

    try {
        $logDir = Split-Path $LogPath
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line
    } catch {
        Write-Host "WARN: Could not write to log file: $_" -ForegroundColor Yellow
    }
}

function Write-AlertBlock {
    param([array]$AlertEntries)

    $border = "=" * 60
    $lines  = @(
        $border,
        "  [ALERT TRIGGER] UNALLOCATED DISK SPACE DETECTED",
        $border
    )
    foreach ($entry in $AlertEntries) {
        $lines += "  Disk $($entry.Number) | $($entry.FriendlyName) | BusType: $($entry.BusType) | Unallocated: $($entry.UnallocatedMB) MB ($($entry.UnallocatedGB) GB)"
    }
    $lines += $border

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    foreach ($line in $lines) {
        $logLine = "$ts [ALERT] $line"
        Write-Host $logLine -ForegroundColor Magenta
        try { Add-Content -Path $LogPath -Value $logLine } catch {}
    }
}

# ── Admin check ──────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Script must run as Administrator/SYSTEM." 'ERROR'
    exit 1
}

# ── TLS 1.2 (SYSTEM context hygiene) ────────────────────────
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# ── Main logic ───────────────────────────────────────────────
Write-Log "Starting unallocated space detection (threshold: $ThresholdMB MB)." 'INFO'

try {
    $allDisks = Get-Disk | Where-Object { $_.Size -gt 0 }

    $eligibleDisks = $allDisks | Where-Object {
        $busType = $_.BusType

        if ($busType -in $ExcludedBusTypes) {
            Write-Log "Skipping Disk $($_.Number) ($($_.FriendlyName)) — excluded bus type: $busType." 'INFO'
            return $false
        }

        if ($_.IsRemovable -eq $true -and $busType -notin @('SCSI','NVMe','Virtual','FileBackedVirtual','iSCSI','SAS','RAID')) {
            Write-Log "Skipping Disk $($_.Number) ($($_.FriendlyName)) — IsRemovable flag set (BusType: $busType)." 'INFO'
            return $false
        }

        if ($_.MediaType -eq 'CD-ROM') {
            Write-Log "Skipping Disk $($_.Number) ($($_.FriendlyName)) — optical/CD-ROM drive." 'INFO'
            return $false
        }

        return $true
    }

    if (-not $eligibleDisks) {
        Write-Log "No eligible physical disks found after exclusions." 'WARNING'
        Write-Log "No alert trigger required — no eligible disks to evaluate." 'INFO'
        exit 0
    }

    $alertEntries = @()

    foreach ($disk in $eligibleDisks) {
        $diskSizeGB       = [math]::Round($disk.Size / 1GB, 2)
        $partitions       = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
        $allocatedBytes   = ($partitions | Measure-Object -Property Size -Sum).Sum
        if ($null -eq $allocatedBytes) { $allocatedBytes = 0 }
        $unallocatedBytes = $disk.Size - $allocatedBytes
        $unallocatedMB    = [math]::Round($unallocatedBytes / 1MB, 2)
        $unallocatedGB    = [math]::Round($unallocatedBytes / 1GB, 2)

        Write-Log ("Disk {0} ({1}) | BusType: {2} | Total: {3} GB | Allocated: {4} GB | Unallocated: {5} MB" -f `
            $disk.Number,
            $disk.FriendlyName,
            $disk.BusType,
            $diskSizeGB,
            [math]::Round($allocatedBytes / 1GB, 2),
            $unallocatedMB
        ) 'INFO'

        if ($unallocatedMB -ge $ThresholdMB) {
            $alertEntries += [PSCustomObject]@{
                Number        = $disk.Number
                FriendlyName  = $disk.FriendlyName
                BusType       = $disk.BusType
                UnallocatedMB = $unallocatedMB
                UnallocatedGB = $unallocatedGB
            }
        }
    }

    if ($alertEntries.Count -gt 0) {
        Write-AlertBlock -AlertEntries $alertEntries
    } else {
        Write-Log "All eligible disks are fully allocated — no alert trigger required." 'INFO'
    }

    exit 0

} catch {
    Write-Log "Unexpected error: $_" 'ERROR'
    exit 1
}
