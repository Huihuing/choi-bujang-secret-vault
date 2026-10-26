# 워치독스 동반 측정 페이지: 일반 권한, 읽기 전용, 값마다 측정 시각.
# 이 스크립트는 방화벽/서비스/권한을 변경하지 않고 원문 로그를 출력하지 않습니다.
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("pc","network")]
  [string]$Section
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Stamp { return [DateTime]::UtcNow.ToString("o") }
function Missing([string]$source,[string]$reason) {
  return [ordered]@{
    status="unavailable"; value=$null; unit=$null; source=$source;
    measuredAt=(Stamp); reason=$reason; detail=$null
  }
}
function Actual($value,[string]$unit,[string]$source,[string]$detail) {
  return [ordered]@{
    status="ok"; value=$value; unit=$unit; source=$source;
    measuredAt=(Stamp); reason=$null; detail=$detail
  }
}

if ($Section -eq "pc") {
  try {
    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $validCpus = @($cpus | Where-Object { $null -ne $_.LoadPercentage -and [double]$_.LoadPercentage -ge 0 -and [double]$_.LoadPercentage -le 100 })
    if ($validCpus.Count -lt 1) { throw "NO_CPU_SAMPLE" }
    $avg = ($validCpus | Measure-Object -Property LoadPercentage -Average).Average
    $cpu = Actual ([math]::Round([double]$avg,1)) "%" "Win32_Processor.LoadPercentage" "WMI CPU 로드의 당시 스냅샷(작업 관리자 집계와 시간·범위가 다를 수 있음)"
  } catch {
    $cpu = Missing "Win32_Processor.LoadPercentage" "CPU 사용률 조회 실패 · WMI 조회 가능 여부를 확인하세요."
  }
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $total = [double]$os.TotalVisibleMemorySize
    $free = [double]$os.FreePhysicalMemory
    if ($total -le 0 -or $free -lt 0 -or $free -gt $total) { throw "INVALID_MEMORY" }
    $usedGiB = [math]::Round(($total - $free) / 1048576,2)
    $memory = Actual $usedGiB "GiB" "Win32_OperatingSystem.TotalVisibleMemorySize/FreePhysicalMemory" ("사용 중 " + $usedGiB.ToString() + " GiB / 전체 " + [math]::Round($total / 1048576,2) + " GiB")
  } catch {
    $memory = Missing "Win32_OperatingSystem" "메모리 조회 실패 · 일반 사용자 WMI 조회 권한을 확인하세요."
  }
  try {
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop)
    $drive = @($disks | Where-Object { $_.DeviceID -eq $env:SystemDrive } | Select-Object -First 1)
    if ($drive.Count -eq 0) { $drive = @($disks | Select-Object -First 1) }
    if ($drive.Count -eq 0 -or $null -eq $drive[0].FreeSpace -or [double]$drive[0].Size -le 0) { throw "NO_LOGICAL_DISK" }
    $disk = Actual ([math]::Round([double]$drive[0].FreeSpace / 1GB,2)) "GiB" "Win32_LogicalDisk.FreeSpace" ("로컬 고정 드라이브 " + $drive[0].DeviceID + " · 전체 " + [math]::Round([double]$drive[0].Size / 1GB,2) + " GiB")
  } catch {
    $disk = Missing "Win32_LogicalDisk.FreeSpace" "디스크 남은 공간 조회 실패 · 대상 로컬 드라이브 또는 조회 권한을 확인하세요."
  }
  $result = [ordered]@{
    schema="watchdogs.local-monitor.v1"; section="pc"; sampleType="measured";
    queriedAt=(Stamp); fields=[ordered]@{cpu=$cpu;memory=$memory;disk=$disk}
  }
} else {
  try {
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
    $up = @($adapters | Where-Object { $_.Status -eq "Up" })
    if ($adapters.Count -eq 0) { throw "NO_ADAPTERS" }
    $network = Actual $up.Count "개" "Get-NetAdapter -Physical" (
      "물리 어댑터 " + $adapters.Count + "개 중 링크 연결 " + $up.Count +
      "개 · 인터넷 연결/안전성 증명 아님"
    )
  } catch {
    $network = Missing "Get-NetAdapter -Physical" "네트워크 어댑터 정보를 읽을 수 없습니다. 관리자 권한으로 우회하지 않습니다."
  }

  try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $parts = @()
    foreach ($name in @("Domain","Private","Public")) {
      $found = @($profiles | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
      if ($found.Count -eq 0 -or $null -eq $found[0].Enabled) { throw "PROFILE_INCOMPLETE" }
      $enabled = $found[0].Enabled -eq $true
      $parts += ($name + ":" + $(if ($enabled) {"켜짐"} else {"꺼짐"}))
    }
    $firewall = Actual "조회됨" "프로필" "Get-NetFirewallProfile" ($parts -join " / ")
  } catch {
    $firewall = Missing "Get-NetFirewallProfile" "방화벽 프로필을 읽을 수 없습니다. 설정을 바꾸지 않고 확인 불가로 남깁니다."
  }

  $since = (Get-Date).AddHours(-24)
  $logs = [ordered]@{}
  foreach ($logName in @("System","Application")) {
    try {
      $events = @(Get-WinEvent -FilterHashtable @{
        LogName=$logName; Level=@(2,3); StartTime=$since
      } -MaxEvents 1001 -ErrorAction Stop)
      $truncated = $events.Count -gt 1000
      if ($truncated) { $events = @($events | Select-Object -First 1000) }
      $errors = @($events | Where-Object { $_.Level -eq 2 }).Count
      $warnings = @($events | Where-Object { $_.Level -eq 3 }).Count
      $logs[$logName] = [ordered]@{
        status=$(if ($truncated) {"partial"} else {"ok"});
        errorCount=$errors; warningCount=$warnings; sampled=$events.Count;
        limit=1000; windowHours=24; measuredAt=(Stamp); source="Get-WinEvent";
        reason=$(if ($truncated) {"최대 1000개까지만 읽어 전체 건수는 확인 불가"} else {$null})
      }
    } catch {
      $errorId = $_.FullyQualifiedErrorId
      if ($errorId -like "NoMatchingEventsFound*") {
        $logs[$logName] = [ordered]@{
          status="ok"; errorCount=0; warningCount=0; sampled=0;
          limit=1000; windowHours=24; measuredAt=(Stamp); source="Get-WinEvent";
          reason=$null
        }
      } else {
        $logs[$logName] = [ordered]@{
          status="unavailable"; errorCount=$null; warningCount=$null; sampled=$null;
          limit=1000; windowHours=24; measuredAt=(Stamp); source="Get-WinEvent";
          reason="이 로그를 읽을 권한이 없거나 조회에 실패했습니다."
        }
      }
    }
  }
  $result = [ordered]@{
    schema="watchdogs.local-monitor.v1"; section="network"; sampleType="measured";
    queriedAt=(Stamp); fields=[ordered]@{network=$network;firewall=$firewall;logs=$logs}
  }
}
$result | ConvertTo-Json -Depth 8 -Compress
