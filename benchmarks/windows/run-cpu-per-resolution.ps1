<#
.SYNOPSIS
  Windows에서 해석당 CPU를 재고, 그 값을 믿어도 되는지 함께 보고한다.

.DESCRIPTION
  이 호스트의 UDP 루프백에는 서버와 무관한 천장이 있다. DNS 처리를 전혀 하지 않는
  에코 서버도 같은 천장에 부딪힌다. 그래서 QPS로는 DNS 서버의 개선을 판정할 수 없다 —
  천장이 서버보다 훨씬 낮으면 무엇을 고쳐도 숫자가 안 움직인다.

  판정 가능한 축은 해석당 user CPU다. 벽시계가 아니라 프로세스가 실제로 태운 CPU를
  처리한 질의 수로 나누므로, 부하가 천장에 막혀 있어도 "질의 하나를 처리하는 비용"은
  그대로 드러난다.

  그래서 이 하네스는 매번 두 가지를 같이 낸다.
    1) 바닥값 — 에코 서버로 잰 이 호스트의 UDP 왕복 한계. 측정 환경의 성질이다.
    2) 해석당 user CPU — 서버의 값. 중앙값과 산포를 내고 게이트로 판정한다.
  바닥값을 같이 보고하지 않으면 "QPS가 안 올랐다"를 서버 탓으로 잘못 읽게 된다.

  부하 발생기는 tools/dnsload(std만 씀)다. dnsperf는 윈도우에 없고, WSL에서 가상
  스위치를 건너면 경로가 초당 1만에서 막혀 서버가 아니라 스위치를 재게 된다.

.EXAMPLE
  powershell -File benchmarks/windows/run-cpu-per-resolution.ps1 -Rounds 5 -Seconds 30
#>
[CmdletBinding()]
param(
    [string]$Workdir = "$env:TEMP\onetdns-winbench",
    [string]$Binary = "target\release\onetdns.exe",
    [int]$Port = 15353,
    [int]$EchoPort = 15354,
    # 0이면 기존 off/on 웹 기본값 비교를 유지한다. 두 바이너리에서 텔레메트리를 명시적으로
    # 켜 같은 코드 경로를 비교할 때는 실행 중 서비스와 겹치지 않는 loopback 포트를 준다.
    [int]$ControlPort = 0,
    [int]$Owners = 20000,
    [int]$Rounds = 5,
    [int]$Seconds = 30,
    [int]$Threads = 4,
    [int]$Outstanding = 32,
    [int]$Workers = 1,
    [double]$DriftGate = 5.0,
    # A/B. 이 호스트는 절대값 산포가 커서 축 하나만으로는 판정이 안 된다. 같은 라운드
    # 안에서 두 팔을 번갈아 재고 그 비율만 인용하면 창의 열화가 양쪽에 같이 실려 상쇄된다.
    [string]$BinaryB = "",
    [string]$ArgsA = "--no-web",
    [string]$ArgsB = "--no-web"
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path

<# 표본의 중앙값과 산포. 산포는 (max-min)/median 이다. #>
function Get-MedianAndDrift([double[]]$samples) {
    $sorted = $samples | Sort-Object
    $n = $sorted.Count
    if ($n % 2 -eq 1) { $median = $sorted[[int](($n - 1) / 2)] }
    else { $median = ($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2 }
    if ($median -le 0) { return @{ Median = 0.0; Drift = 100.0 } }
    return @{ Median = $median; Drift = ($sorted[$n - 1] - $sorted[0]) * 100.0 / $median }
}

<# 부하를 한 번 넣고 (완료 수, QPS)를 돌려준다. #>
function Invoke-Load([string]$loader, [string]$target, [string]$queries, [int]$seconds, [int]$threads, [int]$outstanding) {
    $text = & $loader -s $target -d $queries -l $seconds -T $threads -c $outstanding | Out-String
    if ($text -notmatch 'Queries completed:\s+(\d+)') { throw "완료 수를 찾지 못했습니다:`n$text" }
    $completed = [double]$Matches[1]
    if ($text -match 'Queries per second:\s+([\d.]+)') { $rate = [double]$Matches[1] } else { $rate = 0.0 }
    return @{ Completed = $completed; Qps = $rate }
}

<# 포트가 열릴 때까지 기다린다. #>
function Wait-Udp([int]$port) {
    foreach ($i in 1..40) {
        if (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

$exe = Join-Path $repo $Binary
if (-not (Test-Path $exe)) { throw "바이너리가 없습니다: $exe  (cargo build --release -p onetdns)" }

$loader = Join-Path $repo 'tools\dnsload\target\release\onetdns-dnsload.exe'
if (-not (Test-Path $loader)) {
    Push-Location (Join-Path $repo 'tools\dnsload')
    try { cargo build --release | Out-Null } finally { Pop-Location }
}
if (-not (Test-Path $loader)) { throw "부하 발생기를 빌드하지 못했습니다: $loader" }

if (-not (Test-Path $Workdir)) { New-Item -ItemType Directory -Force $Workdir | Out-Null }
$zone = Join-Path $Workdir 'db.bench.test'
$queries = Join-Path $Workdir 'queries-auth.txt'
if ((-not (Test-Path $zone)) -or (-not (Test-Path $queries))) {
    $drive = $Workdir.Substring(0, 1).ToLower()
    $wslWork = "/mnt/$drive" + ($Workdir.Substring(2) -replace '\\', '/')
    $gen = "/mnt/" + $repo.Substring(0, 1).ToLower() + ($repo.Substring(2) -replace '\\', '/') + "/benchmarks/dns-authority/generate-zone.sh"
    wsl -d Ubuntu -- sh "$gen" "$wslWork" "$Owners" | Out-Null
}
if (-not (Test-Path $queries)) { throw "질의 목록을 만들지 못했습니다: $queries" }

# 1단계: 이 호스트의 바닥값. DNS 처리가 0인 서버도 못 넘는 한계다.
$echo = Start-Process -FilePath $loader -ArgumentList '--serve-echo', $EchoPort, $Threads -PassThru -WindowStyle Hidden
try {
    if (-not (Wait-Udp $EchoPort)) { throw "에코 서버가 $EchoPort 를 열지 못했습니다." }
    $floor = Invoke-Load $loader "127.0.0.1:$EchoPort" $queries 5 $Threads $Outstanding
}
finally {
    if (-not $echo.HasExited) { Stop-Process -Id $echo.Id -Force -ErrorAction SilentlyContinue }
}

$config = Join-Path $Workdir 'onetdns-auth.toml'
$zoneForToml = $zone -replace '\\', '/'
$controlConfig = if ($ControlPort -gt 0) {
    "control_listen = `"127.0.0.1:$ControlPort`"`ncontrol_token = `"onetdns-windows-bench-token-0001`""
} else { "" }
@"
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:$Port"]
$controlConfig
workers = $Workers
do_udp = true
do_tcp = false
cache_enabled = false
querylog = false
zones = [
  { origin = "bench.test", file = "$zoneForToml" },
]
"@ | Set-Content -Path $config -Encoding utf8

if ([string]::IsNullOrWhiteSpace($BinaryB)) { $exeB = $exe } else { $exeB = Join-Path $repo $BinaryB }
if (-not (Test-Path $exeB)) { throw "B팔 바이너리가 없습니다: $exeB" }

<#
 팔 하나를 세운 뒤 부하를 넣고 해석당 user CPU를 잰다.
 서버는 레그마다 새로 띄운다. 한 프로세스로 두 팔을 재려면 인자를 바꿀 수 없다.
#>
function Measure-Arm([string]$binary, [string]$extra, [string]$tag) {
    $argv = New-Object System.Collections.Generic.List[string]
    # Under a supervisor this PID would be the parent, and the worker's CPU would go unmeasured.
    $argv.AddRange([string[]]@('run', '--config', $config, '--no-supervisor'))
    foreach ($piece in ($extra -split '\s+')) { if ($piece) { $argv.Add($piece) } }

    $proc = Start-Process -FilePath $binary -ArgumentList $argv.ToArray() `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Workdir "server-$tag.log") `
        -RedirectStandardError (Join-Path $Workdir "server-$tag.err")
    try {
        if (-not (Wait-Udp $Port)) { throw "포트 $Port 바인딩 실패. $Workdir\server-$tag.err 를 보십시오." }
        # 콜드 페이지 폴트와 존 워밍을 이 레그에 몰아 버린다.
        Invoke-Load $loader "127.0.0.1:$Port" $queries 4 $Threads $Outstanding | Out-Null

        $before = (Get-Process -Id $proc.Id).UserProcessorTime.TotalSeconds
        $leg = Invoke-Load $loader "127.0.0.1:$Port" $queries $Seconds $Threads $Outstanding
        $after = (Get-Process -Id $proc.Id).UserProcessorTime.TotalSeconds
        if ($leg.Completed -le 0) { throw "완료된 질의가 없습니다. ACL이나 포트를 확인하십시오." }
        return @{
            Cpu       = ($after - $before) * 1e6 / $leg.Completed
            Qps       = $leg.Qps
            Completed = $leg.Completed
        }
    }
    finally {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
}

$cpuA = New-Object System.Collections.Generic.List[double]
$cpuB = New-Object System.Collections.Generic.List[double]
$ratios = New-Object System.Collections.Generic.List[double]
$qpsA = New-Object System.Collections.Generic.List[double]

foreach ($round in 1..$Rounds) {
    # 순서를 라운드마다 뒤집는다. 창이 시간에 따라 열화하면 먼저 재는 팔이 유리해진다.
    if ($round % 2 -eq 1) {
        $a = Measure-Arm $exe $ArgsA 'a'
        $b = Measure-Arm $exeB $ArgsB 'b'
    }
    else {
        $b = Measure-Arm $exeB $ArgsB 'b'
        $a = Measure-Arm $exe $ArgsA 'a'
    }
    $cpuA.Add($a.Cpu); $cpuB.Add($b.Cpu); $qpsA.Add($a.Qps)
    $ratios.Add($b.Cpu / [math]::Max($a.Cpu, 1e-9))
    "라운드 {0}: A {1,7:N3} us   B {2,7:N3} us   B/A {3,6:N3}   QPS(A) {4,7:N0}" -f `
        $round, $a.Cpu, $b.Cpu, ($b.Cpu / [math]::Max($a.Cpu, 1e-9)), $a.Qps | Write-Host
}

$statA = Get-MedianAndDrift $cpuA.ToArray()
$statB = Get-MedianAndDrift $cpuB.ToArray()
$statR = Get-MedianAndDrift $ratios.ToArray()
$statQ = Get-MedianAndDrift $qpsA.ToArray()
$verdict = { param($drift) if ($drift -le $DriftGate) { '판정 가능' } else { "게이트 $DriftGate% 초과 — 인용 금지" } }

Write-Host ""
Write-Host ("측정 환경 바닥값 (DNS 처리 0인 에코 서버): {0:N0} QPS" -f $floor.Qps)
Write-Host ("  A팔 QPS는 바닥값의 {0:P0}. 100% 근처면 서버가 아니라 이 호스트의 UDP 경로가 천장이다." -f ($statQ.Median / [math]::Max($floor.Qps, 1)))
Write-Host ""
Write-Host ("결과 (라운드 {0} · 레그 {1}초 · 워커 {2} · 스레드 {3} · 미회수 {4})" -f $Rounds, $Seconds, $Workers, $Threads, $Outstanding)
Write-Host ("  A = '{0}'  해석당 user CPU {1,7:N3} us   산포 {2,6:N2}%" -f $ArgsA, $statA.Median, $statA.Drift)
Write-Host ("  B = '{0}'  해석당 user CPU {1,7:N3} us   산포 {2,6:N2}%" -f $ArgsB, $statB.Median, $statB.Drift)
Write-Host ("  B/A 비율     : {0,8:N3}      산포 {1,6:N2}%  {2}" -f $statR.Median, $statR.Drift, (& $verdict $statR.Drift))
Write-Host ("  절대값 산포가 게이트를 넘어도 비율 산포가 통과하면 그 비율만 인용한다.")
