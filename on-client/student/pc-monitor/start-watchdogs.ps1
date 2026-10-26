# 워치독스의 로컬 PC 상태 읽기 전용 동반 화면 실행.
# 관리자 권한 상승, 시스템 보안 설정 변경, 자동 조회는 수행하지 않습니다.
param([ValidateRange(1024,65535)][int]$Port=5191)
$ErrorActionPreference='Stop'
if($Port -eq 5189){throw "기존 보안 Agent 포트 5189와 겹칠 수 없습니다."}
$node=Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if(-not $node){throw "Node.js를 찾지 못했습니다. Node.js 24.19.0을 준비하세요."}
$version=(& $node.Source --version | Out-String).Trim()
if($version -ne "v24.19.0"){
  throw "검수·이식 기준은 Node.js v24.19.0입니다(현재 $version). 기존 설치를 제거하지 않고 해당 PowerShell 세션에서 버전을 선택하세요."
}
$dir=Split-Path -Parent $MyInvocation.MyCommand.Path
$env:WATCHDOGS_MONITOR_PORT=[string]$Port
Set-Location $dir
& $node.Source (Join-Path $dir "server.mjs")
