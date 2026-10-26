# 워치독스 · 내 PC 측정 화면 설치·사용 안내 (2~5일차)

> 기존 보안 Agent의 로컬 5189번 화면은 그대로 두고, 일반 사용자 권한의 **별도 읽기 전용 측정 화면(5191)**을 추가합니다. 새 Windows 실측은 사용자가 직접 실행하기 전까지 **미확인**입니다. 운영 자격·원본 데이터·기존 제출물은 수정하거나 복사하지 않습니다.

## 준비

Windows 10/11과 Windows PowerShell 5.1, Node.js **v24.19.0**. 관리자 권한 상승이 필요하지 않으며, 설치되지 않은 보안 구성요소를 우회해 구현하지 않습니다. 추가 npm 패키지를 설치할 필요가 없습니다.

소스 경로: `D:\share\choi-bujang-secret-vault\on-client\student\pc-monitor`. 해당 경로는 이 PC에서 확인된 경로 예시이고, 다른 PC에서는 새 체크아웃 경로에 맞게 변경합니다. 기존 원본 폴더에서 `M public/data.json` 상태를 보존합니다.

## 실행 순서

**1. Git 최신 소스를 보존하며 동기화**(기존 폴더에 미커밋 작업이 있으므로 강제 reset 금지).

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault"
git status --short
git fetch origin main
git merge --ff-only origin/main
git status --short
~~~

**2. 별도 PowerShell 창에서 Node.js 24.19.0을 해당 세션에만 적용하고 실행.**

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault\on-client\student\pc-monitor"
$node24 = (& npx --yes node@24.19.0 -p "process.execPath" | Select-Object -Last 1).Trim()
if (-not (Test-Path -LiteralPath $node24)) { throw "Node.js 24.19.0 실행 파일 없음" }
$env:Path = "$(Split-Path -Parent $node24);$env:Path"
if ((node --version).Trim() -ne "v24.19.0") { throw "Node 버전 확인 필요" }
powershell -NoProfile -ExecutionPolicy Bypass -File ".\start-watchdogs.ps1"
~~~

출력의 `http://127.0.0.1:5191/`을 본인 브라우저에서 직접 엽니다. 자동 수집은 없고 **각 「다시 조회」 버튼을 눌렀을 때만** Windows 데이터를 읽습니다. 종료는 실행 PowerShell의 `Ctrl+C`. PC 정책·방화벽·이벤트 로그는 절대 수정하지 않습니다.

**3. 기존 보안 Agent도 필요할 경우 다른 PowerShell에서 별도로 실행**(이미 5189 서버가 켜져 있으면 또 시작하지 않음).

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault\on-client"
node --version  # v24.19.0 확인
powershell -NoProfile -ExecutionPolicy Bypass -File ".\tools\start-alekov.ps1"
~~~

## 값의 실제 출처

| 항목 | Windows 조회 API/명령 | 표시 단위·의미 |
|---|---|---|
| CPU | `GET /api/pc` → `Win32_Processor.LoadPercentage` | % · WMI 순간 스냅샷, 작업 관리자와 시각/집계 범위 차이 가능 |
| 메모리 | `Win32_OperatingSystem.TotalVisibleMemorySize/FreePhysicalMemory` | GiB · 사용 중 / 전체 |
| 디스크 여유 | `Win32_LogicalDisk.FreeSpace` (고정 시스템 드라이브 우선) | GiB · 남은 공간 |
| 네트워크 | `GET /api/network` → `Get-NetAdapter -Physical` | 연결된 물리 어댑터 개수(인터넷 성공 의미 아님) |
| 방화벽 | `Get-NetFirewallProfile` | Domain/Private/Public별 켜짐·꺼짐 · **읽기만 함** |
| Windows 기록 | `Get-WinEvent`, System/Application, Level 2·3, 최근 24시간 | 경고/오류 건수 · **침해 탐지 아님** |
| SDP | `GET /api/sdp` → 기존 보안 Agent `GET /api/diagnostics` | SDP 미연결·예제·어댑터 구성됨·확인 불가. Windows PC 조회와 구분 |

각 항목은 출처·측정 시각(UTC에서 브라우저 현지 시각으로 변환)·단위를 표시합니다. 이벤트 로그는 **로그별 최대 1000건**을 읽고 그 이상이면 표본/부분 조회로 분리하므로 전체 건수로 주장하지 않습니다. 최근 5회 값은 **브라우저 탭 메모리만 사용**하며 새로 열면 사라집니다. 임의 예제 숫자, 이벤트 메시지 전문, 키·토큰, MAC·IP·계정명은 표시하지 않습니다.

## 실패·권한 부족

| 코드/현상 | 원인·다음 행동 |
|---|---|
| `WINDOWS_ONLY` | 다른 OS에선 계측 불가. Windows에서 실행 |
| `READER_UNAVAILABLE` / `MEASURE_FAILED` | PowerShell/WMI 접근 불가. 관리자 권한 우회하지 않고 명령 이용 가능 여부를 확인 |
| `MEASURE_TIMEOUT` | 실측 시간 초과. 읽기 권한과 항목을 확인한 뒤 직접 다시 조회 |
| `INVALID_MEASUREMENT` | 응답 계약 불일치. 수치를 버리고 확인 불가 |
| `SDP_NOT_AVAILABLE` | 기존 5189 서버가 없거나 응답하지 않음. Windows 조회 성공과 구분 |
| `ENGINE_NOT_CONNECTED` | 원천 보안 엔진 미연결. PC 측정 자체는 별도 |
| System/Application partial | 조회 상한 도달. 개별 경고·오류 숫자는 표본이고 전체 건수는 확인 불가 |

## 4~5일차 직접 확인 순서

1. 5191 UI에서 **조회 전**인지 확인하고 CPU 새로 조회 → 단위·시각·출처를 확인합니다.
2. CPU 재조회가 두 번 이상 성공하면 최근 측정 비교가 실제 샘플만 사용했는지 봅니다.
3. 네트워크·방화벽의 **다시 조회** → 이벤트 필터 System/Application 전환. Windows 경고·오류는 공격·침해 판정이 아님을 확인합니다.
4. SDP가 꺼져 있으면 「확인 불가」, 기본 미연결 앱이 켜져 있으면 「SDP 미연결」로 따로 표시되는지 확인합니다.
5. 관리자 권한이 없어 읽지 못한 값은 「확인 불가」와 이유·다음 행동만 있는지 확인합니다.
6. 종료 `Ctrl+C`. 실행 안내만 보고 제3자가 성공했다는 증거는 아직 **미확인**입니다. 위 순서로 검증한 값을 상대방이 전달하면 기록할 수 있습니다.

**보안 경계:** 로컬 GET만 지원, 서버 `127.0.0.1` 바인딩, 교차 출처/Host 거부, 조회 시각 명시. 기존 제공 `public/app.js`·`src/server.mjs`·계정 연결/조치 집행 코드는 건드리지 않습니다. 5191은 기존 앱과 **별개 학생용 동반 페이지**이며 공식 설치형 앱으로 패키징된 것은 아닙니다.
