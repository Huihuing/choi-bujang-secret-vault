# WATCHDOGS 검증 갱신 · 2026-10-26

검증 시작 당시 기준 커밋 및 확인한 GitHub `main`: `1b876b6fa535a3aff8831b02499fc0bb297fdfd5`.
이 기록은 검증한 소스와 함께 저장한다. 현재 로컬 커밋은 `git log -1 --format=%H`로 확인한다. 푸시·공식 제출·점수 변경은 하지 않았다.
이 문서는 기존 인수인계의 미확인 항목을 갱신하며 과거 13~22단계 기록을 대체하지 않는다.

## 확인 수준

- 기존 구현: 별도 5191 측정 서비스, 항목별 WMI/CIM 조회, Windows 기록 집계, 최근 5회 이력, 타임라인과 필터, SDP 상태 분리.
- 이번 수정: PowerShell 인코딩, 누락 메모리 거부, 조회 상태 구분, 기록 실패 상태 유지, 유선·무선 구성 건수, 학생 서버의 UTF-8/응답 중단 처리, 타임라인 시각 안내.
- 코드·모의 검사: 합성 응답을 사용하는 UI 검사 17개를 Node v24.19.0에서 통과. 실제 WMI를 호출하지 않는 별도 모의 검사에서 누락된 여유 메모리는 `unavailable`/`null`이고 다른 항목은 유지됨을 확인.
- 서버 모의 검사: 같은 Node v24.19.0에서 9개(부모 검사 포함)를 통과. 원천 응답 오류·중단·크기 초과·시간 초과·잘못된 JSON·HTTP 실패 후 안전한 503과 후속 GET 200, SDP 미연결 구분, UTF-8 바이트 경계 보존을 격리된 합성 응답으로 확인했다. 이 검사는 실제 WMI·SDP를 호출하지 않았다.
- 에이전트의 로컬 Windows 직접 확인: 관리자 권한이 아닌 프로세스에서 실제 API를 호출하고, 실제 브라우저에서 Tab·Enter 조회와 이벤트 필터를 조작했다. 사용자가 직접 조작한 결과나 제3자 재현 증거로 기록하지 않는다.
- 미확인: 작업 관리자와 동시 비교, 다른 사용자/PC 재현, 실제 SDP·XDR 운영 자료, 설치·제거, 최종 접수.

## 첫 오류와 수정 결과

기존 5191의 `/api/pc`, `/api/network`가 `MEASURE_FAILED`를 반환했다. Windows PowerShell 5.1.26100.9711 파서에서 수집기 구문 오류 4개가 재현됐고 첫 오류는 121행 `TerminatorExpectedAtEndOfString`이었다. UTF-8 BOM을 추가한 직후 구문 오류가 0개가 되고 실제 API 조회가 성공했다. 시작 스크립트도 한글 안내 보존을 위해 UTF-8 BOM으로 저장했다. 시스템 실행 정책·방화벽·Defender 설정을 변경하지 않았다.

## 실제 API 표본

수정된 서버를 기존 Node v24.19.0으로 별도 5192 포트에서 실행한 표본이다. 기본 5191 서버는 유지했다. 표의 시간은 Asia/Seoul(KST)이며 API는 UTC ISO 시각을 반환한다. 순간 값은 이후 조회마다 달라진다.

| 항목 | 실제 결과 | 측정 시각(KST) | 출처 |
|---|---|---|---|
| CPU 사용률 | 21 % | 2026-10-26 14:49:15.554 | `Win32_Processor.LoadPercentage` |
| 메모리 사용량 | 13.80 GiB / 전체 15.83 GiB | 14:49:15.737 | `Win32_OperatingSystem.TotalVisibleMemorySize/FreePhysicalMemory` |
| 시스템 디스크 여유 | 236.34 GiB | 14:49:15.761 | `Win32_LogicalDisk.FreeSpace` |
| 물리 링크 | 연결 1개 / 전체 1개; 유선 1, 무선 0, 기타·유형 확인 불가 0 | 14:49:17.132 | `Get-NetAdapter -Physical`의 상태·물리 매체 유형 |
| 방화벽 | Domain·Private·Public 모두 켜짐 | 14:49:18.245 | `Get-NetFirewallProfile` |
| System | 경고 4건, 오류 2건 | 14:49:19.098 | `Get-WinEvent`, 최근 24시간, Level 2·3 |
| Application | 경고 3건, 오류 5건 | 14:49:19.157 | 같은 조회 조건 |

이벤트 원문·계정명·IP·MAC·어댑터 이름은 저장하거나 출력하지 않았다. 이 표본은 1000건 제한에 도달하지 않았다. 상한/권한 거부 응답의 UI 표시는 모의 검사로만 확인했으며 실제 권한 변경·대량 이벤트 생성은 하지 않았다. Windows 이벤트 수와 방화벽 설정은 공격 탐지나 PC 안전 판정이 아니다. 5189는 실행되지 않아 SDP 조회는 `SDP_NOT_AVAILABLE`이었다.

## 실제 브라우저 및 HTTP 검사

- Tab으로 PC 버튼에 접근하고 Enter로 조회: `idle → loading → ok`, 실제 값·단위·출처·시각, 버튼 복구 확인.
- 키보드로 네트워크 조회와 System 이벤트 필터 전환 확인. Windows 조회 성공과 SDP 확인 불가가 함께 표시됨을 확인.
- 에이전트가 시작한 임시 5192 서버만 중단해 실제 접속 실패를 만들었다. 화면에 접속 실패 이유·다음 행동을 표시했고, 같은 서버 재시작 후 Enter 재조회로 3개 실제 값이 복구됐다. 사용자 기존 5191 서버는 중단하지 않았다.
- Node v24.19.0 별도 서버에서 실제 HTTP 9개 확인: HTML/CSS/JS 각 200, POST 405, 다른 Origin·교차 사이트·잘못된 Host 각 403, 수집기 파일 직접 접근 및 쿼리 포함 주소 각 404.
- CSS 200은 로컬 서비스 제공 확인이다. 공식 설치 패키지에 CSS가 포함됐다는 증거는 아니다.

임시 5192 검증 서버는 종료했고 기존 5191 서버는 유지했다. HTML/CSS/JS와 수집기는 다음 요청에 현재 파일을 읽지만, `server.mjs` 자체의 응답 중단 처리 변경은 5191을 다음에 재시작할 때 적용된다. 수정된 서버 모듈의 실행은 별도 Node v24.19.0 서버에서 검증했다.

화면 캡처는 저장소 밖의 로컬 작업 결과 폴더 `C:\Users\User\.codex\visualizations\2026\10\26\01a176b7-7a20-7a62-b1fd-82ed39684783\watchdogs`에 보관한다. 공식 제출물에는 넣지 않았다.

캡처 파일: `01-idle.png`, `02-connection-error.png`, `03-recovered-pc.png`, `04-network-events.png`, `05-events-sdp.png`. 복구 화면은 14:50:33 KST의 별도 표본(CPU 18 %, 메모리 13.79 GiB, 디스크 여유 236.33 GiB)이며 위 14:49 API 표본과 구분한다.

## 1~7일차 현재 상태

| 일차 | 이번 확인으로 갱신된 상태 | 남은 조건 |
|---|---|---|
| 1 | 타임라인 구현 유지, 발생 시각/원천 확인 시각 안내 정정 | 실제 XDR 사건 조회·조작 |
| 2 | 로컬 Windows 실제 API와 브라우저 수치 표시 성공 | 작업 관리자와 가까운 시각의 비교, 사용자 직접 확인 |
| 3 | 네트워크·방화벽·이벤트 실측 성공, 매체 유형 건수 표시 | 실제 SDP 연결, 다른 환경 권한 결과 |
| 4 | 초기·로딩·오류·부분 상태 수정, 실제 키보드·오류 후 복구 확인 | 다른 사용자 환경 및 설치형 패키지의 측정 CSS 포함 확인 |
| 5 | 실행 안내 존재, 기존 설치된 Node 24.19.0 확인 | 제3자/새 사용자 계정 독립 재현 |
| 6 | 공식 도구 부재 재확인, 미완료 | 공식 포장 도구·승인 Host·PNG·설치 패키지·Inno 설치/제거 |
| 7 | PC 실측·오류 복구 화면 확보, 시연 자료 일부 준비 | 실제 XDR 시연, 공식 패키지, 승인 후 최종 접수·결과 |

## 변경 파일과 이유

| 파일 | 이유 |
|---|---|
| `on-client/student/pc-monitor/collect.ps1` | PS5.1 인코딩 복구, null 메모리 거부, 식별정보 없는 매체 유형별 건수 |
| `on-client/student/pc-monitor/start-watchdogs.ps1` | PS5.1에서 한글 안내 보존 |
| `on-client/student/pc-monitor/app.js` | 조회 전/로딩/부분/오류 구분, 값·시각 검증, 로그 실패 및 SDP demo 상태 보존 |
| `on-client/student/pc-monitor/index.html`, `style.css` | 초기 상태 문구와 중립 색상/로딩 테두리 |
| `on-client/student/pc-monitor/server.mjs` | UTF-8 조각 누적, SDP 응답 중단 시 안전한 실패 응답 |
| `on-client/student/pc-monitor/app.test.mjs`, `server.test.mjs` | 실측과 구분한 모의 회귀 검사 |
| `on-client/student/extension.mjs`, `student/extension.mjs` | 사건 발생 시각과 기록 원천 확인 시각 안내 정정, 두 사본 동일 유지 |
| `on-client/docs/STUDENT_FINAL_OFFENSIVE.md` | 실제 학생 입력 계약의 시각 정보 한계 기록 |
| 이 문서, `WATCHDOGS_FINAL_OFFENSIVE_D2_D7.md`, `WATCHDOGS_FINAL_DEMO.md`, 측정기의 `INSTALL.md`, 루트 `README.md` | 과거 기록과 이번 검증의 구분·저장점 재실행 안내 |

## 다시 확인하는 방법

작업 폴더는 `D:\share\choi-bujang-secret-vault`다. 현재 5191 서버가 켜져 있으면 중복 실행하지 말고 `http://127.0.0.1:5191/`을 열어 각 「다시 조회」를 누른다. PC 버튼은 Tab·Enter로도 실행할 수 있다.

기존에 설치된 Node 중 v24.19.0을 선택해 모의 검사를 실행하는 한 줄:

```powershell
Set-Location 'D:\share\choi-bujang-secret-vault'; $watchdogsNode24 = Get-Command node -All | Where-Object { (& $_.Source --version).Trim() -eq 'v24.19.0' } | Select-Object -First 1; if (-not $watchdogsNode24) { throw 'Node v24.19.0 준비 필요' }; & $watchdogsNode24.Source --test .\on-client\student\pc-monitor\app.test.mjs .\on-client\student\pc-monitor\server.test.mjs
```

5191 서버가 꺼진 뒤 다시 실행할 때는 위에서 고른 실행 파일의 폴더를 **해당 PowerShell 세션 PATH에만** 앞세우고 기존 `start-watchdogs.ps1`을 사용한다. 자세한 명령은 측정기의 `INSTALL.md`를 따른다. PC 전역 Node 설치나 보안 설정은 변경하지 않는다.

정상 결과는 실측값·단위·항목별 시각·출처다. 읽지 못한 항목은 확인 불가·실패 사유·다음 행동이어야 한다. POST/다른 Origin/잘못된 Host 요청은 거부되어야 한다. 모두 읽지 못했는데 정상이나 0으로 표시되면 안 된다.

## 포장 및 다음 작업

루트와 `on-client/package.json` 모두 `package-app`이 없으며 공식 manifest/완성 패키지/PNG 아이콘도 없다. Inno Setup은 PATH와 일반적인 Program Files 설치 위치에서 발견되지 않았다. 다른 사용자 지정 위치까지 설치 부재를 확정한 것은 아니다. 기존 Host 소스만으로 승인 런타임 설치를 입증할 수 없다.

`npm run package-app`/`npm run bundle`, 설치·제거, 유료 AI 호출, 보안 조치 집행, 공식 업로드·최종 제출은 실행하지 않았다. `PROVIDED_RUNTIME_NOT_INSTALLED`나 운영키 오류를 실제 실행 결과로 기록하지 않았다. 가짜 ZIP/manifest/setup.exe를 만들지 않았다.

다음 순서는 작업 관리자 비교 및 제3자 재현 → 담당자의 공식 포장 도구/승인 실행 대상/PNG 제공 → 빈 출력 폴더에서 제공 명령으로 포장 → 같은 버전의 자료·manifest·실행 대상 확인 → 사용자 단위 Inno 설치·실행·제거 → 사용자 승인 후 공식 최종 제출·결과 확인이다.

`public/data.json`의 기존 미커밋 변경, 제공 `on-client/public/app.js`·`on-client/src/server.mjs`, 인증·판정·운영 설정, 13~22단계 제출물은 이번 수정 대상에서 제외했다.
