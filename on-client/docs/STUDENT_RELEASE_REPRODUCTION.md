# 워치독스 · 22단계 최종 인수인계 / 새 환경 재현 기록

> **릴리스 상태: 검증 중. v1.0 아님.** 다음 표와 명령은 실제 관측과 소스 확인을 구분한다. ALEPH의 AI 원문 검토는 프로그램을 실행하지 않으며, 공식 수료 판정도 운영 인증이나 실행 결과를 대신하지 않는다. 미실행 시험은 성공으로 기입하지 않는다.

## 1. 고정 소스·버전·환경

| 항목 | 값과 근거 | 관측 구분 |
|---|---|---|
| GitHub 원문 | `https://github.com/Huihuing/choi-bujang-secret-vault` | [소스 확인] |
| 원문 브랜치 | `main` | [소스 확인] |
| **재현 기준으로 고정한 22단계 최초 공식 제출 커밋(40자리)** | **`2423f04bff3e608cb06b92890367aec379b6b03c`** | **[공식 피드백에서 확인] 2026-10-26 11:05 접수·11:07 검토**. 이 커밋은 22단계 문서와 13~21단계 원문이 함께 있는 **실제 제출 소스**다. **별도 폴더에서 실행한 기록은 아직 없음** |
| **새 환경에서 실제 검증한 22단계 커밋(40자리)** | **`d5305648eac523909f38a55655b7b18e27268472`** | **[사용자 PowerShell·Git 관측]** 깨끗한 별도 clone, Node 24.19.0·문법 검사·포트 5190 서버 시작·종료 후 재시작. **이 기록을 추가하는 후속 문서 커밋과는 다른 SHA** |
| 이전 21단계 문서 갱신 커밋 | `628a7f70c7dd325e2579541fc57964f493abc0d1` | 위 고정 대상의 조상 커밋. 22단계 새 폴더 재현 대상 아님 |
| **피드백 반영 후 제출 커밋 확인 방법** | 최종 제출 때 `git rev-parse HEAD`로 실제 40자리 SHA 확인, 포털 입력값과 대조 | **복제·재실행 증거는 `d5305648eac523909f38a55655b7b18e27268472`에만 귀속.** 이 문서를 변경한 후속 SHA에 결과를 자동 적용하지 않음. 커밋에 자기 SHA를 미리 삽입할 수 없으므로 후속 SHA는 별도 재검증 기록에서 확인 |
| 앱 원문 버전 | `on-client/package.json`: `alekov-client-starter` **0.2.11** | [소스 확인] |
| **이동 가능한 실행의 정확한 Node 기준** | `on-client/package.json`의 `engines.node`는 **정확히 `24.19.0`**, `tools/start-alekov.ps1`은 **22~24** 기동 허용. 재현 기준은 **v24.19.0** | **[새 폴더 실제 관측]** `d5305648...`의 새 복제본에서 **v24.19.0으로 문법 검사·서버 첫 실행·재실행 성공**. 이보다 넓은 런타임 지원 인증은 아님 |
| 기존 PC 관측(예외적으로 기동된 버전) | 시스템 기본 Node `v26.7.0` 대신 `v24.22.1`로 앱이 실행됨 | [기존 폴더 사용자 관측]. **24.22.1은 실행 스크립트가 허용한 버전일 뿐 `package.json`의 정확한 재현 기준 버전(24.19.0)과 일치하지 않음.** 새 폴더 결과도 아님 |
| 구동 명령 | `on-client/tools/start-alekov.ps1`, 기본 5189, 별도 테스트 포트 `-Port 5190` | **[새 폴더 실제 관측]** 포트 5190 HTTP 서버 시작·Ctrl+C 종료 후 무응답·동일 SHA 재시작 완료 |
| 연결 상태 | 운영 SDP 설정 없는 기본 실행: `ENGINE_NOT_CONNECTED`·「연결 없음」 | [소스 확인·기존 폴더 관측] |
| 최종 판정 | **새 폴더 HTTP 서버의 실행·종료·재시작은 확인**. 13~21단계 모든 기능의 실제 운영 연동·조치 집행·OSV 결과 및 이번 후속 커밋 재실행은 미확인 | **검증 중, v1.0 금지** |

외부 npm 의존성은 `on-client/package.json`에 없다. 루트 `package.json`은 기존 1~12단계 앱용으로 구분한다. **호환성 정리:** 앱의 `engines.node: "24.19.0"`은 npm 관점에서 **정확한 버전 하나**를 지정한다. 실행 도구가 22~24를 수용하더라도 그 전체 범위를 패키지 메타데이터의 보장된 지원 범위로 간주하지 않는다. **재현 기준은 v24.19.0**, 이미 실측한 v24.22.1 기동은 '별도 버전에서 로컬 HTTP 기동 성공'으로만 남긴다. 이 설명은 제공 `package.json`과 제공 실행 도구를 수정하거나 둘이 원래부터 일치한다고 주장하는 것이 아니다. 22단계에서 라이브러리 버전을 낮추거나 임의의 빌드·설치 단계를 추가하지 않는다. `npm start`는 `node src/server.mjs`, `npm run demo`는 **예제**, `npm run check`는 `node --check student/extension.mjs`로 **문법만 검사**한다.

## 2. 데이터 보존·백업·복원 계획(원본 불변)

기존 Git 작업 위치는 `D:\share\choi-bujang-secret-vault`다. 사용자가 직접 보여 준 `git status --short`에 **`M public/data.json`**이 남아 있다. **이 변경을 보존한다.** `git clone`은 원격에 커밋된 소스만 가져오므로 원본의 미커밋 데이터는 새 폴더에 나타나지 않는다. 새 복제본의 초기 `public/data.json`이 원본 데이터의 정상 복원이라는 뜻도 아니다.

| 데이터 구분 | 실제 원문·현상 | 보존 및 복원 방법 | 증명 상태 |
|---|---|---|---|
| 버전별 학생 코드·문서 | `on-client/student/extension.mjs`, `student/extension.mjs`, `on-client/docs/*` | 정확한 커밋을 새 빈 폴더에 `git clone` → `switch --detach` → `git rev-parse HEAD`로 대조. 원본은 유지 | **[사용자 실행]** `d5305648...` SHA 일치, 필수 파일 4개 `True`, 복제본 `git status --short` 비어 있음 |
| 미커밋 노트 | 원본 `public/data.json`이 `M` 상태 | 원본 데이터 파일 내용을 출력하거나 덮어쓰지 않고 `Get-FileHash -Algorithm SHA256`, `git status --short` 비교 | **[사용자 실행]** 클론 직후 **원본 해시 일치 True, Git 변경 상태 일치 True**. 서버 재시작 이후의 추가 보존 검사는 아직 없음. **백업·복원 성공은 미확인** |
| Git 추적 초기 자료 | `data.json` 및 `public/data.json` | Git 커밋의 교육용 초기 파일과 원본 로컬 미커밋 자료를 구분. 새 폴더 데이터로 원래 로컬 파일을 덮어쓰지 않음 | [소스 확인] |
| 기존 메모·DB 복원 | `db/stage10-backup-preflight.sql`, `db/stage10-recovery.sql`, `api/restore.js` | 복원 로직 파일 존재만 확인. 검증된 운영 백업·권한/대상을 확인하기 전 SQL이나 복원 API를 실행하지 않음. 기존 DB 변경/삭제 금지 | 운영 백업·복원 [미확인] |
| 조치 감사 데이터 | `on-client/src/actions/store.mjs`의 **기존 지정 SQLite DB**에 추가되는 intent/state/audit 테이블 | 별도 지정 DB에만 저장되며 기본 실행에서 생성하지 않음. 실제 DB/감사 이력 이관은 운영자 승인이 필요한 일관성 백업·복구 대상으로 분리. 이력 DROP 및 자동 재집행 금지 | 실집행·이력 DB [미확인] |
| 비밀 자격과 개인 설정 | 운영자 native/SDP 설정 파일, Windows AI 자격 보관함, Git 밖 `.env` | **새 복제 폴더/제출 JSON/Git/문서로 무단 복사하지 않음.** 필요하면 운영 담당자의 별도 재발급·이관 절차를 따른다 | [미확인] |
| OSV 조회 자료 | `on-client/src/vulnerabilities/project-scan.mjs`, `osv.mjs` | 운영자 승인 공개 패키지와 실제 설치 메타데이터가 없는 새 환경은 `not_configured`/`not_checked` 등으로 구분, OSV 결과를 이전 환경에서 만들어 옮기지 않음 | 외부 조회 [미확인] |

**백업과 복원은 별개다.** Git 소스 복제와 원본 파일 해시가 일치했다는 사실만으로 운영 DB 백업/복원 성공을 보증하지 않는다. 이번 복제 시험에는 실제 보안 조치, 원본 DB 복원, 비밀 설정 복사가 포함되지 않는다. 기존 원본 작업을 덮는 `git reset --hard`, `git clean`, 강제 checkout 등을 사용하지 않는다.

## 3. 깨끗한 새 폴더에서 정확한 커밋 확인하기

아래는 **프로젝트 밖 새 경로를 사용하는 공개 가능한 절차**다. `D:\share`는 해당 학습 PC에서 확인한 예시 경로이고 다른 PC에서는 바꾼다. **사용자가 `d5305648eac523909f38a55655b7b18e27268472`을 `D:\share\alekov-stage22-repro-d530564`에 실제 복제해 서버를 두 번 기동했다.** 아래 스크립트는 후속 제출에서 사용할 별도 새 폴더의 절차이며, 후속 SHA의 실행 성공은 아직 미확인이다.

### 3-1. 원본 보존 검사: 읽기 전용

~~~powershell
$original = "D:\share\choi-bujang-secret-vault"
$clone = "D:\share\alekov-stage22-repro"
git -C $original status --short
git -C $original rev-parse HEAD
Test-Path -LiteralPath "$original\public\data.json"
Get-FileHash -LiteralPath "$original\public\data.json" -Algorithm SHA256 |
    Select-Object Algorithm, Hash
if (Test-Path -LiteralPath $clone) {
    throw "새 폴더가 이미 존재합니다. 삭제하지 말고 다른 빈 이름을 지정하세요."
}
~~~

파일 내용을 출력하지 않는다. 이전 `M public/data.json`이 사라졌거나 해시가 전후 달라지면 원본 보존을 검증 완료로 기록하지 않는다.

### 3-2. 별도 새 폴더 생성 및 정확한 제출 SHA 확인

> 2026-10-26 첫 공식 제출 SHA는 **`2423f04bff3e608cb06b92890367aec379b6b03c`**이다. 이 값은 과거 실패 피드백의 **고정 기록**이다. **이번에 새로 제출하는 커밋은 다른 SHA이므로**, 재현 전 사용자 포털에 입력할 그 **현재 40자리 SHA**를 아래 PowerShell에 입력한 뒤 동일 SHA가 체크아웃되는지 확인한다. 문서가 자신을 포함하는 SHA를 미리 정적 문자열로 적으면 커밋이 바뀌므로, 실제 SHA는 체크아웃 시 `git rev-parse HEAD`로 확인·기록한다.

~~~powershell
$clone = "D:\share\alekov-stage22-repro"
$repoUrl = "https://github.com/Huihuing/choi-bujang-secret-vault.git"

# ALEPH의 이번 22단계에 실제로 제출할 Git commit 전체 40자 입력
$targetCommit = (Read-Host "이번 제출의 40자리 Git 커밋 SHA").Trim()
if ($targetCommit -notmatch '^[0-9a-f]{40}$') {
    throw "40자리 Git SHA를 확인하세요."
}
if (Test-Path -LiteralPath $clone) {
    throw "동일 재현 폴더가 이미 있습니다. 삭제하지 말고 새로운 빈 경로를 지정하세요."
}

git clone --no-checkout --branch main --single-branch $repoUrl $clone
if ($LASTEXITCODE -ne 0) { throw "GitHub 복제 실패" }

git -C $clone switch --detach $targetCommit
if ($LASTEXITCODE -ne 0) { throw "제출 SHA 체크아웃 실패" }
$actual = (git -C $clone rev-parse HEAD).Trim()
if ($actual -ne $targetCommit) { throw "이번 제출 SHA와 체크아웃 SHA 불일치" }

Write-Host "이번 22단계 검증 대상 Git SHA(40자리): $actual"
git -C $clone status --short
Test-Path -LiteralPath "$clone\on-client\tools\start-alekov.ps1"
Test-Path -LiteralPath "$clone\on-client\docs\STUDENT_RUNBOOK.md"
Test-Path -LiteralPath "$clone\on-client\docs\STUDENT_RELEASE_REPRODUCTION.md"
~~~

**검증 원칙:** 위 명령의 `$targetCommit`은 반드시 **이번 포털 제출 필드의 실제 커밋**과 일치해야 한다. 최초 제출 `2423f04...`에서 수행한 시험을 새로운 문서 수정 커밋의 시험 결과로 합산하지 않는다. 기동 전 실제 40자리 SHA, `node --version`, `git status --short`와 이후 HTTP/화면 결과를 서로 묶어서 기록한다. 개인 운영 설정·원본 비밀·미커밋 노트는 복제하지 않는다.

### 3-3. Node.js 24로 앱 시작(복제본 앱 폴더)

기존 5189 서버가 켜져 있을 수 있으므로 **별도 포트 5190**을 사용한다. 5190이 점유됐다면 다른 빈 포트를 선택하고 실제 포트를 기록하되 기존 서버를 종료하지 않는다.

~~~powershell
Set-Location "D:\share\alekov-stage22-repro\on-client"
node --version
# 이 PC의 기본 Node 26 대신, 실제 이전 검증에 쓰인 Node24 위치를 활용
$node24 = (& npx --yes node@24 -p "process.execPath" |
    Select-Object -Last 1).Trim()
if (-not (Test-Path -LiteralPath $node24)) { throw "Node.js 24 실행 파일 없음" }
$version = (& $node24 --version).Trim()
if ($version -notmatch '^v24\.') { throw "Node 24 아님" }
$env:Path = "$(Split-Path -Parent $node24);$env:Path"
node --version
npm run check   # 학생 함수 문법만 검사, 실제 기능 판정 아님

# 설정 파일/개인 자격 복사 없음. 기본 미연결 상태로 HTTP 기동만 검증.
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -Port 5190
~~~

**실제 관측 신호(재현 SHA `d5305648...`):** 첫 기동과 재시작 모두 `케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5190/ 을 여세요.` 및 `서버가 응답한 것만 확인했습니다.`가 출력됐다. Node 버전은 `v24.19.0`, `node --check student/extension.mjs`는 정상 종료했다. **아래 예시 스크립트의 새 후속 제출 SHA에서는 재검사가 필요하다.**

브라우저 `http://127.0.0.1:5190/`에서 보호 현황/업무 앱/보안 기록과 학생 화면·미연결 상태를 확인한다. 다른 PowerShell에서 `Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:5190/"`로 HTTP 200 여부를 읽을 수 있다. **서버 응답 200은 원천 SDP·AI·OSV 성공을 뜻하지 않는다.** 사건 설명 유료 요청·운영 보안 집행·민감 원본 자료 복사를 검사 명령에 넣지 않는다.

### 3-4. 종료·재실행과 원본 보존 후검사

1. 새 복제본 서버를 실행 중인 PowerShell에서 `Ctrl+C`로 종료. 5190 응답이 사라졌는지 확인한다. 원래 폴더 서버는 종료하지 않는다.
2. 같은 새 폴더에서 `node --version`과 공식 `-Port 5190` 시작 명령을 다시 실행. 브라우저를 다시 열어 **같은 커밋**의 기본 상태를 확인한다.
3. 새 폴더 `git rev-parse HEAD`와 `git status --short`를 다시 확인. 테스트로 미커밋 작업이 생겼으면 삭제/복원하지 않고 기록한 뒤 원인을 확인한다.
4. 원본 폴더의 `git status --short`와 `Get-FileHash ... public\data.json`를 다시 읽어 **원본 해시와 수정 표시가 전후 동일**한지 비교한다. 비교 전후 중 하나가 없으면 보존 성공 판정을 보류한다.

**실제 관측한 범위:** `d5305648...`의 복제·첫 시작·`Ctrl+C` 종료 후 HTTP 5190 무응답·같은 SHA 재시작까지 확인했다. **재시작 뒤의 복제본 `git status --short` 및 원본 파일 해시·상태 추가 비교는 별도 미확인**이며, 재시작 화면 텍스트에 주소창 URL이 없어서 그 화면을 포트 5190이라고 독립 확정하지 않는다. 다른 커밋에서의 종료·재시작은 다시 확인해야 한다.

## 4. 동일 최종 커밋 기준 13~21단계 재현 기록

> **실제 새 폴더 검사 SHA: `d5305648eac523909f38a55655b7b18e27268472`** (2026-10-26). 첫 공식 실패 SHA `2423f04bff3e608cb06b92890367aec379b6b03c`와 구분한다. **13·16·17·20단계의 학생 표시 및 앱 시작·재시작은 새 폴더에서 직접 관찰된 범위로만 표시**한다. 나머지 기능과 운영 원천은 미확인이다. **이 기록을 추가한 새 커밋은 별도 SHA로 재시험해야 하며**, 다른 SHA의 성공으로 자동 합산하지 않는다.

| 단계 | 확인 기능·학생 함수 | 새 폴더 결과 | 확인 시각 | 근거·미확인 이유 |
|---|---|---|---|---|
| 13 | `renderIdentity`: 사용자·기기·세션 연결/오류 | **연결 없음** (실패 표시 관측) | 2026-10-26 11:24:44(화면 표시) | `ENGINE_NOT_CONNECTED`, 현재 계정·기기·세션 실패 표시 확인. 정상 신원 연결은 미확인 |
| 14 | `renderDecision`: 업무 앱 접근 `allow/deny/challenge/unknown` | **연결 없음** (목록 조회) | 2026-10-26 11:24:44(화면 표시) | 상단 앱 읽기 오류 `ENGINE_NOT_CONNECTED` 관측. **앱 선택·`renderDecision` 판정 동작은 미확인** |
| 15 | `renderEvents`: 본인 범위 접속/XDR 기록·근거·규칙 | **연결 없음** (원천 조회) | 2026-10-26 11:24:44(화면 표시) | 상단 보안 기록 조회 오류 `ENGINE_NOT_CONNECTED`. **기록 선택·필터·상세는 미확인** |
| 16 | `renderStatus`: 알림·기기/세션·도움정보·실패 안내 | **연결 없음** (오류 안내 재현) | 2026-10-26 11:24:44(화면 표시) | 기기·세션 오류와 알림 5개 `ENGINE_NOT_CONNECTED` 확인. **도움정보 버튼은 미실행** |
| 17 | `renderAiConnection`: `idle/loading/ok/error`, `test/verified` | **확인 불가** (대기 표시 재현) | 2026-10-26 11:24:44(화면 표시) | 'AI 연결 점검 전'·수동 점검 안내 표시 확인. 실제 앱 승인·모델 점검·추론은 미실행 |
| 18 | `renderExplanation`: 사건 근거 ID·규칙·`unknown` | **미확인** | 미기록 | 실제 사건 및 AI 설명 미확인 |
| 19 | `renderAction`: 준비·사람 확인·ACK·효과/미확인 | **미확인** | 미기록 | 운영 조치 집행기/권한 없음. 실집행 요청 금지 |
| 20 | `renderVulnerabilities`: lock 정확 버전·OSV/미조회/부분 실패 | **확인 불가** (조회 전 표시 재현) | 2026-10-26 11:24:44(화면 표시) | '조회 전(idle)'·수동 조회 안내는 확인. 패키지/OSV 실제 조회는 미실행 |
| 21 | `STUDENT_RUNBOOK.md`: 설명서대로 시작·종료·재실행 | **재현됨** (서버 생명주기 범위) | 2026-10-26, 재시작 화면 표시 11:24:44 | d530564... 독립 clone·Node v24.19.0·문법 검사·5190 두 차례 시작·Ctrl+C 종료·종료 후 HTTP 무응답 확인. **전체 기능·운영 연결 재현 뜻 아님** |

### 앞선 작업 환경에서만 직접 관측한 내용 — 절대 합산하지 않음

| 당시 소스 커밋 | 환경과 시간 | 확인한 값 | 증거 구분 |
|---|---|---|---|
| `70f372307ba48c5941ca09124984113be856c422` | 기존 폴더, Node `v24.22.1`, 5189 포트, 2026-10-26 브라우저 표시 시각 **10:25:06** | 케셰브 기동·브라우저 보호 현황·학생 `renderIdentity`/`renderStatus`/`renderAiConnection`/`renderVulnerabilities` 출력. 상단 **연결 없음**, `ENGINE_NOT_CONNECTED` | **[기존 PC 관측]**. 이번 22단계 복제 테스트 아님 |
| 이전 단계별 검토 | 각 단계 커밋에서 별도 점검 | 18단계 DOM 모의 34개, 19단계 40개, 20단계 36개 | **[모의 검사]**, 운영 연결/유료 모델/실집행 아님 |

데모 실행 `npm run demo`는 실제 연결과 별도로 `예제 자료`로만 기록한다. `ENGINE_NOT_CONNECTED`는 연동이 없음을 나타내므로 업무 접근 성공이나 사건 조회 재현 완료로 기록하지 않는다. `unknown`은 정상 또는 효과 없음으로 바꾸지 않는다.

## 5. 버전 제한·미해결(UNV)·시연과 원문 평가의 차이

**발행 상태:** 학생 화면/문서의 검증 중인 원문 버전 **0.2.11**, **v1.0 미발행**. 버전 번호는 `on-client/package.json` 원문 그대로다.

- **[소스 확인]** 이전 학생 함수(13~20), 제공 로컬 HTTP 서버/메뉴, `src/engine.mjs`·`src/ai/service.mjs`·`src/vulnerabilities/project-scan.mjs`의 모듈 경로 존재.
- **[기존 PC 관측]** 커밋 `70f372...`에서 로컬 기본 미연결 상태 기동을 확인했다. **[새 폴더 사용자 관측]** 커밋 `d5305648...`에서 복제·문법 확인·Node v24.19.0·포트 5190 시작/종료/재시작·미연결 화면 텍스트를 확인했다. **이는 새 문서 수정 후 제출 SHA의 시험 결과가 아니다.**
- **[새 폴더 확인/미확인 경계]** `d5305648...` SHA 복제·Node 버전·문법 검사·서버 두 차례 기동과 종료·재기동 확인. 첫 복제 직후 원본 `public/data.json` 해시/수정 상태 비교는 True. **전체 13~21단계 업무 기능·운영 연결, 브라우저 주소창 5190의 직접 증거, 재시작 후 원본 재대조, 후속 문서 커밋의 동일 SHA 재시험은 미확인.**
- **[운영 연결 미확인]** 본인 SDP 로그인·앱 접근·실제 XDR 원천, AI 앱 승인과 실제 모델 사건 설명, 19단계 사람 확인 후 운영 원천 집행 및 실제 효과, 승인된 OSV 실조회.
- **[공식 판정]** 22단계 커밋 `2423f04bff3e608cb06b92890367aec379b6b03c`은 2026-10-26 11:05 접수·11:07 AI 원문 검토에서 **실패(reproduction_record_consistency)**, **확인 불가(portable_package_readiness)**, 나머지 네 항목 통과라는 피드백을 받았다. 이는 실행 시험이 아니며 통과·진도 기록이 아니다. 후속 제출 판정은 미확인.
- **v1.0 조건:** 공식 `on-client/docs/STUDENT_PROMPTS.md`와 `FINAL_PRODUCT_GUIDE.md`에 적힌 **19단계 실제 원천 집행 연결, 22단계 동일 최종 소스 누적 재현, 공식 접수/수용**까지 완료되기 전에는 v1.0으로 적지 않는다. 단계 원문 AI 판정이 성공해도 운영 인증을 자동으로 받지는 않는다.

## 6. 변경 발생 시 동일 커밋 검증과 공식 제출

1. **고정된 기존 제출 SHA는 `2423f04bff3e608cb06b92890367aec379b6b03c`**다. 재현 결과를 이 학생 문서에 추가하면 새로운 커밋이 되어 SHA가 달라진다. **자기 자신의 SHA를 커밋된 파일 안에 미리 상수로 넣을 수 없으므로**, 후속 제출 직전에는 `git rev-parse HEAD`에서 나온 실제 최종 40자리 SHA를 **포털 제출 필드·실측 로그**에 기록하고 그 SHA로 다시 재현한다. 코드가 같더라도 다른 SHA의 결과를 동일 최종 버전의 시험 완료로 합산하지 않는다.
2. 공식 제출 대상 최종 커밋을 새 폴더에서 다시 체크아웃해 `git rev-parse HEAD`, `npm run check`, 로컬 시작·브라우저·종료·재시작을 다시 대조한다. 미실행이면 검증 중으로 둔다.
3. 기존 작업 디렉터리의 `M public/data.json`을 보존한다. 설정 파일/인증서/토큰·노트 원문을 복제하거나 문서와 Git에 넣지 않는다.
4. ALEPH **22단계**에는 저장소 URL과 **제출할 40자리 SHA**를 직접 입력한다. 공식 `student-source-cli.mjs` 도구로 해당 커밋의 원문을 프로젝트 밖 `D:\share\alekov-submit`에 **새 JSON 이름**으로 추출할 수 있으며, 도구는 업로드·AI 판정·학생 코드 실행을 하지 않는다. (워크벤치 제출 준비 지원 범위는 13~20단계.)
5. JSON이 필요하면 해당 단계의 「비공개 저장소 원문 묶음(JSON)」에 사용자가 직접 선택하고 「22단계 제출」을 누른다. 수신 성공과 공식 통과는 별개이며 원문만 전달 실패한 경우 기존 접수를 유지하고 「원문만 다시 보내기」를 사용한다. **이 문서 작성 과정에서 공식 제출은 하지 않았다.**

### 실제 원문 출처

- `on-client/README.md`, `on-client/package.json`, `on-client/docs/STUDENT_RUNBOOK.md`, `on-client/docs/STUDENT_LAUNCH_GUIDE.md`
- `on-client/docs/STUDENT_PROMPTS.md` 22단계, `on-client/docs/FINAL_PRODUCT_GUIDE.md`, `on-client/.on-starter-manifest.json`
- `on-client/tools/start-alekov.ps1`, `on-client/public/index.html`, `on-client/public/app.js`, `on-client/student/extension.mjs`
- `on-client/src/server.mjs`, `on-client/src/engine.mjs`, `on-client/src/actions/store.mjs`, `on-client/src/ai/service.mjs`, `on-client/src/vulnerabilities/project-scan.mjs`
- `public/data.json`, `data.json`, `.gitignore`, `db/stage10-backup-preflight.sql`, `api/restore.js`

**원문 검토는 실행이 아니다. 확인하지 않은 운영 연결을 수료·효과 확인으로 적지 않는다.**
