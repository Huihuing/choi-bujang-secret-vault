# 워치독스 — 학생 실행 설명서·시스템 구성도 (21단계)

> **대상:** `Huihuing/choi-bujang-secret-vault`의 `on-client`(13~22단계). 이 파일 `on-client/docs/STUDENT_RUNBOOK.md`는 **학생이 추가한 문서**이며 제공 `README.md`·`public/app.js`·`src/server.mjs`·인증 설정은 수정하지 않는다.
>
> **확인 수준:** [코드 확인]은 GitHub 제출 커밋의 실제 파일·명령을 읽고 대조한 것, [사용자 실행]은 사용자가 공유한 PowerShell 실제 출력, [모의 확인]은 학생 함수를 가짜 DOM/자료로 점검한 것, [미확인/UNV]는 로컬 앱 기동이나 실제 운영 연동을 수행·검증하지 않은 것이다. 이 문서 작성 자체를 실행 성공 또는 공식 단계 통과로 적지 않는다.
>
> **명칭:** 개인 보안 Agent 이름은 **워치독스**. 제공 앱의 브라우저 제목·실행 안내에 남아 있는 기본 제품명은 **케셰브(KESHEV)**다. 이를 고치기 위해 제공 파일을 변경하지 않는다.

## 1. 목적과 지원 기능

직원 **본인**의 로그인·기기·현재 세션, 업무 앱 접근 결과, 본인 범위 접속/XDR 보안 기록, AI 사건 설명, 조치 준비 및 서버 처리 결과, 설치된 공개 npm 패키지의 OSV 취약점 조회 결과를 구분하여 표시하는 로컬 ZTNA·XDR 학습용 보안 앱이다. 관리자 전체 로그를 보여 주지 않는다. 기본 실행은 기존 회사 보안 서버에 **미연결**이며, 연결 없음을 성공으로 표시하지 않는다.

역할이 다른 AI 셋을 혼동하지 않는다: ① Workbench의 **수업 코드 작성 AI**, ② 앱 서버를 통해 사건을 설명하는 **CLCO·알레프게이트 AI**, ③ 커밋 원문을 읽고 제출 과제를 판정하는 **ALEPH 공식 AI**. `/api/ai/check`로 모델 목록을 확인한 것과 `/api/ai/explain`으로 실제 사건 설명을 받은 것은 별개다. AI 제안만으로 조치가 실행되지 않으며, 원천 접수(ACK)는 효과 확인이 아니다.

## 2. 준비 프로그램과 현재 확인한 버전

| 항목 | 확인한 값·요구 조건 | 근거 / 미확인 여부 |
|---|---|---|
| 앱 패키지 | `on-client/package.json`: `alekov-client-starter` **0.2.11**, 모듈 `type=module` | [코드 확인] |
| Node.js | `package.json`의 엔진 기준 **24.19.0**. 실행 도구는 **Node 22~24** 허용, 24.19.0 권장 | [코드 확인] |
| 사용자 PC Node | 앞서 공유한 PowerShell에서 **Node 26** 사용. 실행 도구는 이 버전을 **거부**함. Node 24.19.0 실제 앱 실행 여부는 미확인 | [사용자 실행] + [코드 확인] |
| Git | `git fetch origin main`, `git cat-file -e`로 제출 커밋 안의 관련 원문을 확인한 사용자 출력 있음 | [사용자 실행] |
| 원문 전달용 Node 24 | `npx --yes node@24`로 공식 원문 전달 JSON을 생성한 기록은 있으나, **앱 실행 성공 증거가 아님** | [사용자 실행] |
| Windows PowerShell | 앱 실행 `tools/start-alekov.ps1` 제공. 브라우저는 로컬 `127.0.0.1`을 연다 | [코드 확인], 브라우저 실측은 [미확인] |
| 의존성 | `on-client/package.json`에 외부 `dependencies` 항목 없음. Git 최상위의 `package.json`은 과거 1~12단계 별도 서버용 | [코드 확인] |
| 보안 연결 설정 | 기존 SDP·native 호스트 및 CLCO 앱 권한은 **운영자 발급**이 있어야 이용. 파일 내용·자격 값을 생성하거나 이 문서에 싣지 않음 | [미확인/UNV] |

`D:\share\on-client`는 앞서 따로 압축 해제해 둔 시작 틀 위치이고, `D:\share\choi-bujang-secret-vault`는 Git 저장소로 사용자의 명령 출력에서 확인됐다. **21단계에 실제 제출된 학생 코드가 들어 있는 것은 Git 저장소 안의 `on-client`다.** 두 앱 폴더의 학생 코드가 자동으로 동기화된다고 가정하지 않는다.

## 3. 폴더 구조: 어디서 명령을 실행하나

~~~text
D:\share\choi-bujang-secret-vault\        ← Git 최상위 / 제출 커밋
├─ README.md                               ← 기존 1~12단계 README: 덮어쓰지 않음
├─ package.json                            ← 기존 프로젝트(앱 package.json 아님)
├─ student\extension.mjs                   ← 학생 원문 사본(커밋에는 앱 사본과 동일 내용)
└─ on-client\                              ← 13~22단계 실행 위치
   ├─ README.md, package.json             ← 제공 시작 안내와 v0.2.11
   ├─ public\index.html                   ← 제공 HTML, 탭·버튼
   ├─ public\app.js                       ← 제공 UI·API 통신·취소
   ├─ public\ai-connect.mjs               ← 제공 AI 연결 승인
   ├─ public\vulnerabilities-view.mjs      ← 제공 패키지 조회 표시
   ├─ student\extension.mjs               ← 13~20단계 학생 DOM 함수
   ├─ student\engine-adapter.mjs          ← 운영 SDP 호스트용 제공 연결 인터페이스
   ├─ src\server.mjs                      ← 로컬 HTTP 서버
   ├─ src\engine.mjs                      ← 연결 없음·demo·연결 엔진
   ├─ src\ai\service.mjs                  ← AI 모델 호출 및 근거 검증
   ├─ src\ai\app-authorization.mjs        ← AI 앱 권한 검증
   ├─ src\vulnerabilities\project-scan.mjs ← lock/설치 메타데이터 대조
   ├─ src\vulnerabilities\osv.mjs         ← 승인 공개 패키지 OSV 조회
   ├─ vendor\clco-http.mjs                ← AI 게이트 HTTP 전송
   ├─ tools\start-alekov.ps1              ← 공식 실행 도구
   └─ docs\STUDENT_RUNBOOK.md             ← 이 학생용 설명서
~~~

- **Git 관리:** `D:\share\choi-bujang-secret-vault`. **앱 실행:** `D:\share\choi-bujang-secret-vault\on-client`. 먼저 `Test-Path`로 실제 파일 존재를 확인한다. Git 경로 자체는 확인됐지만 현재 Windows 작업 트리의 앱 실행 스크립트 경로는 아직 직접 실측하지 않았다.
- `on-client/.on-starter-manifest.json`은 제공 원본 목록 참고 자료다. `.env.example`은 제공 안내에는 언급되지만 **현재 제출 Git 트리에는 존재하지 않는다**(Git 루트 `.gitignore`가 `.env.*`를 제외한다). 없는 견본을 있는 것처럼 안내하거나 비밀값을 직접 채우지 않는다.

## 4. 처음 실행·확인·종료·재실행

아래 명령은 **제공 `on-client/README.md` 및 `docs/STUDENT_LAUNCH_GUIDE.md`와 실제 `tools/start-alekov.ps1`에서 확인한 명령**이다. 이 사용자의 새 PowerShell 창에서 실행한 결과는 아직 **[미확인/UNV]**이므로, 정상 메시지는 예상 출력으로만 적는다.

### A. Git 폴더와 앱 파일 확인

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault"
git rev-parse --show-toplevel
git status --short
Test-Path ".\on-client\tools\start-alekov.ps1"  # True면 앱 폴더로 진행
~~~

`git status --short`는 미커밋 변경을 점검하는 읽기 명령이다. 기존 파일을 삭제하거나 강제 초기화하지 않는다. `Test-Path`가 False라면 임의로 다른 파일을 복사·덮어쓰지 않고 실제 작업 위치를 먼저 대조한다.

### B. 지원 버전 확인 후 공식 도구 실행

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault\on-client"
node --version    # Node 22~24에서 진행, 권장 v24.19.0

# 지원 버전이 준비되었을 때 실행
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
~~~

**Node 26이면 `지금 Node.js 는 vXX 입니다` 오류와 함께 실행 도구가 중지되므로 Node 24.19.0 환경 준비 후 새 창에서 재확인해야 한다.** 별도 원문 도구를 `npx node@24`로 실행했다는 사실만으로 앱 도구도 Node 24로 실행된 것은 아니다.

### C. 정상 실행 신호와 브라우저 화면

스크립트에서 확인한 **예상 정상 출력**(실제 이 PC에서의 관측 결과는 아직 없음):

~~~text
케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5189/ 을 여세요.
서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.
끄려면 이 창에서 Ctrl+C 를 누르세요.
~~~

브라우저 `http://127.0.0.1:5189/`에서 탭 **보호 현황 / 업무 앱 / 보안 기록**, 상단 「다시 불러오기」가 보이는지 확인한다. 정상 기동은 **로컬 서버의 HTTP 응답만** 확인하며 실제 SDP·AI·OSV 연결 성공은 아니다.

- **종료:** 이 앱을 실행한 PowerShell 창에서 `Ctrl+C`. 브라우저 연결이 종료됐는지 직접 확인한다.
- **재실행:** 같은 `on-client` 폴더로 돌아와 위 공식 명령을 다시 실행한다. 파일·Git 이력 삭제 불필요.
- **5189 포트 충돌:** 다른 앱을 강제 종료하지 않고 공식 스크립트 지원 옵션 `-Port 5190`을 지정한 뒤 `http://127.0.0.1:5190/`을 연다. 옵션은 **코드에서 확인**, 실제 사용 결과 **미확인**.
- `on-client/package.json` 스크립트: `npm start` = `node src/server.mjs`, `npm run demo` = `node src/server.mjs --demo`, `npm run check` = `node --check student/extension.mjs`. `demo`는 예제이고 `check`는 문법만 검사한다. 이 명령들의 실제 사용자 실행 출력은 확인되지 않았으므로 재현 완료로 기록하지 않는다.
- 시작 도구는 이번 명령에 한해 `-ExecutionPolicy Bypass`를 사용하며 PC 전체 실행 정책을 변경하지 않는다.

## 5. 글로 된 구성도 (코드와 데이터 흐름)

~~~mermaid
flowchart LR
  B["PC 브라우저 · 제공 UI<br/>public/index.html, public/app.js"]
  S["로컬 앱 서버<br/>src/server.mjs · 127.0.0.1:5189"]
  E["기존 접근 제어·XDR 시스템<br/>src/engine.mjs, student/engine-adapter.mjs"]
  G["CLCO 수업용 AI 게이트<br/>src/ai/service.mjs, vendor/clco-http.mjs"]
  O["공개 OSV 조회<br/>src/vulnerabilities/project-scan.mjs, osv.mjs"]
  P["ALEPH 공식 과제 포털<br/>커밋 접수·AI 판정"]
  B -->|"조회·접속·AI 설명 HTTP"| S
  S -.->|"운영자 SDP 연결 시"| E
  S -.->|"앱 권한 승인 시"| G
  S -.->|"수동 조회 + 승인 공개 패키지"| O
  B -.->|"별도 단계 제출, 앱 런타임과 별개"| P
~~~

**텍스트 구성도(그림 없이도 검토 가능):** 브라우저 `public/index.html`·`public/app.js` → `127.0.0.1:5189` 로컬 `src/server.mjs` → [운영자 설정 필요] **기존 접근 제어·XDR 엔진** `src/engine.mjs`와 `student/engine-adapter.mjs` / **CLCO 앱 AI 게이트** `src/ai/service.mjs`·`src/ai/app-authorization.mjs`·`vendor/clco-http.mjs` / **공개 OSV** `src/vulnerabilities/project-scan.mjs`·`osv.mjs`. 점선은 기본 실행에서는 성공이 **보장되지 않는** 별도 원천 연결이다. **ALEPH 판정 포털**은 로컬 앱이 아니라 제출 커밋을 따로 읽는 시스템이다.

| 로컬 서버의 API(코드 확인) | 데이터 및 역할 | 실제 운영 결과 |
|---|---|---|
| `GET /api/me`, `/api/devices`, `/api/sessions` | 개인 로그인·기기·세션 | SDP 실제 연결 [미확인] |
| `GET /api/apps`, `POST /api/access` | 본인 앱 목록·접근 판정 | 운영 접근 결과 [미확인] |
| `GET /api/events` | 개인 접속/XDR 기록·근거·규칙 | 본인 원천 사건 [미확인] |
| `POST /api/ai/check` | 앱 권한·모델 목록, **설명 생성 아님** | 운영 게이트 점검 [미확인] |
| `POST /api/ai/explain` | 선택 사건의 AI 설명 | 실제 모델 생성 [미확인] |
| `POST /api/actions/prepare`, `/execute`, `/result` | 원천 조치 준비·확인 후 집행·결과 재조회 | 실제 처리/효과 [미확인] |
| `GET /api/vulnerabilities` | 설치 버전·승인 공개 패키지의 OSV 결과 | 실제 스캔 [미확인] |
| `GET /api/diagnostics` | 비밀 없는 상태·점검 정보 | 실제 사용자 화면 [미확인] |

## 6. 제공 파일과 학생이 작성한 기능의 경계

| 구분 | 실제 코드 경로 | 구현 주체 / 범위 |
|---|---|---|
| 제공 UI | `public/index.html`, `public/app.js`, `public/ai-connect.mjs`, `public/vulnerabilities-view.mjs` | 메뉴·버튼·API 요청·취소 및 늦은 응답 무시·AI 승인·OSV 정규화. 학생이 이번 단계 수정하지 않음 |
| 제공 서버 | `src/server.mjs`, `src/engine.mjs`, `src/engine/sdp-host.mjs`, `src/ai/*`, `src/vulnerabilities/*`, `vendor/clco-http.mjs` | 실제 연결/모델 전송/인증/원천 정책. 승인된 운영 설정 없이는 성공이라고 할 수 없음 |
| 제공 실행·안내 | `tools/start-alekov.ps1`, `on-client/README.md`, `docs/STUDENT_LAUNCH_GUIDE.md`, `.on-starter-manifest.json` | 기존 원문 수정 금지 |
| 학생 코드 | `on-client/student/extension.mjs` (Git 루트의 `student/extension.mjs` 사본) | 상태·근거·결과를 DOM `createElement`·`textContent`로 읽기 전용 표시 |
| 학생 문서 | `on-client/docs/STUDENT_RUNBOOK.md` | **21단계에서 새로 작성한 파일**. 기존 README/제공 문서 덮어쓰지 않음 |
| 과거 1~12단계 | 루트 `README.md`, 루트 `package.json`, 루트 `src/` | 13~22단계 `on-client`와 실행 스크립트·의존성 별개 |

### 학생 화면 함수(13~20단계 코드 확인)

| 단계·함수 | 설명 / 지켜야 할 경계 |
|---|---|
| 13 · `renderIdentity` | 로그인 사용자·현재 기기·세션, 연결 없음/오류/확인 불가를 나눔 |
| 14 · `renderDecision` | 접근 `allow/deny/challenge/unknown`, 실패를 허용으로 표시하지 않음 |
| 15 · `renderEvents` | 현재 개인 범위 사건 목록·선택 기록·근거·규칙 |
| 16 · `renderStatus` | 기기/세션/알림/도움정보와 오류, 안전한 필드만 복사 |
| 17 · `renderAiConnection` | `idle/loading/ok/error`, 시험 연결 `test`와 앱 권한 점검 `verified` 분리 |
| 18 · `renderExplanation` | 인용 근거 ID와 실제 사건 근거·규칙 일치 확인, `unknown` 표시, 제안 미실행 |
| 19 · `renderAction` | 준비/사람 확인/ACK/실제 효과/결과 불명을 구별, 실행 요청 코드 없음 |
| 20 · `renderVulnerabilities` | 설치된 정확 버전·lock 해시·OSV ID/수정 시각, 일부 실패와 미조회 분리 |

**실제 버튼 이름(제공 `public/index.html` 확인):** 「다시 불러오기」, 「도움정보 불러오기」, 「설치 패키지 조회」, 「패키지 조회 취소」, 「AI 연결 시작」, 「승인 페이지 열기」, 「승인했으며 연결 확인」, 「현재 API 연결 점검」, 「AI 설명 취소」, 「대상과 조치를 확인했으며 집행합니다」, 「원천 결과만 재조회」, 「조치 화면 취소」. 별도의 조치/인증/AI POST 버튼을 학생 코드에 만들지 않는다.

## 7. 장애 대응: 실제 원문 메시지와 확인 순서

| 상황·코드 | 의미 | 직접 확인할 순서 / 미확인 경계 |
|---|---|---|
| `Node.js 가 없습니다` / `지금 Node.js 는 vXX 입니다` | Node 부재·버전 미지원 | `node --version` → Node 22~24(권장 24.19.0) 준비 → 새 PowerShell에서 공식 실행. 현재 Node 26은 중지됨 |
| `앱 폴더가 아닙니다` / `시작 틀 폴더가 아닙니다` | 실행 폴더·스크립트 불일치 | `git rev-parse --show-toplevel`과 `Test-Path .\on-client\tools\start-alekov.ps1` 확인. 별도 압축본과 Git 수정본 혼동 금지 |
| `포트 5189 를 다른 프로그램이 쓰고 있습니다` | HTTP 포트 충돌 | 다른 프로그램 종료 금지 → 제공 `-Port 5190` 옵션(코드만 확인) → `:5190` 주소 확인 |
| `앱 서버가 ... 초 안에 뜨지 않았습니다` | 시작 제한 시간 초과 | 실행 창 메시지·Node 버전·폴더 확인, 해결 안 되면 담당자에게 오류 코드 전달 |
| `ENGINE_NOT_CONNECTED`, `disconnected` | SDP 엔진 없음 | 로컬 앱만 실행됐는지 확인; 담당자 SDP 연결 설정 전에는 실제 로그인/접근/XDR [UNV] |
| `CONTRACT_MISMATCH`, `ENGINE_RESULT_UNVERIFIED` | API 응답 계약/검증 범위 확인 불가 | 「다시 불러오기」 한 번 → 계속되면 비밀 없는 도움정보로 담당자 확인. 빈 성공으로 보정 금지 |
| `ON_AI_PROVISIONING_PENDING`, `ALEKOV_CONNECT_NOT_MOUNTED` | 앱 권한·호스트 연결 준비 전 | 「계정 연결 확인」 → 앱 승인 상태 확인 → 담당자에게 발급/설치본 문의, 키 직접 입력 금지 |
| `WB_CLCO_AUTH_REQUIRED`, `WB_CLCO_ACCESS_BLOCKED` | AI 인증 또는 앱 접근 제한 | 승인 계정·상태 확인 → 담당자 권한 확인 |
| `WB_CLCO_COHORT_BUDGET_EXHAUSTED`, `WB_CLCO_LIMIT_REACHED`, `WB_CLCO_SESSION_CLOSED` | 수업 사용량·한도·이용 시간 | 유료 요청 반복하지 않고 담당자·시간 확인 |
| `WB_CLCO_RATE_LIMITED`, `WB_CLCO_TIMEOUT`, `WB_CLCO_NETWORK_ERROR` | 요청 제한·응답 지연·네트워크 장애 | 앱 실행/네트워크 확인 → 잠시 뒤 **직접** 점검. 자동 재시도·임의 대체 연결 없음 |
| `ON_AI_MODEL_LIST_EMPTY` / `MODEL_NOT_CONFIGURED` | 앱에 승인된 모델 없음 | 담당자에게 모델 허용 설정 확인. 목록 0건은 모델 설명 성공 아님 |
| `ON_AI_INVALID_OUTPUT` / `AI_REQUEST_UNVERIFIED` | AI 근거/응답 확인 불가 | 근거·현재 기록 재확인, AI 설명 불가로 표시. 기존 보안 기록은 그대로 |
| `ACTION_TIMEOUT` / `ACTION_RESULT_UNVERIFIED` / `unknown` | 원천 효과 불명 | 「원천 결과만 재조회」로 **조회만** 진행. `pending` ACK·화면 취소는 효과 확인/집행 취소가 아님 |
| `CANCELLED` / `REQUEST_CANCELLED` | 사용자의 조회/요청 취소 | 늦게 온 과거 결과를 현재로 표시하지 않음; 사용자가 필요할 때 직접 다시 조회 |
| OSV `not_configured` | 대상 프로젝트 설정 없음 | 담당자 승인 대상 경로가 필요. 취약점 0건이라고 주장 금지 |
| OSV `not_checked` | 승인된 공개 조회 패키지 없음 | 아직 OSV 검색 안 함. 안전함 뜻 아님 |
| OSV `partial` / `unverifiable` | 일부 실패 또는 설치 목록 확인 불가 | 이미 받은 취약점 ID는 남김. `none_found`는 해당 조회 범위에 알려진 항목이 없다는 뜻일 뿐 |
| `demo` / 정상 응답 0건 | 예제 또는 확인된 범위 내 빈 목록 | 미연결·오류·정상 빈 목록을 분리, 실사용 성공으로 작성하지 않음 |

오류 확인은 **보호 현황 → 「도움정보 불러오기」 → 직접 내용 확인 → 「확인했으며 복사합니다」** 순서다. 앱 AI 승인 문제는 「연결 도움정보 보기」를 사용한다. 비밀 자격·확인 번호·토큰·비밀번호는 채팅·Git·제출물에 남기지 않는다. 자세한 운영 문제는 제공 `docs/CONNECTION_TROUBLESHOOT.md`와 `docs/AI_SETUP_GUIDE.md`를 따른다.

## 8. 확인 범위·재현 기록(실행/코드/모의 구분)

| 확인 항목 | 근거 | 이 문서 작성 시 상태 |
|---|---|---|
| 앱 이름·버전·Node 엔진·시작 도구 | `on-client/package.json`, `tools/start-alekov.ps1`, `on-client/README.md` | **[코드 확인]** |
| 메뉴·학생 기능·에러 계약 | `public/index.html`, `public/app.js`, `student/extension.mjs` | **[코드 확인]** |
| Git 커밋·원문 위치 | 사용자가 `D:\share\choi-bujang-secret-vault`에서 `git fetch origin main`·`git cat-file -e` 성공 결과 공유 | **[사용자 실행]** |
| 공식 원문 JSON 생성 | 기존 `D:\share\alekov-source-tool`과 `npx --yes node@24`로 JSON 생성 후 파일 7개 원문 대조 | **[사용자 실행]; 앱 실행과 무관** |
| 학생 DOM 표시 | 대화에서 18단계 34개·19단계 40개·20단계 36개 모의 입력 검사 | **[모의 확인]; 운영 화면 아님** |
| 새 PowerShell에서 지원 Node 버전으로 앱 기동 | `node --version` 및 `start-alekov.ps1` 재실행의 새 관측 없음 | **[미확인/UNV]** |
| 브라우저 접속·종료·재기동 | 실제 PC 브라우저·PowerShell 성공 출력 없음 | **[미확인/UNV]** |
| SDP 로그인·앱 접근·실제 XDR | 본인 시스템 승인/운영자 호스트 설정 미검증 | **[미확인/UNV]** |
| AI 앱 권한·유료 사건 설명 | 실제 모델 수용 미검증. 과거 공개된 17단계 피드백에서 `ai_model_called` 확인 불가였음 | **[미확인/UNV]** |
| 사람 확인 후 원천 조치·효과 | 운영 집행기 및 대상 권한 연결 미검증, 현재 사건의 `supportedActions`는 비어 있을 수 있음 | **[미확인/UNV]** |
| lock 설치 메타데이터와 실제 OSV | 운영자 프로젝트 경로/허용 공개 패키지와 조회 결과 미검증 | **[미확인/UNV]** |
| ALEPH 21단계 통과/22단계 개방 | 실제 포털 제출·판정 별개 | **[미확인/UNV]** |

**새 환경 확인 기록 템플릿(실측 전에는 ‘미확인’으로 보존):**

| 시각 | 위치 / 명령 또는 버튼 | 관측한 출력·상태 | 판정 |
|---|---|---|---|
| 미기록 | Git 최상위 `git status --short` / `Test-Path` | 미관측 | 미확인 |
| 미기록 | 앱 폴더 `node --version` | 새 창 결과 미관측(이전 Node 26) | 미확인 |
| 미기록 | 앱 폴더 `start-alekov.ps1` | 정상 서버 출력 미관측 | 미확인 |
| 미기록 | 브라우저 `http://127.0.0.1:5189/` | 실제 화면 미관측 | 미확인 |
| 미기록 | 실행 창 `Ctrl+C` 뒤 재실행 | 종료/재실행 미관측 | 미확인 |

22단계에서 이 표를 실제 출력과 확인 시각으로 갱신할 수 있지만, 오늘 확인하지 않은 내용을 임의로 채우지 않는다.

## 9. 21단계 제출과 Git 원문 전달

1. Git 최상위 `D:\share\choi-bujang-secret-vault`에서 **새 학생 문서만 저장된 커밋**을 확인한다. 기존 제공 원본·Git 이력을 재설정/덮어쓰지 않는다.
2. **21·22단계는 ALEPH 과제 화면에 저장소 URL과 40자리 커밋을 직접 입력한다.** 기존 Workbench 「포털 제출 준비」는 **13~20단계**까지 지원한다고 공식 과제 화면에 명시돼 있다.
3. 비공개 원문 도구는 `D:\share\alekov-source-tool\student-source-cli.mjs`이고 출력은 Git 프로젝트 밖의 `D:\share\alekov-submit`에 새 JSON 파일로 만든다. **Node 22~24**, `--commit` 뒤 40자리 제출 커밋을 지정하고 Git 최상위에서 실행한다. 도구는 **커밋된 소스만** 묶으며 학생 코드를 실행하거나 제출하지 않는다.
4. JSON을 21단계의 「비공개 저장소 원문 묶음(JSON)」에서 직접 선택한다. 저장소·커밋·단계를 맞춘 뒤 사용자가 **「21단계 제출」**을 누른다. 원문 전달과 AI 판정 통과는 별도이며, 원문만 전달 실패 시 해당 접수에서 「원문만 다시 보내기」를 사용한다.
5. 설정·보관함·인증값은 Git·문서·대화로 복사하지 않는다. `.env` 및 개인 인증 설정 파일의 값은 본 문서에 기록하지 않는다.

**공식 참조:** `on-client/README.md`, `package.json`, `docs/STUDENT_LAUNCH_GUIDE.md`, `docs/GETTING_STARTED_STUDENT.md`, `docs/IMPLEMENTATION_CONTRACT.md`, `docs/CONNECTION_TROUBLESHOOT.md`, `docs/AI_SETUP_GUIDE.md`, `.on-starter-manifest.json`, `public/index.html`, `public/app.js`, `public/vulnerabilities-view.mjs`, `src/server.mjs`, `src/ai/service.mjs`, `src/vulnerabilities/project-scan.mjs`, `src/vulnerabilities/osv.mjs`, `student/extension.mjs`.

**작성 원칙:** 문서가 코드에 일치하는지를 검사했으며, 실제 PC의 운영 연결이나 공식 통과를 대신 주장하지 않는다.
