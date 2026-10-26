# 워치독스 · 마지막 총공세 1일차 개선 기록

> **작전:** 기록 타임라인형(사건 발생 시각 최신순 / 종류별 거르기). **포장 목표:** 기존 과정 포장 후 Inno Setup의 사용자 단위 `setup.exe`(6일차 예정). **현재 앱 버전:** `on-client/package.json`의 `0.2.11` 유지. **수정 전 기준 Git 커밋:** `5baf9bad8762688d9d8927e0879fd919ce228c80`.

## 오늘 확정한 핵심 기능 3가지

| 우선순위 | 기능 | 기존 사실·이번 개선 | 미확인 경계 |
|---|---|---|---|
| 1 | 보안 기록 타임라인 | 학생 `renderEvents`의 기존 발생 시각(`at`) 내림차순 정렬·기록 종류/업무 앱/접속 상태 필터·사건 상세를 유지하고 타임라인·실제 반환 건수·종류별 수·발생 시각 레이블을 강화 | 기본 실행 `ENGINE_NOT_CONNECTED`. 실제 XDR 서버 기록의 조회·필터 동작은 미확인 |
| 2 | 내 계정/기기/세션 연결 상태 | `renderIdentity`, `renderStatus`에서 현재 자원의 `loading/error/ok` 상태와 연결 모드를 카드/글자로 구분. PC의 전체 Windows 보안·백신 상태라고 주장하지 않음 | 운영 SDP 연결·운영체제 보안 측정 미확인 |
| 3 | 조회 오류·주의 알림 | `renderStatus`의 기존 `notifications` 목록을 읽기 좋은 카드로 바꾸고 `ENGINE_NOT_CONNECTED`, `CONTRACT_MISMATCH`, 기타 조회 경고를 구분. 실제 XDR 사건과 혼동하지 않도록 범위를 설명 | 실제 위험 탐지·새로운 실시간 알림 기능을 추가한 것이 아님 |

## 변경 파일과 이유

- `on-client/student/extension.mjs`: 위 3개 학생 출력 함수의 DOM 구성·시각적 클래스·상태 문구 개선. 이미 구현된 `renderDecision`, `renderExplanation`, `renderAction`, `renderVulnerabilities`, `renderAiConnection`의 함수명·입력 계약·실행 요청 흐름은 변경하지 않음.
- `student/extension.mjs`: 기존에 동일한 내용으로 제출해 온 루트 학생 원문 사본. **두 파일을 계속 동일하게 동기화**해 누적 소스 불일치를 방지.
- `on-client/public/style.css`: 승인한 범위 내에서 타임라인·상태 카드·알림·좁은 화면 CSS 보강. 색만으로 의미 전달하지 않으며 키보드 초점 스타일 유지.
- `on-client/docs/STUDENT_FINAL_OFFENSIVE.md`: 기능 선정·근거·실행 및 결과 구분 기록.

**변경하지 않는 파일:** `on-client/public/app.js`, `on-client/public/index.html`, `on-client/src/server.mjs`, 모든 인증·판정·운영 설정, 13~22단계의 기존 실행/제출 기록. 새 네트워크·AI 유료 요청·조치 실행·추가 데이터 저장을 도입하지 않는다.

## 실제 확인한 결과 / 변경 후 확인할 결과

| 대상 | 현황 | 근거 |
|---|---|---|
| 22단계 이전 로컬 기본 화면 | **사용자 실행 관측** | 2026-10-26, 별도 복제본에서 Node.js 24.19.0, 서버 시작·종료·재시작, `ENGINE_NOT_CONNECTED` 화면 확인. 해당 기록은 `STUDENT_RELEASE_REPRODUCTION.md`에 보존 |
| 이번 1일차 학생 함수 | **코드 변경 및 모의 DOM 확인만** | 실제 Windows 브라우저 변경 후 시연은 **미확인**. 함수 유효성, 오류/예제/빈 목록/종류 필터, 상세 열기 등은 모의 검사 대상 |
| 실제 보안 데이터·위험 탐지 | **미확인** | 엔진/운영 XDR·AI·OSV 미연결. 어떤 설명용 수치도 실제 측정으로 쓰지 않음 |
| 포장 `npm run package-app` / 설치 프로그램 | **미구현, 6일차 예정** | 제공 `on-client/package.json`에 해당 포장 스크립트 없음. `setup.exe`를 이미 만들었다고 주장하지 않음 |

## 동일 결과를 다시 확인하는 방법

기존 작업 폴더 `D:\share\choi-bujang-secret-vault`를 보존한다. 제공 파일 변경·코드 개선 결과는 **GitHub 최신 커밋을 로컬로 안전하게 동기화한 뒤** 확인한다. 원본 `public/data.json`의 미커밋 변경이 있으므로 `git reset --hard`, `git clean`을 사용하지 않는다.

~~~powershell
Set-Location "D:\share\choi-bujang-secret-vault"
git status --short
git fetch origin main
# 로컬 main에서 fast-forward 가능한 경우에만
git merge --ff-only origin/main
Set-Location ".\on-client"
node --version  # 공식 실행은 Node.js 24.19.0 권장
node --check ".\student\extension.mjs"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\tools\start-alekov.ps1"
~~~

브라우저 `http://127.0.0.1:5189/`에서 다음을 구분해 확인한다. `보호 현황`은 현재 계정/기기/세션 오류 상태와 알림을, `보안 기록`은 기록 데이터가 실제 반환됐을 때 타임라인과 필터를 보여 준다. **미연결 상태에서 기록 0건이라고 표시하지 않고 오류를 보존**한다. 어떤 데이터가 보이더라도 `예제 자료(demo)`는 실제 서버 자료가 아니다.

## 보존·향후 작업

- 미커밋 `public/data.json`, 기존 제출 기록, 운영 자격·토큰은 수정하거나 복사하지 않는다.
- 2~5일차에 화면 완성도·접근성·실제 사용자 동선을 검토하고, 6일차에 제공 포장 도구 계약이 있을 경우 `npm run package-app`을 설치·점검하고 설치 스크립트를 별도로 준비한다.
- 설치 목표는 **Inno Setup 사용자 단위 설치**. 제공 포장 도구와 포함될 Node 런타임·바로가기 실행 절차는 **아직 확인되지 않아 미구현**으로 적는다. Defender/SmartScreen 등 보호 기능 끄기를 설치 지침으로 사용하지 않는다.
