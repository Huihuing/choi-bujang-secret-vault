# BYTE BACK · 12단계 저장점 — 탈환 작전실

## 보너스 xdr-03 후속 · X03_CLEAR_NOT_BLOCKED / X03_AMBIGUOUS_NOT_ALERT

최초 공식 심판 30점에서는 명확한 공격 차단 건수가 부족하고 애매한 알림 건수가 맞지 않았습니다. 이에 요청 원문의 완전한 JNDI 식만을 `block`으로 처리하던 판단을 보강했습니다. 심판의 비공개 경보와 정답표는 직접 확인하지 못했으므로 **해결 여부는 아직 공식 미검증**입니다.

- **구조적 반복 악용 차단:** Wazuh가 `rule.mitre`에 T1190을 부여하고 `rule.level >= 10`, `data.count >= 5`이며 설명에 Log4j·JNDI·원격 조회·CVE 악용 관련 근거가 있고 단순 스캐너/점검 기록만은 아닐 때 `log4shell-repeated-exploit`로 `block`(0.96)합니다.
- **기존 확정 문자열 탐지:** HTTP 요청에 뚜렷한 JNDI 원격 조회 문법이 있을 때의 `block`(0.97)은 유지합니다. URL 이중 인코딩, `lower`, `upper`, 문자 분리 및 단일 문자 `env:VAR:-x` 기본값 변형을 한정된 횟수로 정규화합니다. 로그 문자열 자체를 실행하지 않습니다.
- **오탐 보호:** 정상 문서 조회와 로그4j 패치 안내처럼 T1190이 없는 낮은 수준(3 이하)의 경보는 `record`합니다. 점검 도구/스캔 표식만 남았거나 1회 관측된 요청은 `alert`로 두고 IP 차단을 생성하지 않습니다. 근거가 부족한 경우 명확한 공격으로 과장하지 않습니다.
- **검증:** 기존 18건 가상 경보는 여전히 `block 6 / alert 6 / record 6`, 정상 오차단 0건입니다. 새 회귀 테스트 7건에서 키트와 유사한 고수준·반복 경보, 점검 전용 경보, 불완전한 근거, 일반 문서, 헤더/인코딩 변형을 검사했습니다. `npm run xdr:test` **18/18 성공**, `npm run xdr:run -- known-cve` 결과 일치, 기존 XDR 및 1~12단계 자동 검사도 성공했습니다.
- **변경 경계:** 판정 파일 `xdr/known-cve/decide.mjs`, 동기화한 `patterns.json`, 테스트, 이 문서만 변경했습니다. `src/decider.mjs`나 기존 차단·복구 API, 실제 DB 자료는 변경하지 않았습니다.

---

## 보너스 xdr-03 저장점 · 알려진 CVE 악용 탐지

이 모듈은 기존 ZTNA 규칙을 **대체하지 않고 추가 확인 단계**로 연결됩니다. `src/decider.mjs`의 판정 규칙은 변경하지 않았으며, `src/xdr-decider.mjs`가 기존 brute-force·web-injection 임시 거부 규칙에 `known-cve` 규칙을 추가로 읽어 옵니다.

- **독립 판정:** `xdr/known-cve/decide.mjs`의 `decide(alert)`는 import·파일 접근·외부 API 없이 단독 실행됩니다. 입력 HTTP 경로·인자·헤더의 구체적인 JNDI 조회 신호는 `block`(0.97), CVE/T1190 점검 흔적만 있는 경우 `alert`(0.6~0.75), 정상 로그는 `record`(0.05)입니다. 임계값은 0.85/0.5입니다. 패턴은 `xdr/known-cve/patterns.json`에 근거와 함께 있습니다.
- **읽기 전용 추출:** `xdr/known-cve/read-alerts.mjs`는 Wazuh의 시간·출발 IP·계정·규칙 수준·설명만 추출하고 비밀값처럼 보이는 문자열을 가립니다. `decide.mjs`에서 이 모듈을 import하지 않습니다.
- **제공 fixture 상태:** 기존 저장소에 `xdr/fixtures/known-cve.json`이 **없어서 새로 만든 교육용 가상 경보 18건**으로 시험했습니다. 원본 교육용 경보를 확보한 것은 아니며, 향후 제공되는 실제 강의 fixture로 교체해 다시 확인해야 합니다. 가상 경보에는 문서용 TEST-NET 주소와 `.invalid` 예시만 사용했습니다.
- **응답·연결:** `xdr/known-cve/respond.mjs`는 실제 입력 경보에서도 다시 명확한 신호를 확인한 `block`에만 출발 주소별 15분 임시 거부 규칙·근거 경보 ID를 붙입니다. 같은 처리 묶음에 정상 활동이 확인된 공유 주소는 차단 후보에서 제외합니다. `alert`/ `record`는 거부 규칙으로 만들지 않습니다. `xdr/alerts.log`에는 본문이나 토큰 대신 비민감 경보 ID·분류·패턴만 저장합니다. 기한이 지난 규칙은 ZTNA 연결부에서 적용하지 않습니다.
- **실행:** `npm ci` → `npm run xdr:test` → `npm run xdr:run -- known-cve`. 산출물은 `xdr/known-cve/result.json`, `xdr/known-cve/deny-rules.json`, `xdr/alerts.log`입니다. 강의용 가상 경보 18건 결과는 **block 6 · alert 6 · record 6 · 정상 차단 0**입니다.
- **중지·복구:** 신규 경보 입력을 중지하고 15분이 경과하면 임시 규칙이 만료됩니다. `src/xdr-decider.mjs`에서 모듈 등록 한 줄을 빼거나 `xdr/known-cve/deny-rules.json`을 `[]`로 만들면 이 모듈의 추가 차단만 중지할 수 있습니다. 기존 판정 규칙·이전 XDR 모듈은 보존해야 합니다.
- **범위:** 이번 결과는 오프라인 합성 경보와 GitHub Actions에서 검증한 것이며, 실제 악용 차단이나 운영 ALEPH 심판 합격은 확인하지 않았습니다. 이 탐지는 취약한 Log4j 버전의 **업데이트를 대체하지 않습니다**.

패턴 출처: [NVD CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) · [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/).

---


## 최신 검증 실험 · 전체 not_run 및 앱 기준 확인 건수

마지막 판정 `S12_SCREEN_MISMATCH`의 원인은 아직 심판 내부 원장으로 확정하지 못했습니다. 이전 수정에서 ‘세 GET/HEAD 요청은 심판이 인식했다’고 서술했지만, 판정 문구는 오히려 그 `attackId`들의 요청 기록이 없다고 지적했습니다. 따라서 **이전 서술을 검증된 사실로 취급하지 않습니다.**

이번 커밋에서는 12단계 제출 묶음의 20개 점검을 모두 `observed: "not_run"`으로 기록하며, 격리 `npm run bundle` 실행 시 외부 HTTP 요청을 보내지 않습니다. 해당 점검의 미실행 표시는 **심판이 공격을 막지 못했다는 의미가 아니라**, 실행과 `attackId`를 연결할 증거가 없다는 의미입니다.

화면의 `41건 미실행 · 확인된 막음 0건 · 확인된 통과 0건` 역시 **이 앱이 확보한 공식 사건별 판정 증거 기준**입니다. 독립적인 ALEPH SDP 심판이 실제로 격파한 공격 수나 최종 판정 점수가 0이라는 주장이 아닙니다. 공개 실측 GET/HEAD 자가 검사 표와 DB에서 읽은 운영 집계는 유지하지만, 이 자료는 공식 판정기에 연결된 검증으로 간주하지 않습니다.

실험 결과 확인: `node --test test/stage12.test.mjs`는 **20건 not_run/네트워크 0회**를, `node --test test/stage12-public.test.mjs`는 화면의 구분 표시를 검사합니다. `npm run bundle` 및 기존 회귀 테스트도 확인한 뒤 제출하며 공식 통과 여부는 재채점 전까지 미확인입니다.

---


## 최신 수정 · S12_SCREEN_MISMATCH의 실측 API 증거 복원

직전 심판 기록에서 제출 묶음의 요청 20건 중 **`anonymous_notes_denied`, `deployment_identity_step12`, `first_page_security_header` 세 건은 실제 요청으로 확인**되었고, 다른 실행 주장 15건에 대응하는 요청 기록은 발견되지 않았습니다. 이후 보수적 수정에서 이 세 건까지 `not_run` 처리한 것은 12단계가 요구하는 정상·거부 실측 HTTP 결과를 없애는 문제가 있었습니다.

- **이번 변경:** `npm run bundle`의 12단계에서는 `GET /api/notes`, `GET /aleph.json`, `HEAD /`만 실제 실행해 관측된 HTTP 결과를 `observed`에 기록합니다. 요청 기록이 확인되지 않은 **나머지 17건은 `not_run`**으로 둡니다. 변경 요청(POST·PUT 등)은 제출 묶음에서 절대 보내지 않습니다.
- **작전실 화면:** 로그인 없이 접근 가능한 ‘제출 단계와 연결되는 공개 GET·HEAD 실측’ 표에서도 동일한 세 API를 GET·HEAD로 읽고, 기대 결과·실제 상태 코드·검사 시각·일치 여부를 표시합니다. 해당 브라우저 기록은 공식 ALEPH SDP 심판의 41종 결과가 아닙니다.
- **운영 집계:** 공개 DB 집계 패널은 데이터베이스 실제 수치만 표시하고, 제공 엔진의 신원 회수·탐지 로그 및 41종 실전 판정은 `미확인`을 유지합니다. 메모 본문·개인키·토큰은 어떤 공개 API에도 포함하지 않습니다.
- **검증:** `node --test test/stage12.test.mjs`, `node --test test/stage12-public.test.mjs`, `npm run bundle`에서 GET·HEAD 이외의 요청이 없는지, 세 실측/17 미실행 기록이 일치하는지 확인합니다. 최종 심판 재판정은 별도 확인이 필요합니다.

---


## S12_SCREEN_MISMATCH 후속: 로그인 전 운영 수치 실측 패널

- **발견한 표시 오류:** 12단계 배포 첫 화면이 `STEP 11`로 보였고, 실제로는 한 행만 있는 공식 사건 안내를 `41개 항목`처럼 설명했습니다. 둘 다 12단계 표기와 미연결 안내로 바로잡았습니다.
- **가린 서버 기록을 읽는 방법:** `GET /api/war-room-summary`가 공개 가능한 **비민감 운영 집계만** 읽습니다. Vercel 서버가 서비스 권한으로 `stage12_public_operational_snapshot()` DB RPC를 호출한 뒤 계정 ID·메모 본문·JWT·기기 자격 식별자 없이 판정 *코드 선언 수*, 기기 상태별 **합산 건수**, 복구 감사 건수, 안전 HTTP 검사 건수, 검증된 기준 백업 버전, **DB가 관측한 시각과 배포 커밋**만 반환합니다. 함수 실행 권한은 `service_role`에만 있고 DB 소유 정보는 이 JSON에 포함되지 않습니다. 동일 SQL은 `db/stage12-public-operational-snapshot.sql`에 기록했습니다.
- **로그인 전에도 표시:** `public/war-summary.js`는 첫 화면에서 실제 공개 API를 GET 요청하여 받은 값만 표시합니다. HTTP 오류·불완전한 값은 `미확인`으로 두며, `0`은 서버가 실제로 0을 반환했을 때만 표시합니다. 9단계 **ALEPH SDP 엔진의** 탐지·회수 로그와 공식 41종 심판 기록은 여전히 미연동(`null`)입니다.
- **보호 범위 유지:** `/api/notes`와 계정별 `/api/war-room`은 기존 인증/보호 정책을 계속 적용합니다. 공개 페이지는 개인별 사건·메모나 실제 공격 세부 내용을 노출하지 않습니다.
- **실측 확인:** 2026-10-13 운영 `GET /api/war-room-summary`에서 **HTTP 200**, `schema:byteback.public-operations.v1`, `source:server_database_aggregate`, 단계 12, 데이터베이스 관측 시각과 실측 집계를 확인했습니다. 실제 비로그인 홈페이지도 **HTTP 200**, STEP 12 및 공개 집계 패널 노출을 확인했습니다. 심판의 최신 공식 통과 여부는 **미확인**입니다.
- **재현:** `node --test test/stage12-public.test.mjs`로 스키마 숫자/누락·화면 표시·DB 권한 선언을 검사하고, 사이트에서 ‘서버 집계 다시 확인’ 버튼으로 값을 재조회합니다. `npm run bundle`은 격리 환경에서 POST/PUT을 보내지 않고 증거가 없는 공격 항목을 `not_run`으로 유지합니다.

---

## 12단계 공식 재채점 S12_SCREEN_MISMATCH 수정 기록

최초 12단계 격리 심판은 `S12_BUNDLE_UNSUPPORTED`(제출 단계의 POST 호출)을 보고했고, 이어진 재채점은 `S12_SCREEN_MISMATCH` 및 요청 기록 대조 실패(20개 제출 점검 중 18개에서 대응하는 `attackId`의 심판 요청 추적 없음)를 보고했습니다. 두 기록을 섞어 ‘41종 공격 통과’라고 주장하지 않습니다.

- **제출 묶음:** 격리 환경이 허용하는 GET/HEAD 범위 안이라도 심판의 개별 `attackId`에 연결된 요청 추적을 확인할 수 없으면 ‘실제 공격 검증’으로 기록하지 않습니다. `src/attack-check.mjs`의 12단계 점검 20건은 모두 `observed: "not_run"`이며, 12단계 묶음을 위해 재현 불가능한 외부 요청을 추가 실행하지 않습니다. 이는 정상/금지 방어의 통과가 아니라 **증거 부재의 정직한 표시**입니다. 별도 이전 단계와 로컬 검사는 이전 코드에 유지합니다.
- **실제 HTTP 근거:** `POST /api/war-room-check`의 서버가 미리 등록한 안전한 검사만 수행하며, 확인한 상태 코드·UUID 요청 ID·시각은 계정별 `app_ops_checks` DB 기록으로 남습니다. 화면 표는 이 기록만 실측으로 표시합니다. 로그인·등록 기기와 실제 판정 공격은 독립적인 심판 증거 없이는 미실행/미확인으로 둡니다.
- **화면 수치:** `/api/war-room`은 현재 계정의 승인·회수·복구·안전 점검 DB 값이 존재하고 유효할 때만 수치로 제공합니다. 코드 규칙 개수는 ‘소스코드 선언’으로, 엔진 탐지·신원 회수·공식 41종 개별 결과는 ‘미연결/미확인’으로 구별합니다. 자료가 없는데 `0`으로 채우거나 가상 공식 요청 41건을 생성하지 않습니다.
- **회귀 검증:** `node --test test/stage12.test.mjs`에서 12단계 제출 점검 20건이 외부 요청 없이 `not_run`인지 검증합니다. `npm run bundle`은 CI에서 깨끗한 커밋을 기준으로 수행합니다. **공식 심판의 재채점 결과는 아직 미확인**입니다.

---


**현재 단계: 12단계 「탈환 작전실을 완성합니다」.** 마지막 11단계 저장점 `31bb1f7d9440`을 이어받아 서버 증거 기반 작전실과 안전 HTTP 검사 이력을 추가했습니다. 기존 단계의 판정·탐지·JWT 검증·WebAuthn·단건 복구 코드를 수정하거나 약화하지 않았습니다.

## 출처 및 작업 구분

- **제공 엔진:** `ALEPH SDP 엔진`. 가상 사용자·기기·신원·정확한 요청 경로 확인, 심판 사건 전송, 최종 공격 판정과 41종 채점은 **제공 엔진/공식 심판**의 역할입니다. 이 저장소는 엔진 소스가 아닙니다.
- **학생 구현:** `src/decider.mjs` 판정 규칙, `src/detect.mjs` 9단계 조회 급증 탐지·회수 제안, `api/notes*.js` 및 `api/instructor-notices*.js` 자료실, `api/restore.js` + `db/stage10-*.sql` 검증 복구, `api/device.js`, `api/app-request.js`, `src/app-webauthn.mjs` 기기 등록/서명 검사, PWA 및 **12단계 작전실**입니다.
- **12단계 새 기능:** `api/war-room.js`에서 로그인한 계정 범위의 기기 승인·회수 건수, 복원 감사 이벤트 수와 `stage10_policy_preview`가 다시 읽어 검증한 복구 버전을 집계합니다. `src/decider.mjs`의 실제 규칙 ID는 **코드에 등록된 규칙**이지 심판의 실측 통과 증거가 아닙니다. 엔진 탐지 사건·회수 집행 데이터는 이 저장소에 수집 경로가 없어 **미연결**이라고 표시합니다.
- **기록 경로:** `GET /api/war-room` 및 `GET|POST /api/war-room-check`는 서명 검증된 학생 JWT가 필요하고, 계정별 메타데이터만 읽거나 고정된 안전 HTTP 검사를 실행합니다. `db/stage12-operations.sql`의 RLS 보호된 `app_ops_checks`에는 검사 ID, 고정 대상 이름, 기대 HTTP, 실제 HTTP 또는 null, 비교 결과, UTC 시간만 남습니다. **비밀번호·토큰·메모 본문·기기 개인키·실명은 저장하지 않습니다.**

## 대시보드가 증명할 수 있는 것과 없는 것

| 표시 항목 | 실제 근거 | 해석 |
|---|---|---|
| 등록 판정 규칙 | 저장소 `RULE_IDS` | 코드 구현 수, **실전 판정 수 아님** |
| 탐지 사건 / 9단계 권한 회수 | 엔진 사건·회수 로그 **미연결** | 미확인; 0건 또는 통과라고 추정하지 않음 |
| 기기 승인·회수 | `stage12_ops_summary` DB RPC | 로그인한 계정의 현재 기기 상태 실측 |
| 복구 버전·정책 차이 | `stage10_policy_preview` DB RPC | 해시가 검증된 백업 버전·시험 정책 차이 |
| 복구 이력 | `restore_audit` DB 조회 | 현재 로그인 계정의 실제 복원 감사 이벤트 수 |
| 대표 정상/거부 HTTP | `/api/war-room-check`의 고정된 익명·공개 조회 | 실측 상태 코드 + 요청 ID + UTC 시각. 테스트의 HTTP 예상값과 비교한 결과에 한정 |
| 41종 공식 총공세 | 공식 심판 사건별 결과 **미연동** | 41개 슬롯 **미확인**, 검사나 통과로 세지 않음 |

### 1~11단계 회귀 시험 표 작성 절차

1. [운영 작전실](https://choi-bujang-secret-vault-jwnp.vercel.app/)에서 로그인한 뒤 **‘운영 상태 다시 읽기’**를 선택합니다. 응답이 실패하면 값을 대체해 보여주지 않고 오류를 표시합니다.
2. ‘안전 HTTP 재검사’에서 **한 검사씩** 실행합니다. 서버는 **고정된** 공개 정상·비인증 거부 경로만 호출하며, 임의의 URL·사용자 토큰·메모 본문을 전달하지 않습니다. 테스트당 기록되는 `requestId`, `observedAt`, 실제 상태 `observedStatus`, 기대 `expectedStatus`를 표에서 대조합니다. 네트워크 실패의 실제 HTTP 상태는 `null`, 판정은 실패입니다.
3. **정상 허용**은 공개 페이지·manifest·배포 식별 정보의 HTTP 200을 직접 측정할 수 있습니다. **보호 메모 정상 허용**은 실제 서버 승인된 기기로 WebAuthn 서명을 완료해야 검증되므로 현재 자동 검사에서는 **미실행**으로 둡니다.
4. **타인 메모 거부, 미등록 기기, 회수된 신원, 복원 직후 재공격, 서명 후 경로/본문 변조**는 공식 심판 또는 실제 등록 기기에서 별도로 실측해야 합니다. 가상 단위 테스트의 통과는 운영 E2E 결과로 옮겨 적지 않습니다.
5. 심판 개별 항목의 공식 요청 ID·시각·기대·결과는 공식 판정 기록이 확보될 때만 별도 대응표에 추가합니다. 현재 공식 41종 공격 결과 API가 없어 화면은 모든 개별 슬롯을 **‘미확인’**으로 표시합니다. 사용자 화면 성공 문구는 심판 근거가 아닙니다.

## 설치 · 실행 · 중지 · 복구 · 재현

1. **소스 검사·설치:** `git clone https://github.com/Huihuing/choi-bujang-secret-vault.git`, `cd choi-bujang-secret-vault`, `git log -1 --oneline`, `git status --short`, `npm ci`. 실제 검사 커밋은 위 `git log -1`과 화면의 `/aleph.json` 커밋이 일치해야 합니다.
2. **로컬 화면 빌드:** Node.js 22 이상에서 `npm run build -- --local`. 정적 UI를 미리보기하려면 `python -m http.server 8080 --directory public`을 실행해 `http://localhost:8080`에 접속합니다. **로컬 HTTP 서버에는 Vercel API가 없으며**, 공개 배포 호스트에 묶인 WebAuthn 등록/보호 API는 로컬 미리보기에서 동작한다고 가정하면 안 됩니다.
3. **실제 실행·PWA 설치:** Vercel이 `main`을 배포하면 위 운영 HTTPS 주소에 접속합니다. Chrome/Edge의 **앱 설치** 메뉴를 사용해 PWA로 실행합니다. 설치 표시는 기기 승인이 아닙니다. Supabase의 환경변수는 운영 Vercel 비밀 설정에만 두고 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `SUPABASE_PUBLISHABLE_KEY` **값은 Git/제출 파일에 포함하지 않습니다**.
4. **실행 확인:** 학생 계정으로 로그인하여 기기 등록 요청(기본 `pending`) → 별도 신원 확인된 관리자만 승인 → WebAuthn 서명으로 보호 메모 접근을 확인합니다. 별도 로그인으로 작전실의 안전 HTTP 검사를 하나씩 실행하여 실제 결과를 남깁니다.
5. **중지:** 로컬 서버는 `Ctrl+C`로 중지합니다. PWA는 창을 닫거나 브라우저에서 제거합니다. **앱 종료·삭제는 승인 회수가 아닙니다.** 신뢰된 관리자만 `db/stage11-device-approval.sql`에 적힌 절차로 등록 기기를 `revoked`로 변경합니다.
6. **복구:** `db/stage10-recovery.sql`, `db/stage10-backup-preflight.sql`의 기존 *검증된* 사본을 먼저 재검증하고, 심판용 서명 B 신원에서 `POST /api/restore`에 `{"id":"대상 메모 UUID","dryRun":true}`로 변경 범위를 확인한 다음, 같은 ID를 dryRun 없이 지정하여 **한 건만** 복원합니다. 감사 기록을 보존하고 1~11단계 정상·금지 사례를 다시 검사합니다. **사본 유실·해시 오류 시 복원 중단**, 실운영 자료를 임의로 덮어쓰지 않습니다.
7. **회귀 테스트:** `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`, `npm run test:r8`, `node --test test/stage10.test.mjs`, `node --test test/stage11.test.mjs`, `node --test test/stage12.test.mjs`, `npm run xdr:test`, `npm run build -- --local`. 저장소를 커밋한 뒤 CI가 `npm run bundle`을 실행하여 무시된 `artifacts/submission.json`을 생성합니다.
8. **실행 기록 구분:** CI에서 통과한 단위/합성 검사, 배포 API의 실측 정상/거부, 실기기 승인 E2E, 심판 41종 최종 평가를 **서로 다른 결과**로 기록합니다. 미실행·미연동은 통과나 0건으로 변환하지 않습니다.

**되돌리기:** 저장소의 `git status`와 `git diff`를 먼저 확인한 뒤 12단계 변경 파일만 골라 이전 정상 커밋 `31bb1f7d9440`과 대조합니다. DB 사본·감사 로그·다른 작업을 지우지 않고, 강제 초기화(`reset --hard`)를 사용하지 않습니다.

---

# BYTE BACK 방어전 · 11단계 저장점 — 나만의 접속 앱

현재 단계 **11단계 「나만의 접속 앱을 완성합니다」**. 이전 1~10단계의 심판용 가상 판정기·JWT A/B 검증·메모 소유자 검사·복원 경로를 보존합니다. 기존 10단계 마지막 저장점 `2b8a8d3f509e` 위에 PWA와 별도 학생 기기 증명 경로를 추가했습니다.

## 설치형 화면과 기기 승인

- **호환 아이콘:** 빌드 과정에서 SVG 로고를 바탕으로 192×192·512×512 PNG 아이콘을 생성하고, manifest에 SVG/PNG 모두 등록합니다. 일부 플랫폼의 PNG 요구 사항을 충족하기 위한 정적 자산이며 인증·메모 자료와 무관합니다.
- **설치형 웹앱(PWA):** `/`의 새로운 로그인·기기 상태·메모 화면, `/manifest.webmanifest`, `/icon.svg`, `/sw.js`. 따로 설치할 EXE는 없습니다. 브라우저의 ‘앱 설치’/‘홈 화면에 추가’를 사용하세요. **설치 여부만으로 기기 승인이라고 표시하거나 권한을 부여하지 않습니다.**
- **오프라인:** 정적 화면에만 네트워크 오류 안내를 제공하고, `/api/*`와 메모·토큰·기기 키를 서비스워커 Cache Storage에 저장하지 않습니다. 로그인 SDK도 `persistSession:false`, `autoRefreshToken:false`라 세션 토큰을 로컬/세션 저장소에 영속화하지 않습니다. 메모/로그인 토큰은 현재 탭 메모리에서만 처리합니다.
- **등록 요청:** 로그인 뒤 ‘기기 등록 요청’을 누르면 운영체제 WebAuthn 인증기가 ES256 키로 등록을 수행합니다. **개인키는 앱 JS나 DB로 전송/저장되지 않습니다.** 서버에는 공개키 좌표, credential ID, 사용자 UUID, `pending` 상태만 저장합니다. 승인 버튼만으로 `approved`가 되지 않습니다.
- **관리자 승인:** 안전하게 확인된 사용자·인증기 공개 식별자를 별도 채널에서 대조한 **서버 DB 관리자만** `public.app_devices.status='approved'`로 변경할 수 있습니다. 재확인/승인·회수 절차의 SQL은 `db/stage11-device-approval.sql`에 있습니다. 아직 등록된 실제 기기를 관리자가 승인하여 시험하지 않았으므로 운영 정상 접속 검증은 **미실행**입니다.
- **서버 승인 확인:** `GET /api/device`가 계정의 대기/승인 건수를 조회합니다. `POST /api/device`의 `begin`/ `finish`는 서버의 일회용 WebAuthn 등록 챌린지 검증 뒤 승인 *요청*만 기록합니다.

## 보호 요청 서명과 세 공격에 대한 방어

| 검증 대상 | 구현 | 거부 근거 |
|---|---|---|
| 인증기 서명 없는 보호 요청 | `POST /api/app-request` `begin`/ `execute` | `approved` 공개키와 실제 WebAuthn ES256 서명, 기기 사용자 확인(UP/UV), 일회용 챌린지가 있어야 접근 |
| 서명한 뒤 요청 경로·메서드 교체 | 동일 경로 | 챌린지에 저장된 정확한 `method`, `path`와 실행 요청의 값을 비교, 쿼리·미등록 경로 거부 |
| 서명한 뒤 수정 본문 교체 | 동일 경로 | 챌린지에 저장된 본문의 SHA-256과 실행 요청의 **원문 JSON 문자열** 해시를 비교 |
| 만료·재생 공격 | `stage11_consume_challenge` | 만료 3분, 이미 쓴 챌린지는 트랜잭션 내 원자적으로 소비한 뒤 재사용 거부 |
| 승인 전 직접 서버 API 접근 | `/api/notes`, `/api/notes/:id`, 강사 공지 API | 일반 학생은 내부 서버가 검증한 WebAuthn 증명 없이는 **403 `device_approval_required`**. 기존 심판 A/B JWT 평가 경로는 변경하지 않음 |
| 승인 취소·서명기 복제 의심 | `app_devices` | 실행 직전 승인 상태와 서명 카운터를 조건부 갱신; `revoked`나 재생 요청은 거부 |

WebAuthn 통과는 **등록된 인증기 자격 증명의 소유 및 사용자 확인**을 의미합니다. 제조사/하드웨어 무결성까지 보장하는 기기 인증(attestation)은 구현되어 있지 않으므로 실제 물리 기기의 복제·동기화 여부가 증명됐다고 주장하지 않습니다.

## 실행 및 확인

1. 배포 주소 [운영 자료실](https://choi-bujang-secret-vault-jwnp.vercel.app/)에서 로그인한 뒤 기기 등록을 요청하세요. 서버에 아직 등록·승인된 키가 없다면 메모 목록·추가 창은 **숨김**, 상태는 **승인 대기**여야 합니다.
2. 운영 관리자만 Supabase 관리 화면에서 `app_devices`의 등록 공개키와 계정 소유자를 독립적으로 확인하고 `pending`을 `approved`로 변경합니다. 브라우저에서 ‘승인 상태 새로고침’으로 확인합니다. 이 관리 단계는 사용자가 직접 신원 확인 없이 승인해도 된다는 뜻이 아닙니다.
3. 승인된 동일 인증기의 사용자 확인 절차를 거쳐 `/api/app-request`가 메모를 조회·작성·수정·삭제합니다. 인증을 취소하거나 승인되지 않은 기기에서 요청하면 거부되어야 합니다.
4. 로컬 회귀 검사: `node --test test/stage11.test.mjs && node --test test/stage10.test.mjs && npm run test:r8 && npm run decider:test && npm run detect:test && npm run xdr:test`. `npm run bundle`은 Git 커밋·Vercel 배포 이후 CI에서 실행합니다.
5. **테스트 구분:** 임시 ES256 키로 정상 서명, Origin·RP ID·챌린지 위조, 메서드·경로·본문 변경, 익명·학생 직접 API 거부를 테스트했습니다. 하지만 실제 사용자의 플랫폼 인증기 등록, 서버 관리자 승인과 운영 심판 공격은 **미실행**입니다. 로컬 테스트/빌드 성공이 심판 11단계 통과를 의미하지 않습니다.

보안 데이터는 DB에만 보관하고 GitHub, HTML, 로그, 제출 묶음에는 토큰, 개인키, 메모 내용, 기기 사용자 식별자를 포함하지 않습니다. 새 DB 스키마는 `db/stage11-device-approval.sql`에 재현 가능한 정의만 포함합니다.

---

## 10단계 보완 · 검증된 백업 미리보기 및 실제 복원

**대상 서비스:** `notes` (비공개 메모). **복원 경로:** `POST /api/restore`. 두 요청 모두 서명 검증된 심판 시험 계정 B의 Bearer 인증이 필요합니다.

| 구분 | 서비스 | 메서드·경로 | JSON 본문 | 동작 |
|---|---|---|---|---|
| 실행 전 미리보기 | `notes` | `POST /api/restore` | `{"id":"메모 UUID","dryRun":true}` | 기준 사본 재읽기·해시 검증 후 버전/변경 항목만 반환, **DB 복구/감사 쓰기 없음** |
| 실제 한 건 복원 | `notes` | `POST /api/restore` | `{"id":"메모 UUID"}` | 사본 재검증 후 동일 ID·소유자의 한 건만 복구 |
| 정책 비교 | 시험 정책 `stage10_restore.policy_trial` | `GET /api/recovery-policy` | 없음 | 기준 정책 버전·해시·차이 확인 |
| 정책 되돌리기 | 시험 정책 `stage10_restore.policy_trial` | `POST /api/recovery-policy` | `{"expectedSha256":"미리보기에서 읽은 기준 해시"}` | **시험 정책만** 검증된 사본으로 되돌림, 실제 RLS 변경 없음 |

- 미리보기 성공은 `preview: true`, `backup_verified: true`, `snapshot_version`, `record_sha256`, `content_sha256`, `changed_fields`(예: `["content","title"]`)를 반환합니다. 메모 내용·실명·토큰·기기 UUID는 응답에 포함하지 않습니다.
- 사본이 없거나 무결성이 검증되지 않으면 복원은 즉시 중단됩니다. 미리보기와 실제 복원 모두 B의 검증된 신원, 저장된 백업 소유자 일치를 요구하며 요청의 소유자/역할 필드를 받지 않습니다.
- 실제 복원은 이전과 동일한 `{"id":"UUID"}`를 허용합니다. `dryRun:true`만 추가했으며 `dryRun:false`, 다른 필드, 소유자 주입은 거부합니다. `src/restore-core.mjs`는 미리보기·복원 RPC 호출을 분리해 테스트 가능하도록 했습니다.
- 테스트: `node --test test/stage10.test.mjs`가 읽기 전용 미리보기(쓰기 RPC 0회), 검증 실패 시 쓰기 0회, 정상 복원 RPC 순서를 검증합니다. **실제 심판 통과 및 심판 B의 운영 복원 실행은 아직 확인되지 않았습니다.**

---

# BYTE BACK 방어전 · 10단계 저장점 — 검증 백업 복원

**현재 단계: 10단계 「백업에서 자료실을 되살립니다」.** 9단계 통과 직후의 GitHub 기준 커밋 `9dde11f22e5f`을 유지하고 기존 1~9단계 판정기·탐지기·로그인·API·RLS 및 보너스 XDR 테스트를 계속 실행합니다.

## 검증된 백업과 시험 정책

- 운영 Supabase 프로젝트의 비공개 `stage10_restore` 스키마에 `notes_snapshot`, `restore_audit`, `policy_baseline`, `policy_trial`, `policy_audit`를 생성했습니다. 복구 데이터는 저장소·공개 자료 파일에 넣지 않습니다.
- 이 단계 공격 **시작 전 기준 시점**에 있던 메모 4건을 사본으로 저장하고, 메모 ID·소유자 UUID·제목·내용을 SHA-256으로 검증했습니다. 침해 이전의 외부 백업을 발견한 것은 아닙니다. **현재 검증된 기준 상태를 10단계 공격 전에 새로 캡처한 것**입니다. 공격 전 이미 변조된 기록까지 되돌리는 역사적 증거는 아닙니다.
- 새로 등록되는 메모는 최초 INSERT 시 사본을 하나 저장합니다. UPDATE/DELETE는 그 사본을 변경하지 않습니다. 이 체크포인트는 DB 관리자 권한과 독립된 외부 백업의 대체재가 아닙니다.
- `policy_baseline`은 복구 시작 시 운영에서 읽은 메모/강사 테이블 RLS 정책 스냅샷과 SHA-256을 보관합니다. `policy_trial`은 *별도의 시험 복사본*이며 실제 RLS 정책이 아닙니다.
- 정책 비교: `GET /api/recovery-policy` → 버전, 백업 해시, 다른 정책 키만 표시. 되돌리기: `POST /api/recovery-policy` 본문 `{"expectedSha256":"GET에서 확인한 해시"}` → **시험 정책만** 기준 사본으로 복원하고 감사 기록을 추가합니다. 실제 운영 정책이나 타 서비스 규칙은 바꾸지 않습니다.

## 단건 메모 복원

- **복구 경로:** `POST /api/restore` (`aleph.config.json.restoreRoute`와 동일).
- **본문:** `{"id":"복구할 메모 UUID"}` 하나만 허용합니다. 소유자·역할·기기 값은 요청에서 받지 않습니다.
- **인증:** 운영 심판이 서명한, 유효한 A/B 신원 중 **B 계정만** 허용합니다. B의 검증된 UUID가 비공개 사본의 소유자와 일치해야 합니다. 단건 SQL 트랜잭션이 사본의 소유자·내용 해시를 재확인하고 동일 ID의 한 건만 INSERT 또는 UPDATE한 뒤 확인 결과를 반환합니다. 백업이 없거나 무결성이 잘못되면 아무 자료도 덮어쓰지 않습니다.
- 다른 메모와 `restore_audit` / `policy_audit`를 삭제·초기화하지 않습니다. 복원된 메모와 SHA-256만 응답하며 메모 내용이나 서버 비밀키는 반환하지 않습니다.
- 익명, 일반 학생, 심판 A, 서명이 틀린 B, 다른 소유자의 메모 ID 요청은 거부합니다. 시험 B의 운영 JWT는 AI에 제공하지 않아 실제 심판 침해 후 복원은 **미실행** 상태입니다.

## 검증 순서 (1~9단계 재검사)

1. `GET /api/recovery-policy`로 기준 정책 버전·해시·변경 키를 확인합니다(심판 B 서명 JWT 필요). 기준 SHA-256을 확인하기 전에는 `POST /api/recovery-policy`로 시험 정책을 되돌리지 않습니다. 다른 서비스 정책은 제외합니다.
2. 기준 메모 스냅샷 ID·소유자·SHA-256을 조회하거나 DB 운영 점검으로 확인합니다. 이후 서명된 B 시험 계정으로 지정 UUID만 `POST /api/restore`하고 정상 응답의 `content_sha256`과 사본 해시가 같은지 비교합니다.
3. 운영 심판이 B의 변조·삭제·재접속 공격을 재생합니다. 메모 **정상 GET/PUT**, 타인 메모 **거부**, 미등록 기기 거부, 7단계 추가 확인, 8단계 목록 조회 거부/강사 공지 쓰기 거부, 9단계 다량 GET 회수 제안을 차례로 확인합니다.
4. 로컬에서 `npm run decider:test`, `npm run fixture:7`, `npm run test:r8`, `npm run detect:test`, `node --test test/stage10.test.mjs`, `npm run test:r5`, `npm run xdr:test`, `npm run build -- --local`을 실행합니다. 실제 B 토큰·운영 정책 변경·침해 후 실자료 비교는 아직 **미실행**이며 통과했다고 기록하지 않습니다.
5. **비로그인 거부 확인:** `curl.exe -i -X POST https://choi-bujang-secret-vault-jwnp.vercel.app/api/restore -H "Content-Type: application/json" -d "{\\"id\\":\\"11111111-1111-4111-8111-111111111111\\"}"` 결과는 401이어야 합니다. 공개키로 `stage10_restore` 비공개 백업 내용을 읽을 수 없어야 합니다.

실제 운영 서비스 RLS·1~9단계 기능은 이번 변경에서 수정하지 않았습니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 포함하지 않습니다. `npm run bundle`은 커밋·배포 이후 CI에서 실행하며, 결과는 심판 판정의 대체가 아닙니다.

---

# BYTE BACK 방어전 · 9단계 저장점 — 가상 사건 탐지와 회수 제안

**현재 단계: 9단계 「도플갱어를 찾고 권한을 거둡니다」.** 마지막 8단계 커밋 `d4d62f79fed5`의 소유자 기반 API 검증·자원 구역 판정과 1~7단계 기능 및 보너스 XDR-01/02는 보존합니다. 9단계의 저장소 구현은 `src/detect.mjs`에만 탐지·제안 로직을 추가하며, 기존 `src/decider.mjs`의 응답 형식을 바꾸거나 실제 회수 API를 만들지 않습니다.

## 9단계 구현 요약

- 반 엔진이 확인해 전달하는 **가상 사건** `{at, method, identity:{sub}}`만 읽습니다. 본문, 비밀값, JWT, 실명, 사용자가 제공한 네트워크/기기값은 로깅하거나 처리하지 않습니다.
- 사용자별(GET만)로 정렬한 사건 중 **임의의 10분 구간에 121회 이상** 발생한 첫 사례에 `{action:'propose_revocation',reasonCode:'burst_read',subject:'해당 가명'}`를 돌려줍니다. 정확히 120회·시간창 밖 조회·다른 사용자 합계는 `{action:'observe'}`입니다. 같은 사용자에서 이상 사건이 발견되지 않으면 아무 회수 제안도 하지 않습니다.
- 현재 제공된 `docs/DETECT_EVENTS.md`의 **입력에는 네트워크 상태와 기기 ID가 없습니다**. 따라서 '비정상 네트워크와 급격한 조회의 결합' 및 '기기 한 대 지정'은 제공된 계약만으로 **진실하게 구현할 수 없습니다**. 엔진이 확증된 기기·네트워크 정보를 별도 계약으로 제공하기 전에는 이를 임의로 추가하지 않습니다. 실제 집행 및 시간 측정은 심판 엔진이 담당합니다.
- Node.js 22 이상에서 `npm run detect:test`로 제공된 6개 가상 사건을 검증하고 `node --test test/detect.test.mjs`로 경계값·혼합 사건·정보 비노출 등 추가 테스트를 실행합니다. 전체 이전 단계 검사는 GitHub Actions에 유지됩니다.
- 기존 Vercel 자료실 `https://choi-bujang-secret-vault-jwnp.vercel.app`, JWT 발급자, 기존 API 허용 경로, 원본 자료 API 주소를 보존합니다. `aleph.config.json.step=9`, 빌드/자체 점검과 배포 메타데이터만 현재 단계에 맞게 확장합니다.

**재현:** `npm run detect:test && node --test test/detect.test.mjs && npm run decider:test && npm run fixture:7 && npm run test:r8 && npm run build -- --local && npm run bundle`. 제출용 비밀값·JSON은 Git에 올리지 않습니다. 마지막 `bundle`은 Git 커밋 이후, 배포된 `/aleph.json`이 step 9가 된 뒤 GitHub Actions에서 실행합니다. 로컬 결과는 운영 심판의 실제 회수 판정이 아닙니다.

---

### 8단계 S08 인증 전 진단 (2026-10-13)

심판의 실제 공격 실패를 판정기·로그인·메모 소유권 중 어디에서 발생했는지 추적하기 위해 메모 목록과 단건 API 핸들러 **진입 즉시** `aleph_s08_entry` 로그를 남깁니다. 요청 메서드는 GET/POST/PUT/DELETE/OTHER로 제한하며, 경로는 `/api/notes` 또는 `/api/notes/:id`라는 정해진 모양만 기록합니다. Authorization 헤더 유무만 남깁니다.

서버가 인증을 확인한 뒤에는 `aleph_s08_auth`로 `judge / student / null`과 실패 사유 `missing / format / issuer / expired / claims / signature / verification / config` 중 하나를 기록합니다. 검증에 실패한 JWT의 issuer 정보는 **로그 분류에만** 활용하며 인가 판단에는 사용하지 않습니다. 토큰 원문·사용자 ID·메모 ID·쿼리·요청 본문·오류 전문은 **절대 로그에 기록하지 않습니다.** 인증 거부 결과 및 API 응답 형식은 변경하지 않습니다. `test/stage8-audit.test.mjs`가 필드 누출과 로그 사유를 검사합니다.

`GET /api/notes/:id`의 기존 소유권 결과 로그(`aleph_stage8_note_get`)는 유지합니다. 로그가 없다는 사실 하나만으로 심판이 API를 호출하지 않았다고 결론 내릴 수는 없습니다. 심판의 실제 실행 시각에 맞춰 Vercel 로그의 보존 기간 안에서 확인해야 하며, 심판 엔진 내부에서 실행되는 `src/decider.mjs`는 Vercel 함수 로그로 관측되지 않습니다.

### 8단계 S08_OTHER_ZONE_ALLOWED 진단 저장점 (2026-10-13)

공식 심판 커밋 `93dae7adedd9`에서도 타인 메모 단건 GET 공격이 통과했습니다. 지금까지의 로컬 fixture 및 모의 DB 테스트는 운영 심판의 실제 A/B 요청을 재현한 것이 아니므로, 통과를 주장할 수 없습니다.

- `GET /api/notes/:id`는 서명 검증된 심판 토큰에 대해서만 `aleph_stage8_note_get` 로그에 **A/B 역할 표시와 조회 결과(`owned` / `not_found` / `db_error`)만** 남깁니다. 사용자 UUID, 토큰, 노트 UUID, 내용, 경로를 로그에 기록하지 않습니다. 향후 심판 판정의 실제 요청을 확인해야 원인을 더 좁힐 수 있습니다.
- 소유권과 강사 권한 검사 후 **성공한 리소스 응답에만** `X-Resource-Id: notes:<uuid>` 또는 `instructor-notices:<uuid>`를 설정합니다. 타인 메모나 없는 자료의 응답에는 자원 ID를 노출하지 않습니다. 신규 메모 POST 성공 시에도 자기 자원 ID를 표시합니다.
- 직접 DB 조회 권한은 `anon=false, authenticated=false`이고 `notes` RLS 정책은 `auth.uid()=owner_id`입니다. 서버 전용 DB 권한은 RLS를 우회하므로 API의 저장된 `owner_id` 필터는 계속 필수입니다.
- 실제 심판이 해당 API를 호출한다는 증거를 수집하기 전까지 `S08_OTHER_ZONE_ALLOWED` 해결을 확정하지 않습니다. 다른 단계 동작과 실제 자료는 변경하지 않았습니다.

### 8단계 재검증: 심판 A/B 서명된 신원도 서로 다른 소유자

`src/verify-login.mjs`의 기존 심판 JWT 처리는 서명된 `aleph_identity`(a/b)와 `aleph_run`을 검증해 놓고도, `userId`는 `sub`만 사용했습니다. 토큰의 `sub`가 같아도 서명된 A/B 신원이 다르면 동일한 메모 소유자가 될 수 없도록 `run + identity + sub`에서 안정적인 128비트 UUID 형식의 소유자 키를 유도합니다. 실제 학생 인증은 기존 Supabase 검증 `sub`를 그대로 사용합니다. 이 구별은 **검증된 판정 토큰의 서명된 필드로만** 수행하며 클라이언트 role, identity, userId 요청값을 신뢰하지 않습니다. 데이터베이스에는 별도 유출성 신원 정보를 저장하지 않습니다.

`test/judge-owner-identity.test.mjs`에서는 테스트 전용 임시 ES256 키로 서명된 두 심판 토큰(같은 `sub`, A/B 정체성)을 만들어 서로 다른 소유자 ID, 동일 정체성 재사용, A 자기 메모 조회·B 거부, 일반 학생 ID 보존을 검증합니다. 이 테스트는 운영 심판 토큰을 이용한 실제 E2E가 아니며 공식 S08 통과를 보장하지 않습니다. 기존 메모 행은 보존됩니다.

# BYTE BACK 방어전 · 8단계 + 보너스 XDR-01/XDR-02 저장점

현재 단계는 **8단계 「자료마다 갈 수 있는 구역을 나눕니다」**입니다. 기존 1~7단계의 로그인·소유자 검사, 기기 판정, 추가 본인 확인, 메모 CRUD와 XDR 기능을 유지하고 메모와 강사 공지를 별도 자원 ID 및 서버 권한으로 분리했습니다.

## 현재 동작

- 로그인/로그아웃은 Supabase Auth 공식 SDK를 그대로 사용합니다.
- 브라우저의 메모 GET/POST/PUT/DELETE는 모두 `/api/notes`와 `/api/notes/:id` 서버 함수로만 요청합니다.
- 서버 함수는 시작 틀의 `src/verify-login.mjs`로 로그인 토큰을 확인하고, 검증된 userId와 `owner_id`를 비교합니다.
- 새 메모의 `owner_id`도 서버가 검증한 userId로만 저장하며 URL·본문의 소유자 값은 신뢰하지 않습니다.
- `public.notes`의 PUBLIC·anon·authenticated 직접 테이블 권한은 모두 회수했습니다.


## 6단계 · 등록 기기 판정

- `docs/DECIDER_REQUEST.md`의 `aleph.decision.v1` 계약만 사용합니다. 엔진이 검증한 가명 사용자 `subjectId`, 기기 `deviceId`, 기기 등록 여부 `deviceRegistered`가 전달됩니다.
- `src/decider.mjs`의 `RULE_IDS`에 `device_registered`만 등록했습니다. `deviceRegistered === true`일 때만 `allow / approved`를 반환합니다.
- 값이 `false`이거나 누락되거나 실제 불리언 `true`가 아니면 `deny / device_not_registered`로 거부합니다. 응답은 기존 계약의 다섯 항목을 유지합니다.
- 별도 기기 등록 프로그램, 인증서·CA·서명 키·개인키를 만들지 않았습니다. 실제 릴레이의 등록 확인은 운영 엔진이 담당하며 `npm run decider:test`는 가상 요청 연습입니다.
- 기존 브라우저 화면, Vercel 자료실 주소, 서버 메모 CRUD, XDR-01/XDR-02는 변경하지 않았습니다. `aleph.config.json`의 `step`을 6으로 올리고 배포 빌드 및 제출 자기점검의 지원 범위를 6단계로 확장했습니다.

6단계 로컬 확인 순서 (Node.js 22 이상):

```powershell
npm run decider:test
npm run build -- --local
npm run test:r5
```

판정기 연습에서는 `통과 · 등록 기기의 정상 요청`과 `통과 · 미등록 기기의 가상 요청`이 모두 출력되어야 합니다. 미등록 기기 응답은 `deny / device_not_registered`이며 누락 값도 같은 이유 코드로 거부합니다. 배포 이후에는 기존 자료실 URL에서 등록 기기 화면을 직접 확인하세요. 실제 미등록 기기 공격과 심판 판정은 운영 측에서 수행하므로 확인하지 않은 결과를 통과로 기록하지 않습니다.

제출할 때는 변경 사항을 `6단계 저장점`으로 커밋한 뒤, Git에 포함되지 않는 `bundle-notes.json`에 이번 단계 설명을 작성하고 `npm run bundle`을 실행합니다. 생성되는 `artifacts/submission.json`도 Git에 올리지 않습니다. 비밀값은 넣지 않습니다.


## 7단계 · 복합 이상 신호와 추가 확인

- 입력 계약은 `docs/DECIDER_REQUEST.md`의 `aleph.decision.v1`이며 신원·기기·경로·접속 정보는 **운영 엔진이 검증해 전달한 값만** 판정합니다. 클라이언트 헤더의 위치, 기기 정보, 가공한 시각을 신뢰하지 않습니다.
- `signals.source === 'judge_fixture'`인 **가상 사건**에서만 복합 위험을 판단합니다. 운영 실요청은 `source: 'none'`, 지역·네트워크 `unknown`으로 오므로 누락 정보나 출처 불명확 신호를 정상값이나 위험값으로 꾸며내지 않습니다.
- `step_up_required` 규칙은 심판 가상 사건에서 **0~5시의 시각**, `network: unusual`, 최근 300초 이내의 `risk_signal` 10건 이상이 *모두* 충족할 때 `step_up / step_up_required`를 반환합니다. `risk_signal`은 제공 fixture의 반복 위험 행동 지표이며 실제 메모 열람 횟수나 내용을 의미하지 않습니다. 지역 하나만으로는 차단하지 않습니다.
- 검증된 기기(`deviceRegistered === true`)가 아니면 위험 신호나 추가 인증에 관계없이 `deny / device_not_registered`입니다. 나머지 등록 기기 요청은 `allow / approved`입니다.
- 위험 조합에서는 운영 엔진에서 검증해 전달한 `stepUp.verified === true`와 정수 `authAgeSeconds`가 **0~120초**일 때만 새 요청을 `allow`합니다. 값이 누락되거나 오래되거나 문자열이면 계속 `step_up`을 요구합니다. 이 값은 브라우저가 설정하는 필드가 아니며 토큰 원문을 기록하지 않습니다.
- 제공 계약에 `stepUp` 판정 입력은 존재하지만 현재 저장소만으로 **운영 엔진이 같은 주체의 실제 새 로그인 시각을 검증한다는 사실을 실측하지는 못했습니다**. 따라서 실제 추가 로그인 전 자료 거부와 재로그인 후 허용은 미실행으로 기록하고, 로컬/CI의 가상 요청 통과를 실제 심판 결과로 표시하지 않습니다.

확인 명령(Node.js 22 이상, 별도 접속 프로그램 설치 불필요):

```powershell
npm run decider:test
npm run fixture:7
node --test test/r7.test.mjs
npm run build -- --local
npm run test:r5
```

기대: 정상 등록 기기 `allow`, 미등록 기기 `deny / device_not_registered`, 출처가 확인된 복합 가상 사건 `step_up / step_up_required`, 엔진의 최신 추가 확인 표시(60초)가 반영된 **새 가상 요청** `allow`. 테스트는 브라우저 헤더를 신뢰하지 않는 경우와 지역 하나만 다른 경우도 확인합니다. 기존 화면·자료실 HTTPS 주소·서버 API·XDR 코드는 변경하지 않습니다.

제출은 `7단계 저장점`을 커밋한 다음, 무시 파일 `bundle-notes.json`에 설명을 작성하고 `npm run bundle`로 생성합니다. `bundle-notes.json`, `artifacts/submission.json`, 토큰·기기 개인키는 Git에 올리지 않습니다.

## 8단계 · 자원 구역 분리와 API 소유자 검증

- 개인 메모의 리소스 ID는 `notes/<uuid>`이며 기존 `/api/notes`, `/api/notes/:id`를 유지합니다. GET 목록은 검증된 사용자 `owner_id`만 조회하고 단건 GET은 **쿼리 자체에 `id`와 검증된 사용자 `owner_id`를 함께 넣어** 다른 사용자의 제목·본문이 서버로 조회되지 않도록 합니다. 단건 GET/PUT/DELETE는 DB에 저장된 `owner_id`와 서명 검증된 로그인 주체를 비교합니다. PUT/DELETE에는 `owner_id` 조건을 한 번 더 적용합니다.
- 강사 공지의 리소스 ID는 `instructor-notices/<uuid>`; 새 API `/api/instructor-notices`, `/api/instructor-notices/:id`로 구역을 분리했습니다. 인증 사용자 공지 읽기는 가능하지만 POST/PUT은 서버의 `instructor_memberships`에 등록된 실제 강사만 수행할 수 있습니다. 사용자 본문 `role`, 메뉴, 임의 헤더와 심판 신원은 강사 권한이 아닙니다.
- 연결된 Supabase에는 `instructor_notices`, `instructor_memberships` 테이블을 추가했습니다. RLS를 활성화했고 비로그인·일반 인증 사용자에게는 테이블 직접 권한을 부여하지 않았습니다. 기존 메모·다른 DB 테이블은 변경하지 않았고 강사 권한을 임의로 부여하지 않았습니다. 적용 SQL: `db/stage8-resource-zones.sql`.
- 판정기는 기존 `device_registered` 및 `step_up_required` 규칙을 유지하면서 정확한 `service`, `method`, `route`, `path`와 검증된 `subjectId`, `deviceId`, `classId`, `projectId`를 확인합니다. 쿼리로 기능을 바꾸거나 `:id`와 동일 깊이의 `export` 경로는 거부합니다.
- **8단계 심판의 S08_OWN_BROKEN / S08_OTHER_ZONE_ALLOWED 대응:** `scripts/fixture-7.mjs`에 이미 정의된 가상 본인 자원 `/notes/demo`는 오직 서버 코드에 고정된 `class_fixture / project_fixture / learner_fixture / aaaaaaaaaaaaaaaa` 조합에만 배정했습니다. 해당 주체의 `GET /notes/:id` 및 `PUT /notes/:id`는 허용하며, 다른 주체·기기·반·프로젝트나 임의 메모 UUID/다른 경로는 거부합니다. 7단계 위험 시각·네트워크 판정도 다시 원래 단건 가상 자원으로 검증합니다.
- **S08_OTHER_ZONE_ALLOWED 추가 보강:** 앞선 수정은 `/notes/demo` 단건만 배정하고 `GET /notes` / `POST /notes` 목록 자원은 임의의 확인된 `subjectId`에도 `allow`를 반환하는 맹점이 있었습니다. 이번에는 **단건과 컬렉션 모두** 신원·기기·반·프로젝트의 서버 배정을 검사합니다. 검증된 가상 본인의 `GET /notes` 및 `POST /notes`는 허용, 다른 주체·기기의 같은 경로는 거부합니다. 메모와 강사 공지는 별개 서비스로 유지합니다.
- **실제 사용자 권한은 별도:** 가상 사용자 명칭은 Supabase 사용자 UUID가 아니므로 실제 메모에 적용하지 않습니다. 실계정의 메모 단건 조회는 서버 API가 저장된 `owner_id`와 검증된 사용자 UUID를 함께 DB 조회 조건으로 사용합니다. 판정기 v1 계약에 실제 메모별 소유자 연결 정보가 없기 때문에 운영 단건 자원 접근을 확장하려면 엔진이 제공하는 별도 소유자 바인딩이 필요합니다. 실계정 A/B 심판 재채점 전에는 성공을 주장하지 않습니다.
- 현재 강사 등록 구성원이 없어 일반 학생의 강사 공지 쓰기는 기본 거부입니다. 강사 권한 부여는 별도 관리자 작업이어야 하며 웹 요청으로 이 테이블을 변경하는 엔드포인트는 없습니다. 기존 화면 메뉴는 바꾸지 않았습니다.
- 현재 실제 A/B 사용자 로그인 및 강사 E2E는 비밀번호·토큰 제공 없이 실행할 수 없어 미실행입니다. 심판의 직접 공격 판정 결과로 로컬 fixture를 대신하지 않습니다.

로컬 및 GitHub Actions 검사(Node.js 22 이상):

```powershell
npm run decider:test
npm run fixture:7
node --test test/r7.test.mjs
npm run test:r8
npm run build -- --local
npm run test:r5
npm run xdr:test
npm run bundle
```

예상: 자료 API에서는 A 소유 메모를 A만 열람·수정, B는 해당 메모 단건 조회 시 `note_not_found`(404), 수정 시 `note_not_found`(404) 또는 `note_forbidden`(403), 다른 계정 목록에는 A 메모가 보이지 않습니다. 일반 학생의 강사 공지 수정은 `instructor_required`, 비로그인 강사 공지 목록은 `authentication_required`입니다. 8단계 저장점 커밋 후 Git 무시파일 `bundle-notes.json`에 설명을 적고 bundle을 생성합니다. JSON·키·본문·개인정보는 Git에 커밋하지 않습니다.

## 보너스 XDR-01 · 무차별 로그인 공격

기존 5단계와 `src/decider.mjs`는 그대로 보존하고, `xdr/` 아래에 독립적인 무차별 로그인 공격 탐지 모듈을 추가했습니다. 시작 당시 저장소에 원래 `xdr/fixtures/brute-force.json`이 없어서 공개 제출용 합성 Wazuh 형태 fixture를 만들었으며 TEST-NET 주소와 가상 계정만 사용합니다.

- `read-alerts.mjs`: 시각·출발 주소·계정·규칙 수준·설명만 추출하고 비밀값처럼 보이는 실제 값은 출력하지 않습니다.
- `patterns.json`: MITRE ATT&CK T1110/T1110.003 근거의 같은 주소 실패 연속과 여러 계정 대상 password spraying 신호만 정의합니다.
- `decide.mjs`: 확신도 0.85 이상 block, 0.5 이상 alert, 그 아래 record입니다. 애매한 경우에만 Jev를 확인하고 응답이 없으면 자동 차단하지 않고 alert로 처리합니다.
- `ztna-bridge.mjs`: block 후보만 15분 만료의 거부 규칙으로 만들고 근거 경보 번호를 붙입니다. 현재 ZTNA 요청 계약에는 출발 IP가 없으므로 임의 필드를 `src/decider.mjs`에 추가하지 않고 바깥 집행 단계용 규칙 피드로 분리했습니다.

다시 실행:

```powershell
npm run xdr:run -- brute-force
```

실제 Node 22 격리 환경 검증 결과는 `alerts=28 extracted=28`, `block=10 alert=9 record=9 normalEventBlocks=0`이었습니다. 추가 `npm run xdr:test`는 3/3, 기존 `npm run test:r5`는 2/2 통과했고, `decide.mjs`를 형제 파일 없이 data URL로 독립 로드한 검사도 `10/9/9`로 통과했습니다.

### X01_CLEAR_NOT_BLOCKED 보완

심판의 `X01_CLEAR_NOT_BLOCKED` 피드백에 따라 `decide(alert)`가 raw Wazuh의 `rule.mitre`, `rule.level`, `data.count`, `data.accounts`를 직접 읽도록 수정했습니다. 명확한 T1110 상관 경보는 문구 하나에 의존하지 않고 block하며, 낮은 수준·횟수의 T1110은 alert, 일반 이벤트는 record로 유지합니다. 심판 격리 실행에서 형제 파일이 없어도 동작하도록 `decide.mjs`의 파일 읽기/import-time 의존성도 제거했습니다. 공개 기준 fixture 28건에서 정답 분포 `block 10 / alert 9 / record 9`를 재현했습니다.


## 보너스 XDR-02 · 웹 주입 공격

기존 5단계와 `src/decider.mjs`, XDR-01 규칙은 수정하지 않고 `xdr/web-injection/` 모듈을 추가했습니다. 공개 Wazuh 형태 fixture 26건에서 MITRE ATT&CK T1190 기반의 SQL 주입, 스크립트 주입, 경로 이탈, 명령 주입 신호를 판정합니다.

- `read-alerts.mjs`: 시각·출발 주소·계정·규칙 수준·설명만 추출하며 비밀값처럼 보이는 설명은 가립니다.
- `decide.mjs`: 반복된 고수준 T1190 경보만 자동 block 합니다. 단발·애매한 시도는 Jev 어댑터가 없거나 실패하면 alert, 정상 요청은 record입니다.
- URL은 판정 중에만 최대 2048자로 제한하고 최대 두 번만 디코딩해 이중 인코딩 경로 이탈을 확인하며 로그에는 URL을 남기지 않습니다.
- `connect.mjs`: block 후보만 15분 만료 규칙으로 만들고 각 규칙에 근거 경보 번호를 붙입니다. `src/xdr-decider.mjs`는 신뢰된 게이트웨이의 sourceIp를 별도 인자로 받아 기존 판정기 앞에 확인 단계를 추가합니다. 브라우저 요청 본문의 sourceIp는 신뢰하지 않습니다.

다시 실행:

```powershell
npm run xdr:run -- web-injection
```

Node 22 격리 환경에서 `alerts=26 extracted=26`, `block=8 alert=9 record=9 normalEventBlocks=0`을 확인했습니다. `npm run xdr:test`는 XDR-01과 XDR-02 합계 7/7, 기존 `npm run test:r5`는 2/2 통과했습니다. encoded traversal, Jev 실패 fallback, 단발 고확신 모델 응답이 자동 block으로 승격되지 않는지, 명확한 공격만 거부 규칙이 되고 정상 baseline 요청은 통과하는지도 회귀 테스트로 확인했습니다.

## 서버 API와 원본 자료 주소

`aleph.config.json.allowedRoutes`:

```text
/api/notes
/api/notes/:id
```

실제 메서드:

```text
GET    /api/notes
POST   /api/notes
GET    /api/notes/:id
PUT    /api/notes/:id
DELETE /api/notes/:id
```

쿼리 없는 원본 자료 HTTPS 경로는 `aleph.config.json.originalApiUrl`에 기록합니다.

```text
https://sckjbblzivbcoofabhqd.supabase.co/rest/v1/notes
```

이 주소는 브라우저의 메모 CRUD에 사용하지 않습니다. 심판과 자기점검이 직접 자료 접근이 차단됐는지 확인하는 기준 주소입니다.

## DB 직접 권한

적용 후 실제 권한을 다시 확인한 결과:

- `anon`: SELECT / INSERT / UPDATE / DELETE 모두 false
- `authenticated`: SELECT / INSERT / UPDATE / DELETE 모두 false
- 기존 RLS의 본인 행 정책 4개는 삭제하지 않고 유지

서버 함수는 서버 전용 설정을 사용하므로 이 직접 권한 회수와 별개로 기존 API 경로를 유지합니다. 다른 테이블은 이번 단계에서 변경하지 않았습니다.

## 직접 점검

현재 공개적으로 재현 가능한 점검은 다음과 같습니다.

- 로그인 없는 `GET /api/notes`는 401/403 JSON 오류여야 합니다.
- 원본 `originalApiUrl`을 공개 Publishable Key로 직접 호출하면 메모 자료 없이 거부되어야 합니다.
- `/aleph.json`은 배포 갱신 후 step 8이며 `allowedRoutes`가 개인 메모와 강사 공지 경로를 포함해야 합니다.
- 첫 화면에는 `X-Content-Type-Options: nosniff` 또는 CSP가 있어야 합니다.
- 첫 화면 HTML 소스에는 `sb_publishable_...` 또는 anon JWT 키 문자열을 직접 넣지 않습니다.

A 계정의 비밀번호나 JWT를 도구에 전달하지 않았으므로, **A 로그인 → 읽기 → 추가 → 수정 → 삭제**와 **B의 A 메모 접근 거부** 브라우저 E2E는 학생이 직접 확인합니다. 실행하지 않은 인증 E2E를 완료했다고 기록하지 않습니다.

## 다시 실행

로컬 빌드와 시작 틀 테스트:

```powershell
npm run build -- --local
npm run test:r5
```

무로그인 서버 API 거부 확인:

```powershell
curl.exe -i https://choi-bujang-secret-vault-jwnp.vercel.app/api/notes
```

정상 결과는 401 또는 403과 JSON 오류입니다.

`/data.json`은 계속 `notes: []`을 유지합니다. 과거 공개 Git 커밋과 이전 Vercel 배포 이력은 남아 있으므로 과거 노출이 삭제됐다고 기록하지 않습니다.

제출 묶음은 저장점 커밋 뒤 `npm run bundle`로 생성하며 `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.
