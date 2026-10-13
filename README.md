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
