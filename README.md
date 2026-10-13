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
- 판정기는 이전 `device_registered`와 `step_up_required`를 유지합니다. 추가한 `resource_zone`은 엔진이 확인한 `subjectId`, `deviceId`, `service`, `method`, 정확한 `path` 및 `route` 조합만 허용하고, 알 수 없는 경로는 `deny / resource_not_allowed`로 거부합니다. `:id` 깊이에는 UUID만 허용하며 `export` 기능이나 쿼리 기반 모드 선택은 허용하지 않습니다. 기존 7단계의 가상 요청인 `/notes/demo`는 `judge_fixture` 입력에서만 지원합니다.
- **중요한 v1 입력 제약:** `docs/DECIDER_REQUEST.md` 계약에는 강사 역할이나 메모 소유자의 검증 정보가 없습니다. 따라서 판정기에서는 강사 공지 쓰기를 `deny / instructor_required`로 막고, 메모 소유권은 실제 서버 API가 DB 기준으로 결정합니다. 판정기만으로 B의 A 메모를 판별했다고 기록하지 않습니다.
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

예상: A 소유 메모는 A만 열람·수정, B는 해당 메모 단건 조회 시 `note_not_found`(404), 수정 시 `note_not_found`(404) 또는 `note_forbidden`(403), 다른 계정 목록에는 A 메모가 보이지 않습니다. 일반 학생의 강사 공지 수정은 `instructor_required`, 비로그인 강사 공지 목록은 `authentication_required`입니다. 8단계 저장점 커밋 후 Git 무시파일 `bundle-notes.json`에 설명을 적고 bundle을 생성합니다. JSON·키·본문·개인정보는 Git에 커밋하지 않습니다.

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
