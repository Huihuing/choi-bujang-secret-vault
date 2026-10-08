# BYTE BACK 방어전 · 5단계 + 보너스 XDR-01/XDR-02 저장점

현재 단계는 **5단계 「자료 요청을 서버 한곳으로 모읍니다」**입니다. 4단계의 로그인·소유자 검사를 유지하면서, 브라우저의 메모 CRUD는 Vercel 서버 함수만 사용하고 Supabase Data API의 직접 테이블 권한은 회수했습니다.

## 현재 동작

- 로그인/로그아웃은 Supabase Auth 공식 SDK를 그대로 사용합니다.
- 브라우저의 메모 GET/POST/PUT/DELETE는 모두 `/api/notes`와 `/api/notes/:id` 서버 함수로만 요청합니다.
- 서버 함수는 시작 틀의 `src/verify-login.mjs`로 로그인 토큰을 확인하고, 검증된 userId와 `owner_id`를 비교합니다.
- 새 메모의 `owner_id`도 서버가 검증한 userId로만 저장하며 URL·본문의 소유자 값은 신뢰하지 않습니다.
- `public.notes`의 PUBLIC·anon·authenticated 직접 테이블 권한은 모두 회수했습니다.


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
- `/aleph.json`은 step 5이며 `allowedRoutes`가 하나 이상 포함되어야 합니다.
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
