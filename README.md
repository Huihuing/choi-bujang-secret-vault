# BYTE BACK 방어전 · 3단계 저장점

현재 단계는 **3단계 「진짜 로그인을 붙입니다」**입니다. 2단계에서 Supabase로 옮긴 가상 메모는 계속 서버에서만 읽고, 이제 Supabase Auth 로그인 토큰을 서버가 직접 검증합니다.

## 현재 동작

- 이메일·비밀번호 로그인/로그아웃은 Supabase Auth 공식 SDK를 사용합니다.
- `GET /api/notes`와 메모 CRUD API는 로그인 토큰이 없거나 검증에 실패하면 자료 없이 JSON 오류로 거부합니다.
- 로그인한 사용자는 서버 API를 통해 가상 메모를 추가·수정·삭제할 수 있고, 새 메모의 `owner_id`는 서버가 검증한 사용자 ID로 저장합니다.
- 3단계에서는 아직 소유자 검사를 하지 않으므로 다른 로그인 사용자가 메모 ID를 알면 접근할 수 있습니다. 이 허점은 4단계 대상입니다.
- 브라우저에는 서버 전용 `SUPABASE_SECRET_KEY`를 넣지 않습니다. 로그인용 Project URL과 Publishable Key만 공개 설정으로 사용합니다.

## 인증과 API 계약

`src/verify-login.mjs`는 시작 틀의 파일을 그대로 사용합니다. 브라우저가 임의로 보낸 `userId`나 `role`은 신뢰하지 않고, 검증된 로그인 결과의 사용자 ID만 서버가 사용합니다.

`aleph.config.json.identityProvider`에는 Supabase Auth의 issuer, audience, JWKS URL만 기록하며 비밀 키는 넣지 않습니다.

`aleph.config.json.allowedRoutes`:

```text
/api/notes
/api/notes/:id
```

실제 자료 메서드:

```text
GET    /api/notes
POST   /api/notes
GET    /api/notes/:id
PUT    /api/notes/:id
DELETE /api/notes/:id
```

POST 요청은 `{ id?, title, body }`를 받습니다. id가 없으면 서버가 UUID를 생성해 응답의 `{ id }`로 돌려줍니다. 한 건 GET은 `{ id, title, body }`이고 삭제된 id를 다시 GET하면 404가 정상입니다.

## 현재 직접 확인

무로그인 요청은 다음처럼 거부되는 것을 확인했습니다.

```text
GET /api/notes
HTTP 401
{"error":"authentication_required"}
```

POST와 `/api/notes/:id` 무로그인 요청도 같은 방식으로 401 JSON 오류를 반환합니다.

100점 추가 조건도 현재 배포에서 확인했습니다.

- 로그인 없이 메모 목록 요청 → 401 JSON 오류
- `/aleph.json` → HTTP 200, step 3
- 첫 화면 → `X-Content-Type-Options: nosniff`

A 계정의 실제 비밀번호를 도구에 전달하지 않았으므로, **A 로그인 → 추가 → 수정 → 삭제의 브라우저 E2E는 학생이 직접 확인해야 합니다.** 정상이라면 로그인 뒤 메모 카드와 추가 폼이 보이고, 추가·수정·삭제 결과가 새로고침된 목록에 반영됩니다.

## 정적 자료와 과거 공개 이력

`/data.json`은 계속 `notes: []`만 유지하며 1단계 확인 표시와 메모 본문을 다시 넣지 않습니다. 현재 GitHub 최신 파일과 최신 정적 배포에서 메모 본문을 제거했더라도, 1단계의 공개 커밋과 이전 Vercel 배포 이력은 남아 있습니다. 따라서 과거 공개 노출이 삭제되거나 해소됐다고 기록하지 않습니다.

## 다시 실행

로컬 정적 빌드:

```powershell
npm run build -- --local
```

무로그인 거부 확인:

```powershell
curl.exe -i https://choi-bujang-secret-vault-jwnp.vercel.app/api/notes
```

정상 결과는 401 또는 403과 JSON 오류이며, 로그인한 A 계정은 배포 화면에서 메모를 읽고 CRUD할 수 있어야 합니다.

제출 묶음은 저장점 커밋 뒤 `npm run bundle`로 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.
