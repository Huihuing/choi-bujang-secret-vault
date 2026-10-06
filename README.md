# BYTE BACK 방어전 · 4단계 저장점

현재 단계는 **4단계 「로그인해도 내 자료만 보이게 합니다」**입니다. 3단계의 로그인 검증을 유지하면서 서버 API와 학습 DB 모두에서 메모 소유자 경계를 추가했습니다.

## 현재 동작

- 서버는 시작 틀의 `src/verify-login.mjs`가 검증한 사용자 ID만 신뢰합니다.
- 목록 조회는 `owner_id = 검증된 userId`인 메모만 반환합니다.
- 새 메모는 서버가 검증한 userId를 `owner_id`로 저장하며 URL·본문의 owner_id를 신뢰하지 않습니다.
- 단건 GET·PUT·DELETE는 기존 행의 owner_id와 검증된 userId를 비교하고, 다른 사용자의 메모는 403으로 거부합니다.
- PUT은 `{title,body}`만 허용하므로 소유자 변경 필드를 받을 수 없습니다.

## API 계약

`aleph.config.json.allowedRoutes`는 다음 두 canonical path를 유지합니다.

```text
/api/notes
/api/notes/:id
```

실제 메서드는 다음과 같습니다.

```text
GET    /api/notes
POST   /api/notes
GET    /api/notes/:id
PUT    /api/notes/:id
DELETE /api/notes/:id
```

한 건 응답은 `{id,title,body}`이고, 삭제된 id를 다시 GET하면 404가 정상입니다.

## 학습 DB 소유자와 권한

현재 가상 메모 4건은 두 Auth 사용자에게 **3건 / 1건**으로 배분되어 있고 owner_id가 비어 있는 행은 없습니다.

`public.notes`는 RLS가 활성화되어 있습니다. 적용 후 실제 권한을 대조한 결과:

- `anon`: SELECT / INSERT / UPDATE / DELETE 모두 없음
- `authenticated`: SELECT / INSERT / UPDATE / DELETE만 있음

RLS 정책은 authenticated 역할에 대해 네 개이며 모두 본인 행만 허용합니다.

- SELECT: `USING (auth.uid() = owner_id)`
- INSERT: `WITH CHECK (auth.uid() = owner_id)`
- UPDATE: 기존 행 `USING`과 새 행 `WITH CHECK` 모두 `auth.uid() = owner_id`
- DELETE: `USING (auth.uid() = owner_id)`

다른 테이블은 이번 단계에서 변경하지 않았습니다.

## 직접 점검

현재 배포에서 실제로 확인한 공개 점검:

- 로그인 없는 `GET /api/notes` → HTTP 401 JSON 오류
- anon Publishable Key로 Supabase `/rest/v1/notes` 직접 요청 → HTTP 401, 자료 반환 없음
- `/aleph.json`은 배포 시 자동 생성
- 첫 화면은 `X-Content-Type-Options: nosniff` 유지

authenticated 역할의 Supabase Data API 직접 접근은 심판이 재현할 수 없는 항목이므로 점수 확인 결과로 주장하지 않습니다.

A/B 계정의 비밀번호나 JWT를 도구에 전달하지 않았으므로, 브라우저에서의 **A/B 각각 자기 CRUD 및 상대 메모 거부 E2E**는 학생이 직접 확인합니다. 정상 결과는 A에는 A 메모만, B에는 B 메모만 보이고, 상대 메모 ID의 GET/PUT/DELETE는 거부되는 것입니다.

## 100점 추가 조건

- 무로그인 메모 목록 → 401 또는 403 + JSON 오류
- 배포 `/aleph.json` → HTTP 200, step 4
- 첫 화면 → `X-Content-Type-Options: nosniff` 또는 CSP

## 다시 실행

```powershell
npm run build -- --local
```

무로그인 거부 확인:

```powershell
curl.exe -i https://choi-bujang-secret-vault-jwnp.vercel.app/api/notes
```

정상 결과는 401 또는 403과 JSON 오류입니다.

`/data.json`은 계속 `notes: []`을 유지합니다. 과거 공개 Git 커밋과 이전 Vercel 배포 이력은 남아 있으므로 과거 노출이 삭제됐다고 기록하지 않습니다.

제출 묶음은 저장점 커밋 뒤 `npm run bundle`로 생성하며 `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.
