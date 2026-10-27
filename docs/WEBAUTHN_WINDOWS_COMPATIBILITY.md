# Windows Hello 기기 등록 호환성

## 확인한 문제

2026-10-27, 일반 Chrome에서 「이 Windows 디바이스」를 선택해도 USB 보안키 저장 창으로 이동하는 사용자 화면을 확인했다. Windows PIN 준비 이후 내장 사용자 확인 인증기 가용성은 `false`에서 `true`로 바뀌었지만, 가용성 조회는 해당 사이트가 요청한 공개키 알고리즘의 지원을 검사하지 않는다.

운영 배포와 GitHub main은 확인 당시 `aaebd723560ae20c5d7c29684aef745f6ac64dea`였고 공개 `app.js`는 로컬 코드와 일치했다. 서버 등록 옵션은 ES256(-7)만 허용하고 검증·DB도 EC P-256 좌표만 지원했다. Chromium 공식 문서는 Microsoft Windows 플랫폼 인증기 호환성을 위해 RS256(-257)도 제공하도록 안내한다.

읽기 전용으로 Microsoft Passport Key Storage Provider를 조회했을 때 RSA는 지원, ECDSA_P256은 `NTE_NOT_SUPPORTED (0x80090029)`였다. 이 결과는 해당 키 제공자 범위의 진단이며 모든 Windows Hello 경로나 해당 Chrome 요청의 최종 원인을 단독으로 확정하는 자료는 아니다. Microsoft는 최신 Windows의 ECC 지원도 명시한다. USB가 없다는 이유만으로 외부 보안키 구매나 추가 PIN 재설정을 요구하지 않는다.

근거:

- [Chromium 공개키 알고리즘 호환성 안내](https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md)
- [Microsoft WebAuthn API](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)
- [인증기 가용성 조회](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnisuserverifyingplatformauthenticatoravailable)
- [키 제공자별 알고리즘 지원 조회](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptisalgsupported)

## 수정 범위

- `api/device.js`: ES256과 RS256을 함께 제안하고 검증된 공개키 성분만 저장한다. `platform`, 사용자 확인 `required`, 등록 결과 `pending`을 유지한다. 정상 UUID(8-4-4-4-12)의 확인 번호를 거부하던 정규식도 수정한다.
- `src/app-webauthn.mjs`: RS256의 RSA 공개키 등록 및 SHA-256/PKCS#1 v1.5 서명을 검증한다. RSA는 2048/3072/4096비트, 공개 지수 65537만 수락한다. 개인 성분·알 수 없는 RSA COSE 필드·modulus 선행 0·공개 성분의 비정규 base64url·알고리즘 혼동을 거부한다. 기존 ES256 검증을 유지한다.
- `api/app-request.js`: 승인된 기기의 키 알고리즘 및 RSA 공개 성분을 읽는다. 소유자·승인·서명·Origin/RP ID·일회용 챌린지·요청 내용·카운터 재확인을 유지한다.
- `supabase/migrations/20261027072847_webauthn_rs256_public_keys.sql`: RSA용 `public_n`, `public_e`, `key_algorithm`을 추가한다. 기존 EC 기기는 `-7`로 유지한다. EC/RSA 공개키 형식을 분리하는 CHECK를 적용하며 승인 상태·기존 데이터·RLS·권한은 변경하지 않는다. 파일 버전은 운영 적용 이력과 일치시켰다.
- `test/stage11-rsa.test.mjs`, `test/stage11-device-api.test.mjs`: 사용자 인증기와 분리한 합성 키·모의 API 검사다.

실제 Windows Hello 개인키·계정 암호·PIN·토큰을 코드나 문서에 저장하지 않는다. 테스트용 개인키도 실행 중 메모리에서만 생성한다.

## 검증 결과

- Node v24.19.0: 기존 Stage 11 합성 검사 6개, 새 RSA 합성 검사 15개, 등록·보호 요청 API 행동 모의 검사 17개(상위 검사 포함) 통과.
- 별도의 메모리 PostgreSQL 호환 엔진(PGlite 0.5.12): 원래 Stage 11 SQL 위에 새 마이그레이션을 적용하고 기존 EC 기기·승인·카운터 보존, 새 RSA 기본 pending, NULL/혼합/불량 공개키 거부, RLS·역할 권한 유지, 익명/일반 인증 사용자의 직접 접근 거부, 재적용 보존을 15개 확인했다. 엔진과 검사 스크립트는 저장소 밖 임시 검증 폴더에만 있으며 운영 DB와 무관하다.
- 2026-10-27 운영 DB에 위 마이그레이션을 적용했다. 사용자 행이나 키를 읽지 않고 스키마·제약·권한 메타데이터와 행 수만 비교했다. 새 공개키 컬럼·형식 제약·기본 `pending` 상태를 확인했고, RLS 활성화와 anon SELECT/일반 인증 사용자 INSERT 거부 및 서버 역할의 기존 읽기·쓰기 권한이 유지됐다. 적용 전후 기기 행 수는 0으로 동일했다.
- 실제 Chrome→Windows Hello→서버 등록 완료 및 관리자 승인 후 보호 요청은 아직 검증하지 않았다. 운영 변경 후 사용자의 직접 인증이 필요하다.

## 적용 순서와 한계

1. 검토한 DB 마이그레이션을 먼저 적용한다. 기존 ES256 서버는 추가된 컬럼이 있는 DB에서도 동작한다.
2. 같은 수정 커밋의 등록·검증·보호 요청 API를 함께 배포한다. 옵션에 RS256만 추가하고 검증·저장 지원을 생략하면 안 된다.
3. 사용자가 직접 일반 Chrome의 기기 등록을 수행하고 Windows 인증창을 완료한다. 성공 결과는 `등록 요청 완료 · 서버 관리자 승인 대기 중`이다.
4. 승인된 기기의 실제 서명과 보호 자료 접근은 신뢰된 관리자의 별도 승인 후 확인한다. 브라우저 클릭이나 등록 성공만으로 승인하지 않는다.

운영 DB 마이그레이션은 적용·확인했다. 서버 코드는 이 변경을 포함한 Git 커밋을 운영 배포의 소스 커밋과 대조해 확인해야 한다. 실제 Windows Hello 등록 성공은 사용자의 직접 인증으로 별도 확인해야 한다. 로컬 합성 검사는 운영 성공이나 공식 심판 결과가 아니다. 암호·PIN 설정, 인증창 입력은 사용자가 Windows 화면에서 직접 수행한다.

이전 서버 버전으로 되돌릴 때는 EC 레코드와 추가 공개키 컬럼을 보존한다. 이전 서버는 RSA 기기를 사용할 수 없으므로 RSA 기기가 승인된 뒤에는 이전 서버로 되돌리는 것만으로 동등한 동작이 보장되지 않는다. 기존 자료나 기기 레코드를 삭제하는 롤백은 하지 않는다.
