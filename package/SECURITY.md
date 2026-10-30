# 패키징 보안 경계 (P2~P4 / P6)

## 공개값과 비밀값

- 브라우저에 공개 가능: SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY (공개 인증 클라이언트용).
- 서버 전용: SUPABASE_SECRET_KEY, OPENAI_API_KEY, 선택적 NVD_API_KEY.
- 이 키들의 실제 값은 Git·브라우저 번들·README·생성된 public/aleph.json·제출 JSON에 넣지 않는다. 환경 변수 이름은 비밀이 아니다.
- AI 기능은 OPENAI_API_KEY가 없거나 DB 호출 제한이 준비되지 않으면 실패로 표시한다. 외부 유료 호출을 자동으로 켜지 않는다.

## 인증과 권한

api/ai.js, api/threat-intel.js 모두 src/package-auth.mjs을 거쳐 기존 서명 검증 로그인 함수(createLoginVerifier)를 사용한다. 단순 브라우저 표시명·User-ID 헤더·임의 JWT 디코딩 결과로 통과시키지 않는다. 학생 계정으로 확인된 요청만 허용하며 비로그인은 401, 심판용 가상 토큰은 403으로 구분한다.

이 두 API는 메모/기기 소유 정보를 읽거나 ZTNA 접근 허용을 결정하지 않는다. 보안 에이전트의 실제 계정/기기 승인과 추가 확인은 기존 판정·집행 경로로 유지한다. AI 설명도 advisory_only이고 방어 집행 결과를 바꾸지 않는다.

## 비용·호출 제한

db/package-ai-quota.sql은 서버가 검증한 사용자 UUID를 기반으로 PostgreSQL에서 직렬화된 카운터를 증가시킨다. 설정: 4회/분, 20회/UTC일. Redis 또는 DB 없는 프로세스 메모리 제한은 서버리스 인스턴스 간 일관성이 없어 사용하지 않는다.

DB 함수는 SECURITY INVOKER로 실행되며 서비스 역할로만 RPC 실행을 허용한다. PUBLIC/anon/authenticated는 EXECUTE 권한을 가지지 않고 테이블 RLS도 활성화한다. RPC 또는 저장소가 실패하면 요청을 차단한다(503). 소진 시 HTTP 429 및 Retry-After를 반환한다. 동시성·실제 배포 환경 결과는 미확인이다. 호출 상한은 서버 비용을 무제한으로 방지하는 보호 장치이지 전체 비용 보장을 의미하지 않는다.

## API 입력과 외부 통신

- AI: 10~1200자 summary, 최대 10개 ruleIds만 입력. 모델과 URL 고정, 256 출력 토큰 상한, store:false, 15초 제한. 토큰·원본 보안 로그·개인정보를 입력하지 않는다.
- 침해 정보: 허용된 CVE ID만 입력. 서버의 고정 NVD·KEV 출처로만 조회하며 사용자 제공 URL을 다운로드하지 않는다.
- 두 API 모두 no-store 응답. upstream 실패 시 실패 또는 partial을 표시하며 임의의 안전 판정을 만들어내지 않는다.

## 패키징 자체 점검 주의

실제 secret scan은 모든 Git 이력, 서버·브라우저 빌드 산출물, Vercel 프로젝트 환경/배포 설정과 연결해 별도로 수행해야 한다. 이 문서는 비밀이 없다는 공식 보증이 아니다.

Hobby 무료 플랜에 맞춰 기존 공개 읽기 API 두 개(/api/public-config, /api/war-room-summary)는 vercel.json에서 기존 api/war-room 함수로 재작성한다. 공개 요청 분기는 인증 검사를 통과시키지 않으며 각각 원래의 공개 데이터만 반환한다. 학생 데이터 접근과 신규 AI/침해 정보 API의 JWT 인증은 기존대로 유지한다.

2026-10-30 실제 DB 적용: `package_ai_consume` SECURITY INVOKER, `service_role` 전용 EXECUTE/테이블 grant, RLS 활성 및 anon/authenticated 접근 불가를 확인했다. 테스트용 UUID 2건은 ROLLBACK 이후 남지 않았다. 외부 사용자 JWT로 호출한 결과는 아직 확인하지 않았다.
