# ARCHITECTURE — 실제 코드 기준 데이터 흐름

아래 그림은 package/ARCHITECTURE.svg와 같은 경계를 표시한다. 실제 ALEPH SDP 운영 엔진과 Windows 로컬 계측은 Vercel 서버리스 환경 안에 포함되지 않는다.

~~~mermaid
flowchart LR
  U[브라우저 public/] -->|학생 JWT| API[기존 Vercel api/]
  API -->|서명 검증| AUTH[src/verify-login.mjs]
  AUTH -->|사용자별 권한| DB[(Supabase RLS / 소유권 검사)]
  API --> Z[src/decider.mjs ZTNA 규칙]
  Z --> X[src/xdr-decider.mjs XDR 추가 판정]
  U -->|로그인 후 설명 요청| A[api/ai.js]
  A -->|사용자별 원자적 쿼터| Q[(Supabase package_ai_quota)]
  A -->|서버 전용 API 키| L[OpenAI Responses API]
  U -->|로그인 후 CVE 조회| T[api/threat-intel.js]
  T --> N[NVD CVE 2.0]
  T --> K[CISA KEV JSON]
  PC[Windows 로컬 PC] --> W[on-client 5189 / pc-monitor 5191]
  W -.->|운영 SDP 설정 없으면 미연결| E[외부 SDP·XDR 엔진]
~~~

## 컴포넌트와 정확한 경계

1. 프런트엔드: public/index.html, public/app.js, public/sw.js. 공개 초기 화면과 로그인·기기 보호 상태 표시를 담당한다. Service Worker는 /api/ 요청을 캐시하지 않는다.
2. 인증 및 DB: src/verify-login.mjs에서 검증된 Supabase 학생 토큰·별도 ALEPH 심판 토큰을 구분한다. api/notes*.js는 서버에서 소유권과 기기 승인 여부를 검사한다. 브라우저 값만으로 권한을 결정하지 않는다.
3. 기존 ZTNA: src/decider.mjs의 RULE_IDS 4개와 서버 소유권 검사. 정확한 엔진 검증 필드 기반으로 allow/deny/step_up을 만든다. 운영 정책 원문·실제 집행 엔진은 이 저장소와 별개다.
4. XDR: src/xdr-decider.mjs가 기존 decide()를 감싸고 XDR 추가 거부 후보 규칙을 읽는다. 원본 실제 이벤트 → 집행 연결은 제공 엔진 지원에 의존한다. 실험 fixture는 실사건 아님.
5. 패키지 서버 확장: api/ai.js, api/threat-intel.js만 신규 HTTP 함수. 두 API 모두 src/package-auth.mjs에서 검증된 학생 신원을 요구한다. 무료 플랜의 12개 함수 상한에 맞추기 위해 기존 공개 읽기 API 2개는 src/package-public-config.mjs, src/package-war-room-summary.mjs로 옮기고, 원래 URL은 api/war-room.js로 재작성해 기존 공개 응답 규격을 유지한다.
6. 호출 제한: DB의 package_ai_consume RPC로 이용자 UUID별 호출 수를 원자적으로 갱신한다. 실제 DB가 미설치라면 AI 호출은 거부된다.
7. 침해 정보: src/package-threat-intel.mjs가 고정 NVD와 CISA KEV를 조회하고 각 출처의 성공/실패, 확인 시각을 별도 반환한다.
8. Windows 로컬: on-client/src/server.mjs, on-client/student/pc-monitor/server.mjs 및 collect.ps1은 사용자의 PC에서 실행한다. Vercel에서 원격 Windows 기기를 직접 측정하는 서버가 아니다.

## 공식 판정과 모의 검사 분리

- XDR 교육 포털 6/6: 기존 과제 판정.
- 공식 총공세 41종: 현재 사건별 공식 결과 미연동.
- 새 패키징 P1~P8: 공식 패키징 판정 미확인.
- 새로운 배포에서 첫 화면·실제 JWT·유료 AI 호출·실제 NVD/KEV 응답·원자적 제한 동시성은 아직 실측하지 않았다.
