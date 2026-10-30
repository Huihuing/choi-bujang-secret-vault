# P1~P8 자체 점검 (공식 판정과 구분)

상태: 2026-10-30 `main` 병합 완료, 기존 Vercel과 신규 패키지 전용 Vercel 프로젝트의 배포 READY. 신규 패키지 시연 첫 화면 및 비로그인 API 실측 완료. **ALEPH 공식 P1~P8 판정은 아직 확인되지 않음.**
이 표의 구현 확인은 ALEPH 공식 초록색 통과 판정을 대신하지 않는다.

| 항목 | 현재 확인할 수 있는 것 | 남은 실측/판정 |
| --- | --- | --- |
| P1 | package/README.md, SELF-CHECK.md, ARCHITECTURE.md, RULES.md, THREAT-INTEL.md, SECURITY.md, 그림 SVG 준비 | 심판의 필수 파일명·구조 검사 미확인 |
| P2 | 새 서버 코드의 키는 process.env에서만 조회. 공개 프런트는 SUPABASE_PUBLISHABLE_KEY만 사용 | GitHub Actions 41029299121의 현행 소스 및 접근 가능한 Git 이력의 알려진 키 패턴 검사가 통과. 비정형 비밀값·배포 응답 전체 검사는 보증하지 않음 |
| P3 | 패키지용 신규 HTTP 함수 소스는 api/ai.js, api/threat-intel.js 2개. 기존의 공개 조회용 API 두 개를 src/의 원형 핸들러로 이동해 api/war-room.js에 재작성 연결함으로써 무료 플랜의 12개 함수 상한 안에 들어간다. 두 경로 모두 검증된 학생 JWT를 요구하고 비로그인은 401 | 공개 시연 주소에서 비로그인 HTTP 401, 로컬 인증된 요청 경로는 의존성 주입 모의 테스트 통과. 실제 로그인 JWT end-to-end는 미완료 |
| P4 | API AI 라우트는 DB RPC package_ai_consume으로 인증된 사용자별 4회/분·20회/UTC일 제한; DB 실패 시 차단 | 기존 Supabase에 비파괴형 SQL 마이그레이션 적용. RLS 및 서비스 역할 전용 권한 확인, 합성 사용자 2명으로 분당 4회·UTC 하루 20회 제한과 사용자별 분리 확인. 실제 Vercel 인증 JWT 및 동시 인스턴스 HTTP 검증은 미완료 |
| P5 | threat-intel API는 고정된 NVD CVE API / CISA KEV JSON을 서버에서 조회, 각 원천의 fetchedAt 및 원천 갱신 시각 기록 | NVD·KEV 원천 형식·실패 시 partial/unknown 처리 모의 검사 통과. 인증된 운영 조회에서 실제 수신되는지 미검증 |
| P6 | src/decider.mjs의 엔진 검증 사실 및 API의 서버 검증 로그인 기준 유지. 프런트가 정책 결정을 하지 않도록 새 API는 읽기/설명만 수행 | 기존 ZTNA·XDR 회귀 검사 통과. 공식 SDP 엔진의 실시간 판정·집행 연동은 확인되지 않음 |
| P7 | 기존 Vercel 빌드 구성과 새 프로젝트 재배포 절차 문서화 | 별도 Vercel 프로젝트(https://watchdogs-ztna-xdr-package-20261030.vercel.app/) READY, 첫 화면 HTTP 200/신규 API 401을 GitHub Actions에서도 검사. 브라우저 실사용·인증 사용자 전체 기능·제3자 설치 확인 필요 |
| P8 | ARCHITECTURE.md/.svg, RULES.md, THREAT-INTEL.md에 실제 코드 경로와 NVD·KEV 비교 기록 | ARCHITECTURE.md/.svg와 코드 경로, RULES.md, THREAT-INTEL.md 작성. 공식 심판의 그림 형식·내용 일치 판정은 미확인 |

## 내부 검사 명령

~~~sh
npm ci
npm run package:check
npm run decider:test
npm run xdr:test
npm run build -- --local
~~~

이 검사들은 배포·운영·공식 판정이 아니라 정적/모의/로컬 검증이다. 특정 시험이 실행되지 않으면 통과로 기재하지 않는다.

## 현재 증거와 미확인

- 기존 XDR 6/6은 교육 포털에 표시된 판정이다. 새 패키징 P1~P8의 통과와 무관하다.
- 41종 총공세의 개별 판정 원장을 이 저장소에 연결하지 않았으므로 —/41을 임의의 0/41 또는 41/41로 표시하지 않는다.
- 22단계 별도 폴더에서 Node 24.19.0 기동/종료/재시작이 확인되었다. 운영 SDP 통합이나 공식 전체 통과를 뜻하지 않는다.
- 신규 API의 인증 사용자 실제 HTTP 호출·외부 제공자 연결·키 발급은 추가 증거가 필요하다. 호출 제한 SQL은 기존 프로젝트에서 적용·롤백 시험했으며 기존 사용자 데이터는 변경하지 않았다. 새 Vercel의 첫 화면/비로그인 거부만 HTTP 실측했다.


## 2026-10-30 최신 내부 근거

- 패키징·회귀·비로그인 HTTP 확인: https://github.com/Huihuing/choi-bujang-secret-vault/actions/runs/41029299121
- main 병합 PR: https://github.com/Huihuing/choi-bujang-secret-vault/pull/3
- 기존 1~12단계 회귀 검사: https://github.com/Huihuing/choi-bujang-secret-vault/actions/runs/41029670512
- XDR 회귀 검사: https://github.com/Huihuing/choi-bujang-secret-vault/actions/runs/41029670635
- 기존 Supabase quota migration: 20261030084225_package_ai_quota_server_side_limit. 두 가상 UUID 분당/일간 제한 및 권한 실측, 테스트용 행은 롤백 후 0건.

### 공식 접수 필드 (사용자가 포털에서 직접 제출·접수 확인)

- GitHub: https://github.com/Huihuing/choi-bujang-secret-vault
- 시연: https://watchdogs-ztna-xdr-package-20261030.vercel.app/
- 제출 설명: 본 패키지는 기존 ZTNA·XDR 및 워치독스 학습 소스와 신규 인증 AI 중계, 호출 제한, NVD·KEV 조회, 구성도/규칙 문서를 포함합니다. 공개 첫 화면과 비로그인 신규 API 차단은 검증했습니다. 실제 SDP 집행, 유료 AI 모델 호출, 실계정 end-to-end 및 공식 41종 총공세 결과는 미확인입니다.

공식 평가 화면에 P1~P8이 모두 '확인되지 않음'으로 남아 있으면 8/8 통과라고 표시하지 않습니다.
