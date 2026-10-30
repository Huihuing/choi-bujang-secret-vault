# P1~P8 자체 점검 (공식 판정과 구분)

상태: 이 브랜치에 소스·문서 추가, 실제 새 배포/공식 패키징 판정 **미완료**.
이 표의 구현 확인은 ALEPH 공식 초록색 통과 판정을 대신하지 않는다.

| 항목 | 현재 확인할 수 있는 것 | 남은 실측/판정 |
| --- | --- | --- |
| P1 | package/README.md, SELF-CHECK.md, ARCHITECTURE.md, RULES.md, THREAT-INTEL.md, SECURITY.md, 그림 SVG 준비 | 심판의 필수 파일명·구조 검사 미확인 |
| P2 | 새 서버 코드의 키는 process.env에서만 조회. 공개 프런트는 SUPABASE_PUBLISHABLE_KEY만 사용 | 전체 소스·Git 이력·배포 빌드·실제 브라우저 응답에서 비밀값 스캔 미완료 |
| P3 | 패키지용 신규 HTTP 함수 소스는 api/ai.js, api/threat-intel.js 2개. Hobby 빌드에서는 opt-in으로 두 얇은 함수 진입점을 기존 api/war-room-summary로 합쳐 12개 물리 함수만 배포한다. 두 경로 모두 검증된 학생 JWT를 요구하고 비로그인은 401 | 실제 배포의 유효/무효 JWT 및 권한 테스트 미완료 |
| P4 | API AI 라우트는 DB RPC package_ai_consume으로 인증된 사용자별 4회/분·20회/UTC일 제한; DB 실패 시 차단 | SQL 반영·여러 서버 인스턴스 동시성·운영 상한 실측 미완료 |
| P5 | threat-intel API는 고정된 NVD CVE API / CISA KEV JSON을 서버에서 조회, 각 원천의 fetchedAt 및 원천 갱신 시각 기록 | 실제 외부 응답과 실패 시 표시 실측 미완료 |
| P6 | src/decider.mjs의 엔진 검증 사실 및 API의 서버 검증 로그인 기준 유지. 프런트가 정책 결정을 하지 않도록 새 API는 읽기/설명만 수행 | 전체 브라우저 코드와 새로운 시연 프로젝트의 요청 경로 재점검 필요 |
| P7 | 기존 Vercel 빌드 구성과 새 프로젝트 재배포 절차 문서화 | 별도 Vercel 프로젝트 생성·첫 화면·비로그인 접근·기본 기능 실측 **미완료** |
| P8 | ARCHITECTURE.md/.svg, RULES.md, THREAT-INTEL.md에 실제 코드 경로와 NVD·KEV 비교 기록 | 배포 대상과 공식 심판이 요구하는 ARCHITECTURE 형식·그림 연결 확인 필요 |

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
- 신규 API의 외부 제공자 연결·키 발급·데이터베이스 마이그레이션·새 Vercel 시연 성공은 추가 증거가 있을 때만 표시한다.
