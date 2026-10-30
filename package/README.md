# 워치독스 ZTNA·XDR 패키징 후보 (검증 중)

이 디렉터리는 기존 1~12단계, XDR 01~06, 마지막 총공세 작업을 보존하면서 ALEPH 패키징 P1~P8에 대비하기 위한 후보 문서입니다. 공식 심판 통과·운영 엔진 연동·제3자 설치 성공을 의미하지 않습니다. 기존 main, 이전 제출물, 실제 사용자 DB를 덮어쓰지 않습니다.

## 파일 목록

- SELF-CHECK.md: P1~P8 검사와 확인된 근거, 미완료 항목
- ARCHITECTURE.md, ARCHITECTURE.svg: 코드와 데이터 경계, 구성도
- RULES.md: ZTNA 정책 ID와 XDR 판정기 경로
- THREAT-INTEL.md: NVD·CISA KEV 원천 및 조회·비교 방법
- SECURITY.md: 키 관리, 권한 확인, DB 원자적 호출 제한
- 기존 실행 기록: on-client/docs/STUDENT_RELEASE_REPRODUCTION.md 및 WATCHDOGS_FINAL_OFFENSIVE_D2_D7.md

## 새 환경에 배포하는 절차 (첫 화면과 비로그인 거부는 새 프로젝트에서 실측)

1. 빈 작업 폴더에 이 저장소를 복제한다. Node.js 24.19.0을 권장한다.
2. 저장소 루트에서 npm ci, node scripts/package-secret-check.mjs, npm run package:check, npm run xdr:test, npm run build -- --local 을 실행한다. 테스트와 빌드는 운영 연동을 증명하지 않는다.
3. Vercel에서 기존 운영 프로젝트와 별개인 새 프로젝트를 같은 저장소의 검토된 커밋으로 가져온다. Framework Preset=Other, Root Directory=저장소 루트, Build Command=npm run build, Output Directory=public을 설정한다. Hobby 무료 플랜의 서버리스 함수 상한 12개를 지키기 위해 기존의 공개 읽기용 /api/public-config 와 /api/war-room-summary를 한 기존 함수(api/war-room)에서 처리한다. vercel.json이 두 URL을 재작성하고 각 공용 핸들러를 호출한다. 신규 두 서버 함수 /api/ai 와 /api/threat-intel은 각각 독립적으로 유지되며 인증된 학생 JWT를 요구한다.
4. 공개 첫 화면에 어떤 개인정보도 노출되지 않는지 확인한다. Vercel Authentication/Deployment Protection 상태와 비로그인 첫 화면의 HTTP 응답을 별도로 실측하고 기록한다. 기존 프로젝트의 보호 설정을 임의로 완화하지 않는다.
5. 별도 검증용 Supabase 프로젝트에서 먼저 db/package-ai-quota.sql의 객체와 권한을 검토한다. 실제 운영 DB에 바로 적용하지 않는다. 서버에서만 SUPABASE_URL, SUPABASE_SECRET_KEY를 설정한다. SUPABASE_PUBLISHABLE_KEY는 공개 로그인용이며 비밀 서비스 키와 다르다.
6. AI 기능을 실제로 켜야 하는 경우에만 Vercel 서버 환경 변수 OPENAI_API_KEY를 직접 설정한다. 예산·호출 과금·사용자별 4회/분 및 20회/UTC일 제한을 확인한다. OpenAI 키가 없으면 AI 요청은 503(미설정)으로 실패한다.
7. NVD_API_KEY는 필요할 때만 서버에 설정한다. /api/threat-intel 은 NVD·CISA KEV의 현재 조회 결과를 보여 주며 두 원천이 실패하면 503, 한 원천 실패 시 partial 상태로 구분한다.
8. 시험 계정의 검증된 JWT를 이용해 /api/ai 와 /api/threat-intel 을 확인한다. 비로그인 요청이 401인지 반드시 먼저 확인하고, 인증 실패·AI 제공자 오류·호출 제한·외부 원천 장애를 각각 구분한다.
9. 패키징 공식 판정 P1~P8과 새 Vercel 프로젝트 시연 URL은 실제 검사 결과가 확보된 후 기록한다. 기존 https://choi-bujang-secret-vault-jwnp.vercel.app 은 자료실 배포이지 새 패키지 검증 증거가 아니다.

## 안전하게 재현하는 예 (키를 저장소·채팅에 입력하지 않음)

~~~sh
npm ci
npm run package:check
npm run xdr:test
npm run build -- --local
# 비로그인 요청은 새 시연 프로젝트에서 401로 거부되어야 한다.
# 실제 로그인 JWT와 서비스 키는 공개 문서, URL, 콘솔 로그에 남기지 않는다.
~~~

### 알려진 제한

- ALEPH SDP 원천 엔진, 실제 XDR 대응 집행, 공식 41종 총공세 판정은 이 GitHub 소스만으로 증명되지 않는다.
- on-client 보안 Agent(기본 포트 5189)와 Windows 로컬 측정기(5191)는 Vercel에 배포되는 Node 서버리스 함수가 아니다.
- 이 브랜치의 API 2개는 기존 앱에 영향을 주지 않는 별도 인증 API로 작성했다. UI에서 실제 사용하고 있는지, 새 Vercel 프로젝트에서 작동하는지는 아직 검증 전이다.
- Supabase 서버 비밀키, AI 제공자 키, 실제 사건 데이터는 패키지에 넣지 않는다.
