# NVD·CISA KEV 침해 정보 대조 (P5 / P8)

코드: src/package-threat-intel.mjs, api/threat-intel.js

## 원천 (브라우저가 아닌 서버에서 고정 URL 조회)

- NIST NVD CVE 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
  - 단일 cveId 검색, vulnerabilities[].cve.id / published / lastModified / descriptions 값만 추출.
  - NVD_API_KEY는 필요한 경우 서버 환경 변수로만 전달한다.
- CISA Known Exploited Vulnerabilities JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - vulnerabilities[].cveID와 요청 CVE를 일치 비교한다.
  - 카탈로그 catalogVersion, dateReleased, 해당 항목 dateAdded/requiredAction을 추출한다.

## 표시 원칙

- 각 원천이 실제 HTTP 200 + 예상 JSON 구조를 반환한 경우에만 available=true와 fetchedAt(마지막 받은 시각)을 기록한다.
- NVD에 조회 결과가 없더라도 성공 응답이면 found=false; 응답 실패는 found=null.
- KEV 목록에 해당 CVE가 없다는 결과는 목록 조회에 성공한 경우에만 knownExploited=false. 통신 실패/형식 오류는 null.
- 두 소스 중 하나라도 실패하면 state=partial, 둘 다 실패하면 state=unavailable 및 HTTP 503.
- fetchedAt는 서버가 조회 결과를 확인한 시각, NVD lastModified·KEV dateReleased는 원천이 게시한 시각이다. 동일 의미로 표기하지 않는다.
- 이 대조는 외부 침해 정보 조회이며 해당 시스템이 침해됐다는 증명이 아니다. NVD 미등재 또는 KEV 미등재를 안전/무취약 판정으로 바꾸지 않는다.

## 연동 조건

- 허용 입력: CVE-YYYY-NNNN 형식(정규식 검증) 외 임의 URL, IP, 파일 경로는 받지 않는다.
- 신원: 검증된 Supabase 학생 JWT만 허용; 비로그인은 401.
- 현재 외부 제공자 실시간 정상 응답, NVD 사용량 제한, 패키지 시연 연동은 아직 실측하지 않았다.

실제 외부 접근 검증과는 별개로, 서버의 인증된 처리 경로를 의존성 주입형 단위 테스트에서 검증했다. 유효 CVE만 조회, 일부 원천 실패 시 `partial`과 `knownExploited:null` 유지가 확인되었다. 운영 서버에서 실제 NVD·CISA 원천 호출 결과로 주장하지 않는다.
