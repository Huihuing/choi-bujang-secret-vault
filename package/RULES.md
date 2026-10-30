# 보안 규칙 목록 — 코드 경로와 근거

## ZTNA: src/decider.mjs

실제 RULE_IDS 배열에 선언된 기본 규칙 4개:

| 규칙 ID | 역할 | 결정 위치 |
| --- | --- | --- |
| device_registered | 검증된 기기 등록 여부 확인; 미등록이면 deny | src/decider.mjs |
| step_up_required | 검증된 복합 위험 신호에 추가 확인 요청 | src/decider.mjs |
| resource_zone | 정확한 서비스·메서드·경로·대상에 대한 허용 구역 검사 | src/decider.mjs |
| instructor_write_protected | 강사 공지 쓰기 권한을 브라우저 역할 주장이 아니라 서버에서 제한 | src/decider.mjs + api/instructor-notices*.js |

메모 사용자 소유권은 API의 owner_id 검사에서 최종적으로 적용한다. 모든 요청이 기본적으로 allow 되는 구조가 아니다. src/decider.mjs의 입력은 엔진 검증 필드만 유효하며 브라우저의 role, deviceId 주장만으로 신뢰하지 않는다.

## XDR: src/xdr-decider.mjs에 연결된 여섯 시나리오

| 시나리오 | 판단기 | 증거/반응 |
| --- | --- | --- |
| XDR-01 반복 로그인 실패 | xdr/brute-force/decide.mjs | xdr/fixtures/brute-force.json, xdr/brute-force/deny-rules.json |
| XDR-02 웹 주입 | xdr/web-injection/decide.mjs | xdr/fixtures/web-injection.json, xdr/web-injection/connect.mjs |
| XDR-03 알려진 취약점 악용 | xdr/known-cve/decide.mjs | xdr/fixtures/known-cve.json, xdr/known-cve/respond.mjs |
| XDR-04 지속성 공격 | xdr/persistence/decide.mjs | xdr/fixtures/persistence.json, xdr/persistence/respond.mjs |
| XDR-05 권한 상승 | xdr/privilege/decide.mjs | xdr/fixtures/privilege.json, xdr/privilege/respond.mjs |
| XDR-06 정보 유출 | xdr/exfiltration/decide.mjs | xdr/fixtures/exfiltration.json, xdr/exfiltration/respond.mjs |

기존 ZTNA 판정은 기본값으로 보존한다. XDR 추가 거부는 신뢰된 게이트웨이의 IP/기기/가명 주체/목적지 바인딩과 증거가 있을 때만 적용한다. 실제 운영 격리·세션 회수·정보 유출 차단 완료는 시험 규칙의 존재만으로 입증되지 않는다.

## 재현/검증

- npm run decider:test, npm run xdr:test, npm run test:r5
- 저장소의 README.md에는 XDR 원본 교육용 경보 크기와 각 로컬 판정 분포가 기록되어 있다.
- 실제 ALEPH 심판 판정과 로컬/합성 시험은 별도의 근거로 유지한다.
