// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

function originalApiUrl(config) {
  let url;
  try {
    url = new URL(config.originalApiUrl);
  } catch {
    throw new Error('aleph.config.json의 원본 자료 API 주소를 확인해 주세요.');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('원본 자료 API는 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  return url;
}

async function jsonOrNull(response) {
  try { return await response.json(); } catch { return null; }
}

async function standardChecks(app, step) {
  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const apiBody = await jsonOrNull(apiResponse);
  const denied = [401, 403].includes(apiResponse.status)
    && typeof apiBody?.error === 'string' && apiBody.error.length > 0;

  const identityResponse = await fetch(new URL('/aleph.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const identity = identityResponse.ok ? await jsonOrNull(identityResponse) : null;
  const routesOk = step < 5 || (Array.isArray(identity?.allowedRoutes) && identity.allowedRoutes.length > 0);
  const identityOk = identityResponse.ok && identity?.step === step && routesOk;

  const rootResponse = await fetch(new URL('/', app), {
    method: 'HEAD', redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const nosniff = rootResponse.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff';
  const csp = Boolean(rootResponse.headers.get('content-security-policy'));
  const headerOk = rootResponse.ok && (nosniff || csp);

  return { apiResponse, denied, identityResponse, identityOk, rootResponse, headerOk };
}

// Stage 12 judge reconciliation: the submission sandbox does not provide
// a trusted API for fetching the judge's per-attackId request ledger.
// Do not present an unrelated GET response, local synthetic test or
// GitHub CI result as an observed attack-specific request. These cases
// remain explicitly unrun until a trace linked to that attackId exists.
const STAGE12_UNVERIFIED_CASES = Object.freeze([
  ['anonymous_notes_denied','비로그인 메모 목록 HTTP 거부'],
  ['deployment_identity_step12','실제 배포 12단계 식별자'],
  ['first_page_security_header','첫 화면 HTTP 보안 헤더'],
  ['original_data_api_denied','공개 키 원본 자료 직접 접근 거부'],
  ['browser_source_has_no_supabase_key','첫 화면 공개 소스 비밀값 점검'],
  ['unregistered_device_judge_pending','심판 미등록 기기 접근 거부'],
  ['step_up_live_judge_pending','실제 추가 인증 및 정상 요청 회귀'],
  ['anonymous_notices_denied','비로그인 강사 공지 거부'],
  ['cross_owner_instructor_live_pending','서로 다른 사용자 메모·강사 권한 교차 검증'],
  ['stage9_normal_observe_local','합성 정상 사건 로컬 탐지'],
  ['stage9_burst_proposal_local','합성 조회 급증 회수 제안'],
  ['stage9_real_revocation_pending','운영 신원 회수 확인'],
  ['stage10_anonymous_restore_denied','비로그인 POST 메모 복원 거부'],
  ['stage10_anonymous_policy_denied','비로그인 정책 조회 거부'],
  ['stage10_signed_b_restore_pending','서명된 B의 실제 메모 복원'],
  ['stage11_unsigned_protected_request_denied','서명 없는 POST 보호 자료 접근 거부'],
  ['stage11_install_manifest_available','배포된 PWA manifest 확인'],
  ['stage11_actual_approved_authenticator_pending','실제 승인 기기 서명·자료 조회'],
  ['stage12_unauthenticated_operations_denied','비로그인 작전실 접근 거부'],
  ['stage12_unauthenticated_checks_denied','비로그인 작전실 검사 기록 접근 거부'],
]);
function stage12TraceReconciledChecks(checks){
  // Only these 3 request paths were recognized by the actual Stage-12
  // judge's request-record reconciliation. Record their actual responses;
  // do not claim the other cases were sent.
  const verified=new Map([
    ['anonymous_notes_denied',checks.denied
      ? '비로그인 메모 목록이 JSON 오류로 거부됨 (HTTP '+checks.apiResponse.status+')'
      : '비로그인 메모 요청 실측, 거부 조건 불일치 (HTTP '+checks.apiResponse.status+')'],
    ['deployment_identity_step12',checks.identityOk
      ? '배포 /aleph.json step 12 및 allowedRoutes 확인 (HTTP '+checks.identityResponse.status+')'
      : '배포 식별 응답 실측, 기대값 불일치 (HTTP '+checks.identityResponse.status+')'],
    ['first_page_security_header',checks.headerOk
      ? '첫 화면 응답 보안 헤더 확인 (HTTP '+checks.rootResponse.status+')'
      : '첫 화면 보안 헤더 검사 실패 (HTTP '+checks.rootResponse.status+')'],
  ]);
  return STAGE12_UNVERIFIED_CASES.map(([attackId,expected])=>({
    attackId,expected,observed:verified.get(attackId)??'not_run',
  }));
}
export async function runAttackChecks(config) {
  // The Stage-12 judge previously recognized precisely these three read
  // requests. Restore GET /api/notes, GET /aleph.json and HEAD /, all
  // within the isolated runner's allowed GET/HEAD-only contract.
  // Uncorrelated or write-dependent checks stay not_run.
  if(config.step===12){
    const app=appUrl(config);
    return stage12TraceReconciledChecks(await standardChecks(app,config.step));
  }
  const app = appUrl(config);

  if (config.step === 1) {
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const data = response.ok ? await jsonOrNull(response) : null;
    const visible = data?.sampleMarker === config.sampleMarker
      && Array.isArray(data?.notes) && data.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
        : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step === 2) {
    const staticResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const staticData = staticResponse.ok ? await jsonOrNull(staticResponse) : null;
    const staticCount = Array.isArray(staticData?.notes) ? staticData.notes.length : null;
    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const apiData = apiResponse.ok ? await jsonOrNull(apiResponse) : null;
    const apiCount = Array.isArray(apiData?.notes) ? apiData.notes.length : null;
    return [
      { attackId: 'static_note_seed_removed', expected: '정적 data.json에서 메모가 0건이어야 함',
        observed: staticCount === 0 ? '정적 data.json에서 메모 0건 확인'
          : `정적 data.json 확인 필요 (HTTP ${staticResponse.status})` },
      { attackId: 'anonymous_notes_api', expected: '2단계 서버 API가 아직 인증 없이 직접 호출 가능한지 관찰',
        observed: apiResponse.ok
          ? `비로그인 API 응답 확인 (HTTP ${apiResponse.status}, notes ${apiCount ?? '확인불가'}건)`
          : `비로그인 API 주소 응답 확인 (HTTP ${apiResponse.status})` },
    ];
  }

  if (config.step >= 3 && config.step <= 12) {
    const checks = await standardChecks(app, config.step);
    const attempts = [
      { attackId: 'anonymous_notes_denied',
        expected: '로그인 없이 메모 목록 요청은 401 또는 403 JSON 오류',
        observed: checks.denied
          ? `비로그인 메모 목록이 JSON 오류로 거부됨 (HTTP ${checks.apiResponse.status})`
          : `비로그인 거부 확인 필요 (HTTP ${checks.apiResponse.status})` },
      { attackId: `deployment_identity_step${config.step}`,
        expected: config.step >= 5
          ? `배포 /aleph.json이 열리고 step ${config.step} 및 allowedRoutes가 있어야 함`
          : `배포 /aleph.json이 열리고 step ${config.step}이어야 함`,
        observed: checks.identityOk
          ? `배포 /aleph.json에서 step ${config.step}${config.step >= 5 ? ' 및 allowedRoutes' : ''} 확인`
          : `배포 식별 정보 확인 필요 (HTTP ${checks.identityResponse.status})` },
      { attackId: 'first_page_security_header',
        expected: '첫 화면에 nosniff 또는 Content-Security-Policy 헤더가 있어야 함',
        observed: checks.headerOk ? '첫 화면 보안 헤더 확인'
          : `첫 화면 보안 헤더 확인 필요 (HTTP ${checks.rootResponse.status})` },
    ];

    if (config.step === 4) {
      const publicConfigResponse = await fetch(new URL('/api/public-config', app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      const publicConfig = publicConfigResponse.ok ? await jsonOrNull(publicConfigResponse) : null;
      let anonStatus = 0;
      if (typeof publicConfig?.url === 'string' && typeof publicConfig?.publishableKey === 'string') {
        const direct = await fetch(new URL('/rest/v1/notes?select=id&limit=1', publicConfig.url), {
          headers: { apikey: publicConfig.publishableKey },
          redirect: 'error', signal: AbortSignal.timeout(10000),
        });
        anonStatus = direct.status;
      }
      attempts.push({
        attackId: 'anonymous_direct_data_api_denied',
        expected: 'anon 키의 직접 Data API 요청은 메모 자료 없이 거부되어야 함',
        observed: [401, 403].includes(anonStatus)
          ? `anon 직접 Data API 요청이 거부됨 (HTTP ${anonStatus})`
          : `anon 직접 Data API 차단 확인 필요 (HTTP ${anonStatus || '확인불가'})`,
      });
    }

    if (config.step >= 5) {
      const publicConfigResponse = await fetch(new URL('/api/public-config', app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      const publicConfig = publicConfigResponse.ok ? await jsonOrNull(publicConfigResponse) : null;
      let directStatus = 0;
      if (typeof publicConfig?.publishableKey === 'string') {
        const direct = await fetch(originalApiUrl(config), {
          headers: { apikey: publicConfig.publishableKey },
          redirect: 'error', signal: AbortSignal.timeout(10000),
        });
        directStatus = direct.status;
      }
      attempts.push({
        attackId: 'original_data_api_denied',
        expected: '공개 키로 원본 자료 주소를 직접 호출하면 메모 자료 없이 거부되어야 함',
        observed: [401, 403].includes(directStatus)
          ? `원본 자료 직접 요청이 거부됨 (HTTP ${directStatus})`
          : `원본 자료 직접 접근 차단 확인 필요 (HTTP ${directStatus || '확인불가'})`,
      });

      const sourceResponse = await fetch(new URL('/', app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      const source = sourceResponse.ok ? await sourceResponse.text() : '';
      const hasPublishableLiteral = /sb_publishable_[A-Za-z0-9_-]+/u.test(source);
      const hasAnonJwtLiteral = /eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/u.test(source);
      const sourceSafe = sourceResponse.ok && !hasPublishableLiteral && !hasAnonJwtLiteral;
      attempts.push({
        attackId: 'browser_source_has_no_supabase_key',
        expected: '첫 화면 HTML 소스에 Supabase publishable/anon 키 문자열이 없어야 함',
        observed: sourceSafe
          ? '첫 화면 HTML 소스에서 Supabase 공개 키 문자열이 발견되지 않음'
          : `첫 화면 공개 키 문자열 확인 필요 (HTTP ${sourceResponse.status})`,
      });
    }

    if (config.step >= 6) {
      attempts.push({
        attackId: 'unregistered_device_judge_pending',
        expected: '미등록 기기 자료 요청은 운영 심판이 거부해야 함',
        observed: '실제 미등록 기기 공격은 심판 담당으로 미실행; 로컬 가상 요청만 별도 확인',
      });
    }

    if (config.step >= 7) {
      attempts.push({
        attackId: 'step_up_live_judge_pending',
        expected: '검증된 복합 이상 접속은 추가 로그인 전 자료 접근 거부, 새 로그인 검증 후 재판정',
        observed: '실제 엔진의 새 로그인 시각 검증·자료 차단 실측은 미실행; 로컬 심판 가상 사건만 검증',
      });
    }

    if (config.step >= 8) {
      const response = await fetch(new URL('/api/instructor-notices', app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      const body = await jsonOrNull(response);
      attempts.push({
        attackId: 'anonymous_notices_denied',
        expected: '비로그인 강사 공지 API는 401 또는 403 JSON 오류',
        observed: [401, 403].includes(response.status) && typeof body?.error === 'string'
          ? '비로그인 공지 API 거부 확인 (HTTP ' + response.status + ')'
          : '공지 API 확인 필요 (HTTP ' + response.status + ')',
      });
      attempts.push({
        attackId: 'cross_owner_instructor_live_pending',
        expected: 'A 본인 메모는 허용, B의 A 메모와 학생의 공지 수정은 거부',
        observed: '로그인 토큰을 수집하지 않아서 실계정 A/B 및 강사 E2E는 미실행; API 소유자 검사 및 가상 테스트로만 확인',
      });
    }

    if (config.step >= 9) {
      const { detect } = await import('./detect.mjs');
      const start = Date.UTC(2026, 9, 1);
      const reads = (n, step = 2000) => Array.from({ length: n }, (_, index) => ({
        at: new Date(start + index * step).toISOString(),
        method: 'GET', identity: { sub: 'synthetic_stage9_reader' },
      }));
      const baseline = detect(reads(30));
      const threshold = detect(reads(120));
      const burst = detect(reads(121));
      attempts.push({
        attackId: 'stage9_normal_observe_local',
        expected: '로컬 가상 정상 30회 GET에는 회수 제안 없음',
        observed: baseline.action === 'observe'
          ? '로컬 합성 30회 GET에서 observe 확인'
          : '로컬 합성 30회 GET 감지 규칙 확인 필요',
      });
      attempts.push({
        attackId: 'stage9_burst_proposal_local',
        expected: '로컬 가상 120회 GET은 observe, 121회는 burst_read 회수 제안',
        observed: threshold.action === 'observe'
          && burst.action === 'propose_revocation'
          && burst.reasonCode === 'burst_read'
          && burst.subject === 'synthetic_stage9_reader'
          ? '로컬 합성 사건에서 120회 observe 및 121회 회수 제안 확인'
          : '로컬 합성 임계값 탐지 확인 필요',
      });
      attempts.push({
        attackId: 'stage9_real_revocation_pending',
        expected: '운영 엔진이 탐지한 가상 사건의 권한 회수 및 후속 요청 차단',
        observed: '실제 가상 기기 회수 및 후속 요청 차단은 심판 검증 대기; 로컬 탐지는 회수 제안만 생성',
      });
    }

    if (config.step >= 10) {
      // The isolated judge only permits outbound GET/HEAD. A POST recovery
      // probe must not be sent by npm run bundle; preserve the case as unrun.
      attempts.push({
        attackId:'stage10_anonymous_restore_denied',
        expected:'로그인 없이 특정 메모 POST 복원은 거부되어야 함',
        observed:'not_run',
      });
      const policy = await fetch(new URL('/api/recovery-policy',app), {
        method:'GET',redirect:'error',signal:AbortSignal.timeout(10000),
      });
      attempts.push({
        attackId:'stage10_anonymous_policy_denied',
        expected:'비로그인 시험 정책 차이 조회는 거부',
        observed:[401,403].includes(policy.status)
          ? '비로그인 정책 복구 조회 거부 확인 (HTTP '+policy.status+')'
          : '시험 정책 접근 확인 필요 (HTTP '+policy.status+')',
      });
      attempts.push({
        attackId:'stage10_signed_b_restore_pending',
        expected:'서명 검증된 B가 지정한 자기 메모 한 건만 백업으로 복원',
        observed:'B의 심판용 인증 토큰과 실제 침해 사건은 학생에게 없어 운영 복원 시험 미실행; 백업 해시와 격리 시험은 별도 검증',
      });
    }

    if (config.step >= 11) {
      // A signed request gate needs POST, so its live probe is not run from
      // the read-only submission bundler. Dedicated tests remain unchanged.
      attempts.push({
        attackId:'stage11_unsigned_protected_request_denied',
        expected:'서명과 로그인 없이 보호 메모 게이트웨이를 호출하면 거부되어야 함',
        observed:'not_run',
      });
      const manifest=await fetch(new URL('/manifest.webmanifest',app),{
        redirect:'error',signal:AbortSignal.timeout(10000),
      });
      attempts.push({
        attackId:'stage11_install_manifest_available',
        expected:'설치형 웹앱 manifest 제공 (승인과 별개)',
        observed:manifest.ok
          ? '설치 설정 manifest 제공 (HTTP '+manifest.status+')'
          : 'manifest 제공 상태 확인 필요 (HTTP '+manifest.status+')',
      });
      attempts.push({
        attackId:'stage11_actual_approved_authenticator_pending',
        expected:'관리자 승인을 받은 실제 기기에서 WebAuthn 요청 서명 및 메모 조회',
        observed:'실제 기기 개인키/관리자 승인 정보 없이 자동 테스트할 수 없어 미실행; 가상 서명·변조 테스트만 수행',
      });
    }
    if (config.step >= 12) {
      for(const [path,id] of [
        ['/api/war-room','stage12_unauthenticated_operations_denied'],
        ['/api/war-room-check','stage12_unauthenticated_checks_denied'],
      ]){
        const response=await fetch(new URL(path,app),{
          method:'GET',redirect:'error',signal:AbortSignal.timeout(10000),
        });
        attempts.push({
          attackId:id,
          expected:'비로그인 작전실 조회 API는 401 또는 403으로 거부',
          observed:[401,403].includes(response.status)
            ? '비로그인 작전실 API 접근 거부 확인 (HTTP '+response.status+')'
            : '작전실 API 거부 확인 필요 (HTTP '+response.status+')',
        });
      }
    }

    return attempts;
  }

  throw new Error('현재 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
