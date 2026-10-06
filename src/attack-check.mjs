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

async function jsonOrNull(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function runAttackChecks(config) {
  const app = appUrl(config);

  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
      throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
    }
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      const data = await jsonOrNull(response);
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    }
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
      {
        attackId: 'static_note_seed_removed',
        expected: '정적 data.json에서 메모가 0건이어야 함',
        observed: staticCount === 0
          ? '정적 data.json에서 메모 0건 확인'
          : `정적 data.json 확인 필요 (HTTP ${staticResponse.status})`,
      },
      {
        attackId: 'anonymous_notes_api',
        expected: '2단계 서버 API가 아직 인증 없이 직접 호출 가능한지 관찰',
        observed: apiResponse.ok
          ? `비로그인 API 응답 확인 (HTTP ${apiResponse.status}, notes ${apiCount ?? '확인불가'}건)`
          : `비로그인 API 주소 응답 확인 (HTTP ${apiResponse.status})`,
      },
    ];
  }

  if (config.step === 3) {
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
    const identityOk = identityResponse.ok && identity?.step === 3;

    const rootResponse = await fetch(new URL('/', app), {
      method: 'HEAD', redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const nosniff = rootResponse.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff';
    const csp = Boolean(rootResponse.headers.get('content-security-policy'));
    const headerOk = rootResponse.ok && (nosniff || csp);

    return [
      {
        attackId: 'anonymous_notes_denied',
        expected: '로그인 없이 메모 목록 요청은 401 또는 403 JSON 오류',
        observed: denied
          ? `비로그인 메모 목록이 JSON 오류로 거부됨 (HTTP ${apiResponse.status})`
          : `비로그인 거부 확인 필요 (HTTP ${apiResponse.status})`,
      },
      {
        attackId: 'deployment_identity_step3',
        expected: '배포 /aleph.json이 열리고 step 3이어야 함',
        observed: identityOk
          ? '배포 /aleph.json에서 step 3 확인'
          : `배포 식별 정보 확인 필요 (HTTP ${identityResponse.status})`,
      },
      {
        attackId: 'first_page_security_header',
        expected: '첫 화면에 nosniff 또는 Content-Security-Policy 헤더가 있어야 함',
        observed: headerOk
          ? '첫 화면 보안 헤더 확인'
          : `첫 화면 보안 헤더 확인 필요 (HTTP ${rootResponse.status})`,
      },
    ];
  }

  throw new Error('현재 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
