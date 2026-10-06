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
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
        : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step === 2) {
    const staticResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let staticCount = null;
    if (staticResponse.ok) {
      try {
        const data = await staticResponse.json();
        staticCount = Array.isArray(data?.notes) ? data.notes.length : null;
      } catch {
        staticCount = null;
      }
    }

    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let apiCount = null;
    if (apiResponse.ok) {
      try {
        const data = await apiResponse.json();
        apiCount = Array.isArray(data?.notes) ? data.notes.length : null;
      } catch {
        apiCount = null;
      }
    }

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

  throw new Error('현재 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
