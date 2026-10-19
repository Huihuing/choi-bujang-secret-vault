// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions } = {}) {
      // The host replaces the previously mounted node with this new tree on refresh.
      // No previous identity data or DOM nodes are cached between calls.
      const root = document.createElement('section');
      const title = document.createElement('h2');
      title.textContent = '로그인 사용자·기기·세션';
      root.appendChild(title);

      const deviceStates = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionStates = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const modes = {
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const value = (item) =>
        typeof item === 'string' && item.trim() ? item :
        typeof item === 'number' && Number.isFinite(item) ? String(item) : '확인 불가';
      // Show both the exact API status and its Korean interpretation.
      // Keep raw status tokens unchanged for the official 13-stage review.
      const statusText = (status, meanings) => {
        const raw = typeof status === 'string' && status.trim()
          ? status : 'unknown';
        return raw + ' · ' + (Object.prototype.hasOwnProperty.call(meanings, raw)
          ? meanings[raw] : '확인 불가');
      };
      const deviceState = (status) => statusText(status, deviceStates);
      const sessionState = (status) => statusText(status, sessionStates);

      const line = (parent, text, tag = 'p') => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const details = (parent, pairs) => {
        const list = document.createElement('dl');
        for (const [name, content] of pairs) {
          line(list, name, 'dt');
          line(list, value(content), 'dd');
        }
        parent.appendChild(list);
      };
      const section = (heading, response, showOk) => {
        const container = document.createElement('section');
        line(container, heading, 'h3');
        const state = response && typeof response === 'object' ? response : {};
        if (Object.prototype.hasOwnProperty.call(modes, state.mode)) {
          line(container, modes[state.mode]);
        }
        if (state.status === 'loading') {
          line(container, '불러오는 중');
        } else if (state.status === 'error') {
          const message = state.error && typeof state.error.message === 'string'
            ? state.error.message.trim() : '';
          line(container, message ? '연결 실패: ' + message : '연결 실패: 오류 상세 확인 불가');
        } else if (state.status === 'ok') {
          showOk(container, state.data);
        } else {
          line(container, '확인 불가');
        }
        root.appendChild(container);
      };

      section('현재 계정', me, (parent, data) => {
        const user = data?.user;
        const device = data?.device;
        const session = data?.session;
        details(parent, [
          ['사용자 이름', user?.label],
          ['사용자 ID', user?.id],
          ['현재 기기 이름', device?.label],
          ['현재 기기 ID', device?.id],
          ['현재 기기 보안 상태', deviceState(device?.status)],
          ['현재 세션 ID', session?.id],
          ['현재 세션 상태', sessionState(session?.status)],
        ]);
      });
      section('기기 목록', devices, (parent, data) => {
        if (!Array.isArray(data)) {
          line(parent, '기기 목록 확인 불가');
          return;
        }
        if (data.length === 0) {
          line(parent, '표시할 기기가 없습니다.');
        }
        for (const device of data) {
          const entry = document.createElement('div');
          details(entry, [
            ['기기 이름', device?.label],
            ['기기 ID', device?.id],
            ['기기 보안 상태', deviceState(device?.status)],
          ]);
          parent.appendChild(entry);
        }
      });
      section('세션 목록', sessions, (parent, data) => {
        if (!Array.isArray(data)) {
          line(parent, '세션 목록 확인 불가');
          return;
        }
        if (data.length === 0) {
          line(parent, '표시할 세션이 없습니다.');
        }
        for (const session of data) {
          const entry = document.createElement('div');
          details(entry, [
            ['세션 ID', session?.id],
            ['세션 상태', sessionState(session?.status)],
          ]);
          parent.appendChild(entry);
        }
      });
      return root;
    },
    renderDecision({ status = 'idle', mode, data, error, appId } = {}) {
      // The provided UI owns access requests and replaces this DOM after every response.
      // Do not retain an earlier decision or error across requests.
      const root = document.createElement('section');
      const line = (text, tag = 'p') => {
        const node = document.createElement(tag);
        node.textContent = text;
        root.appendChild(node);
      };
      const safeText = (value, fallback = '확인 불가') =>
        typeof value === 'string' && value.trim() ? value.trim()
          : typeof value === 'number' && Number.isFinite(value) ? String(value)
          : fallback;

      line('업무 앱 접속 판정', 'h3');
      if (mode === 'demo') line('예제 자료');
      else if (mode === 'disconnected') line('연결 없음');
      else if (mode === 'unknown') line('연결 상태 확인 불가');

      const requestedAppId = status === 'ok' ? (data?.appId ?? appId) : appId;
      if (requestedAppId != null) line('업무 앱 ID: ' + safeText(requestedAppId));

      if (status === 'idle') {
        line('앱을 골라 접속을 요청하세요.');
      } else if (status === 'loading') {
        line('판정 확인 중');
      } else if (status === 'error') {
        line('요청 실패: ' + safeText(error?.message, '오류 메시지 확인 불가'));
        line('요청 실패는 접근 거부(deny) 판정이 아닙니다. 접속 결과를 확인할 수 없습니다.');
      } else if (status === 'ok') {
        const labels = {
          allow: '접근 허용',
          deny: '접근 거부',
          challenge: '추가 확인 필요',
          unknown: '확인 불가',
        };
        const decision = typeof data?.decision === 'string'
          && Object.prototype.hasOwnProperty.call(labels, data.decision)
            ? data.decision : 'unknown';
        line('접속 판정: ' + labels[decision] + '(' + decision + ')');
        line('판정 이유: ' + safeText(data?.reason, '이유 확인 불가'));
        line('판정 시각: ' + safeText(data?.checkedAt));
        if (decision === 'allow') {
          line('정책상 접근 허용이며 실제 업무 앱 접속 성공을 보장하지 않습니다.');
        } else if (decision === 'challenge') {
          line('추가 인증 또는 확인이 필요합니다. 이 화면은 인증 절차를 대신 수행하지 않습니다.');
        } else if (decision === 'unknown') {
          line('접속 가능 여부를 확인할 수 없습니다.');
        }
      } else {
        line('접속 요청 상태 확인 불가');
      }
      return root;
    },
    renderEvents({ status, mode, data, error } = {}) {
      // Only the supplied user's recent records are shown; never query another endpoint.
      // Each call owns a new DOM and selection state, so reload drops stale details.
      const root = document.createElement('section');
      const make = (tag, text) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = String(text);
        return node;
      };
      const line = (parent, text) => parent.appendChild(make('p', text));
      const value = (raw, fallback = '확인 불가') =>
        typeof raw === 'string' && raw.trim() ? raw : fallback;
      const stateLabel = (raw, meanings) => {
        const code = typeof raw === 'string' && Object.prototype.hasOwnProperty.call(meanings, raw)
          ? raw : 'unknown';
        return meanings[code] + '(' + code + ')';
      };
      const accessLabels = { allowed: '허용됨', denied: '거부됨', unknown: '확인 불가' };
      const sessionLabels = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const deviceLabels = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const kindLabels = { access: '접속 기록', xdr: 'XDR 경보' };
      const appLabel = (appId) => value(appId, '앱 ID 없음 · 확인 불가');

      root.appendChild(make('h3', '내 접속 기록과 XDR 경보'));
      if (mode === 'demo') line(root, '예제 자료 · 실제 계정 기록이 아닙니다.');
      else if (mode === 'disconnected') line(root, '연결 없음');
      else if (mode === 'unknown') line(root, '연결 상태 확인 불가');

      if (status === 'loading') {
        line(root, '기록 불러오는 중');
        return root;
      }
      if (status === 'error') {
        if (error?.code === 'CONTRACT_MISMATCH') {
          line(root, '응답 형식 확인 불가(CONTRACT_MISMATCH)');
        }
        line(root, '기록을 불러오지 못했습니다: ' + value(error?.message, '오류 내용 확인 불가'));
        return root;
      }
      if (status !== 'ok') {
        line(root, '보안 기록 확인 전 · 확인 불가');
        return root;
      }
      if (!Array.isArray(data)) {
        line(root, '기록을 확인할 수 없습니다: 응답 형식 확인 불가');
        return root;
      }
      // Copy before sorting; do not mutate server data.
      const records = data.slice().sort((a, b) =>
        (Date.parse(b?.at) || 0) - (Date.parse(a?.at) || 0));
      line(root, '현재 계정의 최근 접속·저장된 XDR 기록만 표시합니다(서버 제공 범위 최대 40건). 전체 직원 이력이나 실시간 탐지 결과가 아닙니다.');
      if (records.length === 0) {
        line(root, '표시할 기록이 없습니다');
        return root;
      }

      const filters = document.createElement('div');
      root.appendChild(filters);
      const createFilter = (name, options) => {
        const label = make('label', name);
        const select = document.createElement('select');
        select.setAttribute('aria-label', name);
        const addOption = (key, text) => {
          const option = make('option', text);
          option.value = key;
          select.appendChild(option);
        };
        addOption('all', '전체');
        for (const [key, text] of options) addOption(key, text);
        select.value = 'all';
        label.appendChild(select);
        filters.appendChild(label);
        return select;
      };
      const unique = (pick) => [...new Set(records.map(pick))];
      const kindFilter = createFilter('기록 종류',
        unique((event) => event.kind).map((kind) => [kind, (kindLabels[kind] ?? '확인 불가') + '(' + kind + ')']));
      // Missing appId is represented by the empty select value, never a fabricated ID.
      const appFilter = createFilter('업무 앱',
        unique((event) => event.appId ?? '').map((id) => [id, id === '' ? '앱 확인 불가(appId 없음)' : id]));
      const accessFilter = createFilter('접속 상태',
        unique((event) => event.state?.access ?? 'unknown').map((access) =>
          [access, stateLabel(access, accessLabels)]));

      const count = make('p');
      root.appendChild(count);
      const list = document.createElement('ul');
      root.appendChild(list);

      const makeDetail = (event) => {
        const detail = document.createElement('section');
        detail.setAttribute('data-student-event-detail', event.id);
        detail.appendChild(make('h4', '기록 상세 · ' + value(event.id)));
        line(detail, '사건 ID: ' + value(event.id));
        line(detail, '앱 ID: ' + appLabel(event.appId));
        const entries = (title, rows) => {
          detail.appendChild(make('h5', title));
          if (!Array.isArray(rows) || rows.length === 0) {
            line(detail, title + ' 없음');
            return;
          }
          const ul = document.createElement('ul');
          for (const entry of rows) {
            ul.appendChild(make('li', 'ID: ' + value(entry?.id) + ' · 내용: ' + value(entry?.text)));
          }
          detail.appendChild(ul);
        };
        entries('근거', event.evidence);
        entries('적용 규칙', event.rules);
        line(detail, '접속 상태: ' + stateLabel(event.state?.access, accessLabels));
        line(detail, '세션 상태: ' + stateLabel(event.state?.session, sessionLabels));
        line(detail, '기기 상태: ' + stateLabel(event.state?.device, deviceLabels));
        // A disabled notice is shown only when supportedActions are supplied.
        // It never sends an action request.
        if (Array.isArray(event.supportedActions) && event.supportedActions.length) {
          detail.appendChild(make('h5', '미지원 조치 안내'));
          for (const action of event.supportedActions) {
            if (typeof action !== 'string' || !action.trim()) continue;
            const button = make('button', action + ' 미지원');
            button.type = 'button';
            button.disabled = true;
            detail.appendChild(button);
          }
          line(detail, '조치 실행 연결은 준비 중입니다. 미지원 조치는 실행되지 않으며 요청을 보내지 않습니다.');
        }
        return detail;
      };

      const renderList = () => {
        list.replaceChildren();
        let selectedButton = null;
        let selectedSlot = null;
        const matching = records.filter((event) =>
          (kindFilter.value === 'all' || event.kind === kindFilter.value) &&
          (appFilter.value === 'all' || (event.appId ?? '') === appFilter.value) &&
          (accessFilter.value === 'all' || (event.state?.access ?? 'unknown') === accessFilter.value));
        count.textContent = '표시 중 ' + matching.length + '건 / 받은 기록 ' + records.length + '건';
        if (matching.length === 0) {
          list.appendChild(make('li', '조건에 맞는 기록이 없습니다'));
          return;
        }
        for (const event of matching) {
          const item = document.createElement('li');
          item.setAttribute('data-student-event-id', event.id);
          item.appendChild(make('h4', '요약: ' + value(event.summary)));
          line(item, '사건 ID: ' + value(event.id));
          line(item, '시각: ' + value(event.at));
          line(item, '종류: ' + (kindLabels[event.kind] ?? '확인 불가') + '(' + value(event.kind) + ')');
          line(item, '앱 ID: ' + appLabel(event.appId));
          const button = make('button', value(event.id) + ' 상세');
          button.type = 'button';
          button.setAttribute('aria-expanded', 'false');
          const slot = document.createElement('div');
          button.addEventListener('click', () => {
            if (selectedSlot) selectedSlot.replaceChildren();
            if (selectedButton) selectedButton.setAttribute('aria-expanded', 'false');
            if (selectedButton === button) {
              selectedButton = null;
              selectedSlot = null;
              return;
            }
            slot.replaceChildren(makeDetail(event));
            button.setAttribute('aria-expanded', 'true');
            selectedButton = button;
            selectedSlot = slot;
          });
          item.appendChild(button);
          item.appendChild(slot);
          list.appendChild(item);
        }
      };
      kindFilter.addEventListener('change', renderList);
      appFilter.addEventListener('change', renderList);
      accessFilter.addEventListener('change', renderList);
      renderList();
      return root;
    },
    renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
      // The provided UI supplies snapshots and owns all requests and refresh.
      // This function only displays current data; no previous result is cached.
      const root = document.createElement('section');
      const make = (tag, text) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = String(text);
        return node;
      };
      const line = (parent, text) => parent.appendChild(make('p', text));
      const value = (input, fallback = '확인 불가') =>
        typeof input === 'string' && input.trim() ? input.trim() : fallback;
      // Do not display or copy diagnostic fields containing secret-looking text.
      const secretPattern = /bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[a-z0-9_-]{8,}|-----BEGIN|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|password|passwd|secret|비밀번호|토큰|인증\s*키|(?:gh[opusr]_|xox[baprs]-)[a-z0-9_-]+/i;
      const safeMessage = (raw, fallback = '내용 확인 불가') => {
        const text = value(raw, fallback);
        return secretPattern.test(text) ? '비밀 정보로 의심되는 내용은 표시하지 않았습니다.' : text;
      };
      const safeField = (raw) =>
        typeof raw === 'string' && /^[A-Za-z0-9_.:+-]{1,100}$/.test(raw)
          && !secretPattern.test(raw) ? raw : '확인 불가';
      const modeNames = { connected: '연결됨', demo: '예제 자료 · 실제 연결 아님',
        disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
      const modeText = (raw) => Object.prototype.hasOwnProperty.call(modeNames, raw)
        ? modeNames[raw] : '연결 상태 확인 불가';
      const deviceNames = { compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const sessionNames = { active: '활성', expired: '만료',
        revoked: '철회됨', unknown: '확인 불가' };
      const stateText = (state, names) => {
        const code = Object.prototype.hasOwnProperty.call(names, state) ? state : 'unknown';
        return names[code] + '(' + code + ')';
      };

      root.appendChild(make('h3', '기기·세션·알림·도움정보'));
      line(root, '연결 상태: ' + modeText(mode));
      line(root, '등록 기기는 최대 100개까지 조회합니다. 세션은 현재 검증된 연결 한 개만 조회하며, 과거 세션 목록이 아닙니다.');

      const showList = (name, input, type, emptyText) => {
        const section = document.createElement('section');
        section.appendChild(make('h4', name));
        root.appendChild(section);
        const resource = input && typeof input === 'object' ? input : {};
        if (resource.mode === 'demo' || resource.mode === 'disconnected' || resource.mode === 'unknown') {
          line(section, '자료 연결: ' + modeText(resource.mode));
        }
        if (resource.status === 'loading') {
          line(section, name + ' 불러오는 중');
        } else if (resource.status === 'error') {
          const code = value(resource.error?.code, '');
          const message = safeMessage(resource.error?.message, '오류 내용 확인 불가');
          if (/timeout|timed.?out|시간\s*초과/i.test(code + ' ' + message)) {
            line(section, name + ' 조회 시간 초과');
          }
          line(section, name + '을(를) 불러오지 못했습니다: ' + message);
          line(section, '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요. 자동 재요청하지 않습니다.');
        } else if (resource.status === 'ok') {
          if (!Array.isArray(resource.data)) {
            line(section, name + ' 응답 형식 확인 불가');
          } else if (resource.data.length === 0) {
            line(section, emptyText);
          } else {
            const list = document.createElement('ul');
            for (const item of resource.data) {
              const content = type === 'device'
                ? '기기 이름: ' + value(item?.label) + ' · 상태: ' + stateText(item?.status, deviceNames)
                : '현재 세션 ID: ' + value(item?.id) + ' · 상태: ' + stateText(item?.status, sessionNames);
              list.appendChild(make('li', content));
            }
            section.appendChild(list);
          }
        } else {
          line(section, name + ' 조회 전 · 확인 불가');
        }
      };
      showList('기기', devices, 'device', '등록된 기기가 없습니다');
      showList('세션', sessions, 'session', '현재 연결 없음');

      const alerts = document.createElement('section');
      alerts.appendChild(make('h4', '주의 알림'));
      root.appendChild(alerts);
      if (!Array.isArray(notifications)) {
        line(alerts, '알림 자료 확인 불가');
      } else if (notifications.length === 0) {
        line(alerts, '주의할 알림이 없습니다');
      } else {
        const list = document.createElement('ul');
        for (const alert of notifications) {
          const code = typeof alert?.code === 'string' &&
            /^[A-Za-z0-9_.:-]{1,80}$/.test(alert.code) && !secretPattern.test(alert.code)
              ? alert.code : '확인 불가';
          list.appendChild(make('li', '자료(resource): ' + safeMessage(alert?.resource) +
            ' · 코드(code): ' + code + ' · 알림(message): ' + safeMessage(alert?.message)));
        }
        alerts.appendChild(list);
      }

      const help = document.createElement('section');
      help.appendChild(make('h4', '연결 도움정보'));
      root.appendChild(help);
      const check = diagnostics && typeof diagnostics === 'object' ? diagnostics : {};
      if (check.mode === 'demo' || check.mode === 'disconnected' || check.mode === 'unknown') {
        line(help, '자료 연결: ' + modeText(check.mode));
      }
      let copyText = '';
      if (check.status === 'loading') {
        line(help, '도움정보 불러오는 중');
      } else if (check.status === 'error') {
        const code = value(check.error?.code, '');
        const message = safeMessage(check.error?.message, '오류 내용 확인 불가');
        if (/timeout|timed.?out|시간\s*초과/i.test(code + ' ' + message)) {
          line(help, '도움정보 조회 시간 초과');
        }
        line(help, '도움정보를 불러오지 못했습니다: ' + message);
        line(help, '다시 시도는 위쪽 도움정보 조회 버튼을 직접 누르세요.');
      } else if (check.status === 'ok' && check.data && typeof check.data === 'object') {
        // Whitelist only six fields; ignore ai, credentials, token, config, etc.
        const data = check.data;
        const allowed = [
          ['requestId', safeField(data.requestId)],
          ['component', safeField(data.component)],
          ['version', safeField(data.version)],
          ['checkedAt', safeField(data.checkedAt)],
          ['engine.mode', safeField(data.engine?.mode)],
          ['engine.code', safeField(data.engine?.code)],
        ];
        for (const [key, field] of allowed) line(help, key + ': ' + field);
        copyText = allowed.map(([key, field]) => key + ': ' + field).join('\n');
      } else if (check.status === 'ok') {
        line(help, '도움정보 응답 형식 확인 불가');
      } else {
        line(help, '도움정보 조회 전');
      }
      line(help, '도움정보는 지원 요청에 사용하며, 사용자가 누른 경우에만 복사합니다.');
      const button = make('button', '도움정보 복사');
      button.type = 'button';
      button.disabled = !copyText;
      const feedback = make('p', '');
      button.addEventListener('click', async () => {
        if (!copyText) return;
        try {
          if (!navigator.clipboard?.writeText) throw Error('Clipboard unavailable');
          await navigator.clipboard.writeText(copyText);
          feedback.textContent = '도움정보를 복사했습니다.';
        } catch {
          feedback.textContent = '도움정보 복사 실패: 브라우저 클립보드 권한을 확인하세요.';
        }
      });
      help.appendChild(button);
      help.appendChild(feedback);
      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
