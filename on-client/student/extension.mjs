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
          line(section, name + ' 정보를 불러오지 못했습니다: ' + message);
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
    renderAiConnection({ status = 'idle', mode, data, error, checkedAt, explanationAccepted } = {}) {
      // Display provided results only. Requests, cancellation, identity reset and
      // late-response suppression belong to the supplied app UI.
      const root = document.createElement('section');
      const add = (tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        root.appendChild(node);
      };
      const safeCode = (raw, supported) => typeof raw === 'string'
        && Object.prototype.hasOwnProperty.call(supported, raw) ? raw : 'AI_REQUEST_UNVERIFIED';
      const secret = /bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[a-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|access[_ -]?token|refresh[_ -]?token|비밀번호|토큰)\s*[:=]\s*\S+/i;
      const safeMessage = (raw) => typeof raw === 'string' && raw.trim()
        && raw.length <= 400 && !/[\u0000-\u001f]/.test(raw) && !secret.test(raw)
          ? raw.trim() : '오류 상세 내용은 확인할 수 없습니다.';
      const modes = { connected: '연결됨', demo: '예제 자료 · 실제 연결 아님',
        disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
      const errorGuidance = {
        ON_AI_PROVISIONING_PENDING: '앱 계정 및 AI 권한 준비 중입니다. 담당자에게 연결과 권한 발급 상태를 확인하세요.',
        WB_CLCO_AUTH_REQUIRED: '인증 실패입니다. 제공 화면에서 계정 연결 상태를 다시 확인하고 담당자에게 문의하세요.',
        WB_CLCO_ACCESS_BLOCKED: '앱 접근 권한이 제한됐습니다. 담당자에게 권한을 확인하세요.',
        ON_AI_AUTHORIZATION_CHANGED: '점검 중 앱 권한이 변경됐습니다. 담당자에게 현재 권한을 확인하세요.',
        SUBJECT_SCOPE_UNVERIFIED: '현재 계정·프로젝트 연결을 확인할 수 없습니다. 담당자에게 확인하세요.',
        WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.',
        WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.',
        WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 운영 시간을 확인하세요.',
        // These are safe transport codes. The provided UI may currently
        // normalize them to AI_REQUEST_UNVERIFIED; that contract is not changed here.
        NETWORK_ERROR: '로컬 서버와 네트워크 연결에 실패했습니다. 연결 상태를 확인하고 잠시 뒤 직접 다시 점검하세요.',
        WB_CLCO_NETWORK_ERROR: 'AI 게이트 네트워크 연결에 실패했습니다. 연결 상태를 확인하고 잠시 뒤 직접 다시 점검하세요.',
        WB_CLCO_SERVER_UNAVAILABLE: 'AI 서버가 응답하지 않습니다. 잠시 뒤 직접 다시 점검하고 반복되면 담당자에게 확인하세요.',
        WB_CLCO_RATE_LIMITED: '요청 제한 상태입니다. 잠시 뒤 사용자가 직접 다시 점검하세요.',
        WB_CLCO_TIMEOUT: 'AI 응답 시간이 초과됐습니다. 잠시 뒤 사용자가 직접 다시 점검하세요.',
        REQUEST_TIMEOUT: '서버 요청 시간이 초과됐습니다. 사용자가 직접 다시 점검하세요.',
        ENGINE_TIMEOUT: '엔진 응답 시간이 초과됐습니다. 사용자가 직접 다시 점검하세요.',
        TIMEOUT: 'AI 응답 시간이 초과됐습니다. 사용자가 직접 다시 점검하세요.',
        WB_CLCO_CANCELLED: '요청이 취소됐습니다. 이전 점검 결과는 현재 결과가 아닙니다.',
        CANCELLED: '요청이 취소됐습니다. 이전 점검 결과는 현재 결과가 아닙니다.',
        REQUEST_CANCELLED: '요청이 취소됐습니다. 이전 점검 결과는 현재 결과가 아닙니다.',
        MODEL_NOT_CONFIGURED: '사용 가능한 AI 모델이 설정되지 않았습니다. 담당자에게 확인하세요.',
        ON_AI_MODEL_LIST_EMPTY: '허용된 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
        ON_AI_INVALID_INPUT: '사건 입력을 검증하지 못했습니다. 해당 기록을 확인하세요.',
        ON_AI_INVALID_OUTPUT: 'AI 설명 결과를 검증하지 못했습니다. 해당 기록의 근거를 확인하세요.',
        AI_REQUEST_UNVERIFIED: 'AI 연결 또는 응답 원인을 확인할 수 없습니다. 네트워크 상태와 계정 연결을 확인하고 잠시 뒤 직접 다시 점검하세요. 문제가 반복되면 담당자에게 권한과 오류 코드를 확인하세요.',
      };

      add('h3', '알레프게이트 AI 연결 점검');
      if (Object.prototype.hasOwnProperty.call(modes, mode)) add('p', '연결 모드: ' + modes[mode]);

      if (status === 'idle') {
        add('p', 'AI 연결 점검 전');
        add('p', '계정·앱 권한 연결을 마친 뒤 제공 화면의 점검 버튼을 직접 누르세요.');
      } else if (status === 'loading') {
        add('p', 'AI 연결 점검 중');
        add('p', '아직 권한 또는 모델 점검 결과가 확정되지 않았습니다.');
      } else if (status === 'error') {
        const code = safeCode(error?.code, errorGuidance);
        add('p', 'AI 연결 점검 실패 · 오류 코드: ' + code);
        add('p', '오류 메시지: ' + safeMessage(error?.message));
        add('p', '안내: ' + errorGuidance[code]);
        add('p', '이 실패는 사건의 보안 판정이 아닙니다. 이전 연결 점검은 현재 결과가 아닙니다.');
      } else if (status === 'ok') {
        if (data?.transportChecked !== true || !['test', 'verified'].includes(data?.audienceAuthorization)
            || !Number.isInteger(data?.modelCount) || data.modelCount < 0) {
          add('p', 'AI 연결 점검 결과 확인 불가 · 응답 계약이 맞지 않습니다.');
        } else {
          add('p', data.audienceAuthorization === 'test'
            ? '시험 연결 점검(test) · 실제 앱 권한 확인 결과가 아닙니다.'
            : '앱 권한 확인 후 점검(verified) · 점검 당시의 앱 권한 및 모델 응답입니다.');
          add('p', '모델 응답 수: ' + String(data.modelCount));
          const time = typeof checkedAt === 'string' && /^\d{4}-\d{2}-\d{2}T[\d:.+-]+Z?$/.test(checkedAt)
            && Number.isFinite(Date.parse(checkedAt)) ? checkedAt : '확인 불가';
          add('p', '점검 시각: ' + time);
          if (data.modelCount === 0) add('p', '현재 이용 가능한 모델 수가 0개입니다. 실제 사건 설명은 확인되지 않았습니다.');
          add('p', '사건 설명은 아직 실행하지 않았습니다. 모델 연결 점검은 사건 설명 호출의 성공을 의미하지 않습니다.');
        }
      } else {
        add('p', 'AI 연결 점검 상태 확인 불가');
      }
      // explanationAccepted is deliberately not interpreted as a model-call receipt.
      add('p', '다시 점검하려면 제공 화면의 「현재 API 연결 점검」을 직접 누르세요. 자동 재점검은 하지 않습니다.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt } = {}) {
      // Stage 18: a fresh, read-only DOM view of the CURRENT selected event.
      // The provided host owns AI requests, cancellation, record refresh and
      // generation checks. No student-side cache, request or action is used.
      const root = document.createElement('section');
      const add = (tag, value, parent = root) => {
        const node = document.createElement(tag);
        node.textContent = String(value);
        parent.appendChild(node);
        return node;
      };
      const list = (title, values) => {
        add('h4', title);
        const ul = document.createElement('ul');
        for (const value of values) add('li', value, ul);
        root.appendChild(ul);
      };
      const secret = /bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[a-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|access[_ -]?token|refresh[_ -]?token|비밀번호|토큰)\s*[:=]\s*\S+/i;
      const safeText = (value, max) => typeof value === 'string'
        && value.trim().length > 0 && value.length <= max
        && !secret.test(value)
        && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
      const safeId = (value) => typeof value === 'string'
        && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value) && !secret.test(value);
      const allowedCodes = new Set([
        'ON_AI_PROVISIONING_PENDING', 'WB_CLCO_AUTH_REQUIRED',
        'WB_CLCO_ACCESS_BLOCKED', 'WB_CLCO_COHORT_BUDGET_EXHAUSTED',
        'WB_CLCO_RATE_LIMITED', 'WB_CLCO_LIMIT_REACHED', 'WB_CLCO_SESSION_CLOSED',
        'WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT', 'TIMEOUT',
        'WB_CLCO_CANCELLED', 'CANCELLED', 'REQUEST_CANCELLED',
        'MODEL_NOT_CONFIGURED', 'ON_AI_AUTHORIZATION_CHANGED',
        'ON_AI_MODEL_LIST_EMPTY', 'SUBJECT_SCOPE_UNVERIFIED',
        'ON_AI_INVALID_INPUT', 'ON_AI_INVALID_OUTPUT', 'AI_REQUEST_UNVERIFIED',
        'NETWORK_ERROR', 'WB_CLCO_NETWORK_ERROR',
      ]);
      const fail = (reason) => {
        add('p', 'AI 설명 사용 불가: ' + reason);
        add('p', '원본 보안 기록과 업무 앱 판정은 그대로 유지됩니다. 근거가 확인되지 않은 설명을 사실로 표시하지 않습니다.');
        return root;
      };

      add('h3', 'AI 설명(참고용)');
      if (explanation?.mode === 'demo') {
        add('p', '예제 응답(demo)입니다. 실제 AI 모델 설명 성공을 확인한 결과가 아닙니다.');
      }

      // An error must be shown even when the supplied event is null.
      if (explanation?.status === 'error') {
        const code = allowedCodes.has(explanation.error?.code)
          ? explanation.error.code : 'AI_REQUEST_UNVERIFIED';
        const message = safeText(explanation.error?.message, 400)
          ? explanation.error.message : '오류 상세 메시지를 안전하게 확인할 수 없습니다.';
        add('p', 'AI 설명 실패 · 오류 코드: ' + code);
        add('p', '오류 메시지: ' + message);
        if (code === 'ON_AI_INVALID_INPUT') {
          add('p', '실패 사유: 설명에 필요한 사건 근거·규칙이 부족하거나 확인되지 않았습니다.');
        } else if (code === 'ON_AI_INVALID_OUTPUT') {
          add('p', '실패 사유: AI 설명의 근거 ID·조치·응답 형식이 현재 기록과 일치하지 않습니다. 이미 실행했다고 주장하는 설명도 사용할 수 없습니다.');
        } else {
          add('p', 'AI 설명 결과를 확인할 수 없습니다. 현재 기록을 기준으로 확인하세요.');
        }
        add('p', '기록은 그대로입니다. AI 설명 실패가 업무 앱 판정이나 과제 실패를 의미하지 않습니다.');
        return root;
      }
      if (!event || !safeId(event.id)) {
        add('p', '보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        add('p', '사건 ID: ' + event.id);
        add('p', 'AI 설명 요청 중 · 아직 AI 설명 결과가 없습니다.');
        return root;
      }
      if (explanation?.status !== 'ok') {
        add('p', '이 사건의 AI 설명은 아직 실행하지 않았습니다. 기록은 그대로입니다.');
        return root;
      }

      const data = explanation.data;
      if (!data || data.executed === true) {
        return fail(data?.executed === true
          ? 'AI가 이미 실행했다고 주장한 응답은 허용되지 않습니다. 제안만으로 보안 조치가 실행되지 않습니다.'
          : 'AI 설명 결과가 없습니다.');
      }
      if (!safeText(data.summary, 1500) || data.requiresHumanConfirmation !== true
          || data.executed !== false || !Array.isArray(data.evidenceIds)
          || !Array.isArray(data.proposals) || data.proposals.length > 3) {
        return fail('AI 설명의 요약·근거·사람 확인·미실행 정보가 유효하지 않습니다.');
      }

      const rows = event.evidence, rules = event.rules, actions = event.supportedActions;
      if (!Array.isArray(rows) || rows.length === 0 || rows.length > 20
          || !Array.isArray(rules) || rules.length === 0 || rules.length > 20
          || !Array.isArray(actions)
          || !rows.every(row => safeId(row?.id) && safeText(row?.text, 500))
          || !rules.every(row => safeId(row?.id) && safeText(row?.text, 300))
          || !actions.every(safeId)) {
        return fail('현재 사건의 근거 또는 규칙이 부족하거나 유효하지 않습니다.');
      }
      const evidenceMap = new Map(rows.map(row => [row.id, row.text]));
      if (evidenceMap.size !== rows.length || new Set(rules.map(row => row.id)).size !== rules.length) {
        return fail('현재 사건의 근거 또는 규칙 ID가 중복됩니다.');
      }
      if (data.evidenceIds.length !== rows.length
          || new Set(data.evidenceIds).size !== data.evidenceIds.length
          || !data.evidenceIds.every(id => safeId(id) && evidenceMap.has(id))) {
        return fail('AI가 인용한 근거 ID가 현재 사건의 근거와 맞지 않거나 일부 근거가 빠졌습니다.');
      }

      const sourceState = event.state;
      const validStates = {
        access: ['allowed', 'denied', 'unknown'],
        session: ['active', 'expired', 'revoked', 'unknown'],
        device: ['compliant', 'noncompliant', 'unknown'],
      };
      if (!sourceState || typeof sourceState !== 'object'
          || Object.keys(validStates).some(key => !validStates[key].includes(sourceState[key]))) {
        return fail('접속·세션·기기의 현재 상태를 확인할 수 없습니다.');
      }

      if (!data.proposals.every(p => p && safeId(p.action)
          && actions.includes(p.action) && safeText(p.reason, 500)
          && Array.isArray(p.evidenceIds) && p.evidenceIds.length > 0
          && new Set(p.evidenceIds).size === p.evidenceIds.length
          && p.evidenceIds.every(id => safeId(id) && evidenceMap.has(id)))) {
        return fail('AI 조치 제안이 지원 조치 또는 인용 근거와 맞지 않습니다. 어떠한 조치도 실행되지 않았습니다.');
      }

      // Add the success marker only after ALL evidence and proposal checks.
      root.setAttribute('data-student-explanation-event', event.id);
      add('p', '사건 ID: ' + event.id);
      add('p', 'AI 요약(참고용): ' + data.summary);
      if (typeof checkedAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(checkedAt)
          && Number.isFinite(Date.parse(checkedAt))) {
        add('p', '설명 확인 시각: ' + checkedAt);
      }
      add('p', 'AI 설명은 해석입니다. 사실 판단은 인용한 근거와 연동 시스템이 알려 준 현재 상태를 기준으로 하세요.');

      list('인용한 근거 ID와 원문', data.evidenceIds.map(id => id + ' — ' + evidenceMap.get(id)));
      list('현재 사건의 규칙', rules.map(rule => rule.id + ' — ' + rule.text));

      const labels = { access: '접속', session: '세션', device: '기기' };
      const unknown = Object.keys(labels).filter(key => sourceState[key] === 'unknown')
        .map(key => labels[key] + ': 확인 불가(unknown)');
      add('h4', '현재 상태 중 확인 불가 항목');
      if (unknown.length) list('확인 불가 상태', unknown);
      else add('p', '없음');

      add('h4', 'AI 조치 제안');
      if (data.proposals.length === 0) {
        add('p', actions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : '지원 가능한 조치는 있으나 AI가 이 사건에 대해 제안한 조치는 없습니다.');
        add('p', 'AI는 어떤 조치도 실행하지 않았습니다.');
      } else {
        const details = data.proposals.map(p => p.action + ' — ' + p.reason
          + ' (인용 근거: ' + p.evidenceIds.join(', ') + ')');
        list('조치별 제안과 근거', details);
        add('p', '제안은 미실행입니다. 실행하려면 별도의 사람 확인이 필요하며 아직 실행되지 않았습니다.');
      }
      add('p', 'AI 설명과 제안만으로 보안 조치는 실행되지 않습니다.');
      return root;
    },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
