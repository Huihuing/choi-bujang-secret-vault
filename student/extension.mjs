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
      const deviceState = (status) => deviceStates[status] ?? '확인 불가';
      const sessionState = (status) => sessionStates[status] ?? '확인 불가';

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
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
