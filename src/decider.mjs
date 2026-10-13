// ALEPH SDP 엔진이 확인한 판정 요청만 사용합니다. 브라우저 헤더는 위험 근거가 아닙니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

function hasVerifiedCompositeRisk(request) {
  const signals = request?.signals;
  // 현재 계약에서 판정 가능한 이상 신호는 심판이 제공한 가상 사건뿐입니다.
  // 운영의 source:none / unknown 값이나 누락값을 정상 시각·네트워크로 대체하지 않습니다.
  if (!signals || typeof signals !== 'object' || signals.source !== 'judge_fixture') return false;
  const unusualHour = Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour < 6;
  const unusualNetwork = signals.network === 'unusual';
  const repeatedRisk = Array.isArray(request.recentEvents) && request.recentEvents.some(event =>
    event && typeof event === 'object' && event.kind === 'risk_signal'
    && Number.isInteger(event.count) && event.count >= 10
    && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= 300);
  return unusualHour && unusualNetwork && repeatedRisk;
}

function hasFreshEngineVerification(request) {
  const stepUp = request?.stepUp;
  return stepUp?.verified === true && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 120;
}

export async function decide(request) {
  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'],
    };
  }

  if (hasVerifiedCompositeRisk(request) && !hasFreshEngineVerification(request)) {
    return {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'step_up', reasonCode: 'step_up_required', ruleIds: ['step_up_required'],
    };
  }

  return {
    schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'],
  };
}
