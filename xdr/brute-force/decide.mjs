const PATTERNS = Object.freeze({
  guessing: 'password-guessing',
  spraying: 'password-spraying',
});

let jevAdapter = null;

export function configureJev(adapter) {
  jevAdapter = typeof adapter === 'function' ? adapter : null;
}

function makeDecision(confidence, reason) {
  const value = Number(confidence);
  const bounded = Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
  return {
    action: bounded >= 0.85 ? 'block' : bounded >= 0.5 ? 'alert' : 'record',
    confidence: bounded,
    reason,
  };
}

function mitreIds(alert) {
  const mitre = alert?.rule?.mitre;
  if (Array.isArray(mitre)) return mitre.filter((value) => typeof value === 'string');
  const ids = mitre?.id;
  if (Array.isArray(ids)) return ids.filter((value) => typeof value === 'string');
  if (typeof ids === 'string') return [ids];
  return [];
}

function validIp(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 45) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(':');
}

function validTime(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function safeDescription(alert) {
  const value = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  if (/\b(password|passwd|secret|token|api[-_ ]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/i.test(value)) {
    return '[redacted]';
  }
  return value.slice(0, 500);
}

function countValue(alert) {
  const value = Number(alert?.data?.count);
  return Number.isInteger(value) && value >= 0 ? value : 0;
}

function distinctAccountCount(alert) {
  const value = alert?.data?.accounts;
  const accounts = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value.split(',')
      : [];
  return new Set(accounts.map((item) => String(item).trim()).filter(Boolean)).size;
}

function factsFrom(alert) {
  const description = safeDescription(alert);
  const ids = mitreIds(alert);
  const tagged = ids.some((id) => /^T1110(?:\.|$)/.test(id));
  const sprayTagged = ids.some((id) => /^T1110\.003(?:\.|$)/.test(id));
  const level = Number(alert?.rule?.level) || 0;
  const count = countValue(alert);
  const accounts = distinctAccountCount(alert);
  const sourceIp = alert?.data?.srcip ?? alert?.sourceIp ?? null;
  const timestamp = alert?.timestamp ?? alert?.time ?? null;

  const multiAccount = /여러 계정|서로 다른 계정|계정\s*\d+개|계정 이름을 바꿔|multiple\s+(?:accounts|users)|password\s*spray/i.test(description);
  const samePassword = /같은 비밀번호|same password|password\s*spray/i.test(description);
  const failure = /로그인 실패|실패|fail(?:ed|ure|ures)?|invalid password|authentication (?:error|failure)|brute.?force/i.test(description);

  return {
    description,
    tagged,
    sprayTagged,
    level,
    count,
    accounts,
    sourceIp,
    timestamp,
    multiAccount,
    samePassword,
    failure,
  };
}

async function askJev(facts) {
  if (!jevAdapter) return null;
  let timer;
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => jevAdapter({
        technique: 'T1110',
        facts: {
          level: facts.level,
          count: facts.count,
          accounts: facts.accounts,
          description: facts.description,
          pattern: facts.multiAccount || facts.sprayTagged ? PATTERNS.spraying : PATTERNS.guessing,
        },
      })),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), 1500);
      }),
    ]);
    const confidence = Number(response?.confidence);
    return Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function decide(alert) {
  const facts = factsFrom(alert);
  const hasLocation = validIp(facts.sourceIp) && validTime(facts.timestamp);

  // A low-level event without a T1110 classification is ordinary activity.
  if (!facts.tagged && facts.level <= 3) {
    return makeDecision(0.05, 'normal-event');
  }

  if (facts.tagged && hasLocation && facts.level >= 10) {
    // Wazuh already correlated many authentication failures into one high-severity T1110 alert.
    if (facts.count >= 20) {
      return makeDecision(0.95, facts.multiAccount || facts.sprayTagged ? PATTERNS.spraying : PATTERNS.guessing);
    }

    // Password spraying can be clear even without a count when the alert contains a large account set.
    if ((facts.sprayTagged || facts.multiAccount) && (facts.accounts >= 5 || (facts.samePassword && facts.count >= 10))) {
      return makeDecision(0.96, PATTERNS.spraying);
    }
  }

  // T1110 with lower severity/count is suspicious but not clear enough for an automatic deny.
  if (facts.tagged || (facts.failure && facts.level >= 5)) {
    const reason = facts.multiAccount || facts.sprayTagged ? PATTERNS.spraying : PATTERNS.guessing;
    const jevConfidence = await askJev(facts);
    return jevConfidence === null ? makeDecision(0.5, reason) : makeDecision(jevConfidence, reason);
  }

  return makeDecision(0.1, 'normal-event');
}
