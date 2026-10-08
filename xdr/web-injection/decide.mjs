const PATTERNS = Object.freeze({
  sql: 'sql-injection',
  script: 'script-injection',
  traversal: 'path-traversal',
  command: 'command-injection',
  review: 'injection-review',
});

let jevAdapter = null;

export function configureJev(adapter) {
  jevAdapter = typeof adapter === 'function' ? adapter : null;
}

function decision(confidence, reason) {
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

function safeDescription(alert) {
  const value = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  if (/(?:password|passwd|token|secret|비밀번호|암호)\s*[:=]\s*[^\s,;]+|sb_(?:secret|publishable)_|eyJ[A-Za-z0-9_-]+\.|-----BEGIN/i.test(value)) {
    return '[redacted]';
  }
  return value.replace(/[\r\n]/g, ' ').slice(0, 500);
}

function decodeBounded(value) {
  let output = typeof value === 'string' ? value.slice(0, 2048) : '';
  for (let index = 0; index < 2; index += 1) {
    try {
      const next = decodeURIComponent(output);
      if (next === output) break;
      output = next;
    } catch {
      break;
    }
  }
  return output;
}

function indicators(alert) {
  const description = safeDescription(alert);
  const url = decodeBounded(alert?.data?.url);
  const sql = /SQL\s*(?:구문|표기|표식)|데이터베이스 조회를 이어|sql injection/i.test(description)
    || /\bunion\s+(?:all\s+)?select\b|\bselect\b.{1,100}\bfrom\b|['"]\s*or\s+\d+\s*=\s*\d+/i.test(url);
  const script = /스크립트\s*(?:삽입|표식)|script injection|cross.?site scripting/i.test(description)
    || /<\s*script\b|\bon(?:error|load)\s*=/i.test(url);
  const traversal = /경로.*(?:거슬러|이탈)|path traversal/i.test(description)
    || /(?:\.\.\/){2,}/.test(url);
  const command = /명령\s*(?:구분자|삽입)|command injection/i.test(description)
    || /[;|&]\s*(?:cat|sh|bash|whoami)\b/i.test(url);
  const reason = sql ? PATTERNS.sql
    : script ? PATTERNS.script
      : traversal ? PATTERNS.traversal
        : command ? PATTERNS.command
          : PATTERNS.review;
  return { description, url, sql, script, traversal, command, reason };
}

async function askJev(facts) {
  if (!jevAdapter) return null;
  let timer;
  try {
    const answer = await Promise.race([
      Promise.resolve().then(() => jevAdapter({
        technique: 'T1190',
        facts: {
          level: facts.level,
          count: facts.count,
          description: facts.description,
          pattern: facts.reason,
        },
      })),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), 1500);
      }),
    ]);
    const confidence = Number(answer?.confidence);
    return Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function decide(alert) {
  const signal = indicators(alert);
  const tagged = mitreIds(alert).some((id) => /^T1190(?:\.|$)/.test(id));
  const level = Number(alert?.rule?.level) || 0;
  const count = Number(alert?.data?.count);
  const clearIndicator = signal.sql || signal.script || signal.traversal || signal.command;

  if (level <= 3 && !tagged && !clearIndicator) {
    return decision(0.05, 'normal-event');
  }

  // Repeated, high-severity, T1190-correlated injection is the only automatic block path.
  if (tagged && level >= 10 && Number.isInteger(count) && count >= 5 && clearIndicator) {
    return decision(0.96, signal.reason);
  }

  if (tagged || clearIndicator) {
    const jevConfidence = await askJev({
      level,
      count: Number.isInteger(count) ? count : 0,
      description: signal.description,
      reason: signal.reason,
    });
    if (jevConfidence === null) return decision(0.5, signal.reason);
    // A single ambiguous request cannot become an IP block from model opinion alone.
    return decision(Math.min(jevConfidence, 0.84), signal.reason);
  }

  return decision(0.1, 'normal-event');
}
