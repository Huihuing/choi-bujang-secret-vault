import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { extract } from './read-alerts.mjs';

const rulesFile = new URL('./deny-rules.json', import.meta.url);
const logFile = new URL('../alerts.log', import.meta.url);
const TTL_MS = 15 * 60 * 1000;

export function makeRule(alert, decision, observedAt = Date.now()) {
  const safe = extract(alert);
  if (
    decision?.action !== 'block'
    || Number(decision?.confidence) < 0.85
    || !safe.sourceIp
    || !safe.time
    || typeof alert?.id !== 'string'
    || !/^wi-[0-9]+$/.test(alert.id)
  ) return null;

  const start = Date.parse(safe.time);
  if (!Number.isFinite(start) || !Number.isFinite(observedAt)) return null;
  if (start > observedAt + 5000 || observedAt >= start + TTL_MS) return null;

  return {
    id: `xdr.web-injection.${alert.id}`,
    sourceIp: safe.sourceIp,
    alertId: alert.id,
    pattern: decision.reason,
    startsAt: new Date(start).toISOString(),
    expiresAt: new Date(start + TTL_MS).toISOString(),
  };
}

export async function persistRules(rules) {
  await writeFile(rulesFile, `${JSON.stringify(rules, null, 2)}\n`, 'utf8');
}

export async function logDecision(alert, decision) {
  if (!['block', 'alert'].includes(decision?.action)) return;
  if (typeof alert?.id !== 'string' || !/^wi-[0-9]+$/.test(alert.id)) return;
  const line = JSON.stringify({
    module: 'web-injection',
    alertId: alert.id,
    action: decision.action,
    confidence: decision.confidence,
    pattern: decision.reason,
  });
  await appendFile(logFile, `${line}\n`, 'utf8');
}

export async function loadRules() {
  try {
    const parsed = JSON.parse(await readFile(rulesFile, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export function createGuard(baseDecide, getRules) {
  return async function guardedDecide(request, { sourceIp, now = Date.now() } = {}) {
    const rules = await getRules();
    const match = isIP(sourceIp ?? '') && rules.find((rule) =>
      rule.sourceIp === sourceIp
      && Date.parse(rule.startsAt) <= now
      && now < Date.parse(rule.expiresAt)
    );
    if (match) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'deny',
        reasonCode: 'starter_not_ready',
        ruleIds: [match.id],
      };
    }
    return baseDecide(request);
  };
}
