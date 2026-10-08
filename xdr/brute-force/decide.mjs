import { readFileSync } from 'node:fs';

const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const patternById = new Map(patterns.map((pattern) => [pattern.id, pattern]));

function pattern(id) {
  const value = patternById.get(id);
  if (!value) throw new Error(`Unknown brute-force pattern: ${id}`);
  return value;
}

function fromConfidence(confidence, reason) {
  const bounded = Math.max(0, Math.min(1, Number(confidence)));
  if (bounded >= 0.85) return { action: 'block', confidence: bounded, reason };
  if (bounded >= 0.5) return { action: 'alert', confidence: bounded, reason };
  return { action: 'record', confidence: bounded, reason };
}

async function askJev(facts) {
  const endpoint = process.env.JEV_URL;
  if (!endpoint) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1500);
  try {
    const headers = { 'content-type': 'application/json' };
    if (process.env.JEV_API_TOKEN) headers.authorization = `Bearer ${process.env.JEV_API_TOKEN}`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        technique: 'T1110',
        facts: {
          ruleLevel: facts.ruleLevel,
          sameSourceFailures2m: facts.sameSourceFailures2m,
          distinctAccounts5m: facts.distinctAccounts5m,
          upstreamPasswordSpray: facts.upstreamPasswordSpray,
          patternId: facts.patternId,
          description: facts.description,
        },
      }),
    });
    if (!response.ok) return null;
    const body = await response.json();
    const confidence = Number(body?.confidence);
    return Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export async function decide(alert) {
  const context = alert?.context ?? {};
  const ruleLevel = Number(alert?.ruleLevel ?? 0);
  const burst = Number(context.sameSourceFailures2m ?? 0);
  const distinctAccounts = Number(context.distinctAccounts5m ?? 0);
  const upstreamPasswordSpray = context.upstreamPasswordSpray === true;

  const burstPattern = pattern('same-source-failure-burst');
  const sprayPattern = pattern('multi-account-password-spray');

  if (burst >= 8 && ruleLevel >= 8) {
    return { action: 'block', confidence: 0.95, reason: burstPattern.name };
  }
  if (upstreamPasswordSpray && distinctAccounts >= 3 && ruleLevel >= 8) {
    return { action: 'block', confidence: 0.93, reason: sprayPattern.name };
  }

  const ambiguous = distinctAccounts >= 3
    ? sprayPattern
    : burst >= 4
      ? burstPattern
      : null;

  if (!ambiguous) {
    return { action: 'record', confidence: 0.2, reason: '일치 패턴 없음' };
  }

  const confidence = await askJev({
    ruleLevel,
    sameSourceFailures2m: burst,
    distinctAccounts5m: distinctAccounts,
    upstreamPasswordSpray,
    patternId: ambiguous.id,
    description: alert?.description ?? null,
  });

  // Jev failure is fail-safe: notify, never auto-block.
  if (confidence === null) {
    return { action: 'alert', confidence: 0.5, reason: ambiguous.name };
  }
  return fromConfidence(confidence, ambiguous.name);
}
