export const AI_MAX_CHARS = 1200;
export const AI_MAX_TOKENS = 256;
export const AI_MODEL = 'gpt-4.1-mini';
export const AI_PROVIDER_URL = 'https://api.openai.com/v1/responses';

export function parseExplanation(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(k => !['summary', 'ruleIds'].includes(k))) return null;
  const summary = body.summary;
  const ruleIds = body.ruleIds ?? [];
  if (typeof summary !== 'string' || summary !== summary.trim()
      || summary.length < 10 || summary.length > AI_MAX_CHARS
      || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(summary)
      || !Array.isArray(ruleIds) || ruleIds.length > 10
      || !ruleIds.every(id => typeof id === 'string' && /^[a-zA-Z0-9_.-]{1,70}$/u.test(id))) return null;
  return { summary, ruleIds };
}

export async function consumeQuota(supabase, userId) {
  // Atomic DB RPC; a process-local Map is not an enforceable serverless quota.
  let result;
  try {
    result = await supabase.rpc('package_ai_consume', { p_owner_id: userId });
  } catch {
    return { state: 'unavailable' };
  }
  const quota = result?.data;
  if (result?.error || !quota || typeof quota !== 'object'
      || typeof quota.allowed !== 'boolean') return { state: 'unavailable' };
  if (!quota.allowed) {
    const retry = Number(quota.retryAfterSeconds);
    return {
      state: 'limited',
      retryAfterSeconds: Number.isInteger(retry) && retry >= 1 && retry <= 86400 ? retry : 60,
    };
  }
  return { state: 'allowed' };
}

export function explanationPayload({ summary, ruleIds }) {
  return {
    model: AI_MODEL,
    instructions: 'You are a security-event explanation assistant. Explain the supplied event in Korean in plain language. Distinguish observed evidence from uncertain hypotheses. Do not claim to have blocked an attack or accessed live systems. Never invent incidents, identities or mitigations. Keep it concise.',
    input: JSON.stringify({ summary, ruleIds }),
    max_output_tokens: AI_MAX_TOKENS,
    store: false,
  };
}

export function extractExplanation(value) {
  if (!Array.isArray(value?.output)) return null;
  const texts = [];
  for (const item of value.output) {
    for (const entry of Array.isArray(item?.content) ? item.content : []) {
      if (entry?.type === 'output_text' && typeof entry.text === 'string') {
        texts.push(entry.text);
      }
    }
  }
  const text = texts.join('\n').trim();
  return text ? text.slice(0, 3000) : null;
}
