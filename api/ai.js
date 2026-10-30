import { authenticatedStudent, json } from '../src/package-auth.mjs';
import {
  AI_PROVIDER_URL, consumeQuota, explanationPayload,
  extractExplanation, parseExplanation,
} from '../src/package-ai.mjs';

export default async function handler(req, res) {
  const ctx = await authenticatedStudent(req, res);
  if (!ctx) return;
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return json(res, 405, { error: 'method_not_allowed' });
  }
  const body = parseExplanation(req.body);
  if (!body) return json(res, 400, { error: 'invalid_explanation_request' });
  const key = process.env.OPENAI_API_KEY;
  // Disabled rather than making uncontrolled provider requests without a key.
  if (!key) return json(res, 503, { error: 'ai_provider_not_configured' });
  const quota = await consumeQuota(ctx.supabase, ctx.userId);
  if (quota.state === 'unavailable') {
    return json(res, 503, { error: 'ai_quota_unavailable' });
  }
  if (quota.state === 'limited') {
    res.setHeader('Retry-After', String(quota.retryAfterSeconds));
    return json(res, 429, { error: 'ai_quota_exceeded' });
  }
  try {
    const upstream = await fetch(AI_PROVIDER_URL, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
      headers: {
        Authorization: 'Bearer ' + key,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(explanationPayload(body)),
    });
    if (!upstream.ok) return json(res, 502, { error: 'ai_provider_unavailable' });
    const text = extractExplanation(await upstream.json());
    if (!text) return json(res, 502, { error: 'ai_response_unavailable' });
    return json(res, 200, {
      schema: 'watchdogs.ai-explanation.v1',
      source: 'server_proxy',
      kind: 'advisory_only',
      explanation: text,
    });
  } catch {
    return json(res, 502, { error: 'ai_provider_unavailable' });
  }
}
