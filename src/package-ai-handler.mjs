import { authenticatedStudent, json } from './package-auth.mjs';
import {
  AI_PROVIDER_URL, consumeQuota, explanationPayload,
  extractExplanation, parseExplanation,
} from './package-ai.mjs';

// Dependencies can be replaced in isolated tests. Live routes always use
// the verified student identity, server-only key, and DB-backed quota.
export function createAiHandler({
  authenticate = authenticatedStudent,
  quotaCheck = consumeQuota,
  fetcher = globalThis.fetch,
  keyProvider = () => process.env.OPENAI_API_KEY,
} = {}) {
  return async function handler(req, res) {
    const ctx = await authenticate(req, res);
    if (!ctx) return;
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return json(res, 405, { error: 'method_not_allowed' });
    }
    const body = parseExplanation(req.body);
    if (!body) return json(res, 400, { error: 'invalid_explanation_request' });
    const key = keyProvider();
    // No configured server credential = no external paid request.
    if (typeof key !== 'string' || !key.trim()) {
      return json(res, 503, { error: 'ai_provider_not_configured' });
    }
    const quota = await quotaCheck(ctx.supabase, ctx.userId);
    if (quota.state === 'unavailable') {
      return json(res, 503, { error: 'ai_quota_unavailable' });
    }
    if (quota.state === 'limited') {
      res.setHeader('Retry-After', String(quota.retryAfterSeconds));
      return json(res, 429, { error: 'ai_quota_exceeded' });
    }
    try {
      const upstream = await fetcher(AI_PROVIDER_URL, {
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
  };
}

export default createAiHandler();
