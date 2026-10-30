import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const BEARER = /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;

export function json(res, code, data) {
  res.status(code);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res.json(data);
}

// Only verified student identities can use package add-on endpoints.
// Unlike protected notes, these endpoints return no account-owned stored records;
// no browser-supplied identity, device flag or role is trusted.
export async function authenticatedStudent(req, res) {
  const authorization = req.headers?.authorization;
  if (typeof authorization !== 'string' || !BEARER.test(authorization)) {
    json(res, 401, { error: 'authentication_required' });
    return null;
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    json(res, 503, { error: 'authentication_unavailable' });
    return null;
  }
  try {
    const supabase = createClient(url, key, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
    const verify = createLoginVerifier({
      config, supabaseSecretKey: key, supabaseClient: supabase,
    });
    const login = await verify(authorization);
    if (!login) {
      json(res, 401, { error: 'authentication_required' });
      return null;
    }
    if (login.kind !== 'student') {
      json(res, 403, { error: 'student_account_required' });
      return null;
    }
    return { supabase, userId: login.userId };
  } catch {
    json(res, 503, { error: 'authentication_unavailable' });
    return null;
  }
}
