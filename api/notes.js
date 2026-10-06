import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function sendJson(response, status, body) {
  response.status(status);
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  return response.json(body);
}

function parseBody(request) {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) {
    return request.body;
  }
  if (typeof request.body === 'string') {
    try {
      const parsed = JSON.parse(request.body);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

function cleanText(value, max) {
  return typeof value === 'string' && value.trim() && value.trim().length <= max
    ? value.trim() : null;
}

function hasOnlyKeys(body, allowed) {
  return body && Object.keys(body).every(key => allowed.includes(key));
}

async function context(request, response) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    sendJson(response, 503, { error: 'server_not_configured' });
    return null;
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });

  let verifyLogin;
  try {
    verifyLogin = createLoginVerifier({ config, supabaseSecretKey, supabaseClient: supabase });
  } catch {
    sendJson(response, 503, { error: 'login_verifier_not_configured' });
    return null;
  }

  const login = await verifyLogin(request.headers.authorization);
  if (!login) {
    sendJson(response, 401, { error: 'authentication_required' });
    return null;
  }

  return { supabase, login };
}

export default async function handler(request, response) {
  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return sendJson(response, 405, { error: 'method_not_allowed' });
  }

  const ctx = await context(request, response);
  if (!ctx) return;

  if (request.method === 'GET') {
    const { data, error } = await ctx.supabase
      .from('notes')
      .select('id,title,content,created_at')
      .eq('owner_id', ctx.login.userId)
      .order('created_at', { ascending: true })
      .order('id', { ascending: true });

    if (error) return sendJson(response, 500, { error: 'notes_unavailable' });

    return sendJson(response, 200, {
      notes: (data ?? []).map(note => ({ id: note.id, title: note.title, body: note.content })),
    });
  }

  const body = parseBody(request);
  if (!hasOnlyKeys(body, ['id', 'title', 'body'])) {
    return sendJson(response, 400, { error: 'invalid_note' });
  }

  const title = cleanText(body?.title, 120);
  const noteBody = cleanText(body?.body, 4000);
  const id = body?.id === undefined || body?.id === null || body?.id === ''
    ? randomUUID()
    : (typeof body.id === 'string' && UUID.test(body.id) ? body.id.toLowerCase() : null);

  if (!id || !title || !noteBody) {
    return sendJson(response, 400, { error: 'invalid_note' });
  }

  const { error } = await ctx.supabase
    .from('notes')
    .insert({ id, owner_id: ctx.login.userId, title, content: noteBody });

  if (error) return sendJson(response, 500, { error: 'note_create_failed' });
  return sendJson(response, 201, { id });
}
