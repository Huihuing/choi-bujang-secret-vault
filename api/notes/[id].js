import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function sendJson(response, status, body) {
  response.status(status);
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  return response.json(body);
}

function parseBody(request) {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) return request.body;
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

function requestId(request) {
  const pathname = new URL(request.url, 'https://local.invalid').pathname;
  const id = decodeURIComponent(pathname.split('/').filter(Boolean).at(-1) ?? '');
  return UUID.test(id) ? id.toLowerCase() : null;
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

async function loadNote(supabase, id) {
  const { data, error } = await supabase
    .from('notes')
    .select('id,owner_id,title,content')
    .eq('id', id)
    .maybeSingle();

  return { data, error };
}

function denyOtherOwner(response) {
  return sendJson(response, 403, { error: 'note_forbidden' });
}

export default async function handler(request, response) {
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return sendJson(response, 405, { error: 'method_not_allowed' });
  }

  const id = requestId(request);
  if (!id) return sendJson(response, 400, { error: 'invalid_note_id' });

  const ctx = await context(request, response);
  if (!ctx) return;

  const current = await loadNote(ctx.supabase, id);
  if (current.error) return sendJson(response, 500, { error: 'notes_unavailable' });
  if (!current.data) return sendJson(response, 404, { error: 'note_not_found' });
  if (current.data.owner_id !== ctx.login.userId) return denyOtherOwner(response);

  if (request.method === 'GET') {
    return sendJson(response, 200, {
      id: current.data.id,
      title: current.data.title,
      body: current.data.content,
    });
  }

  if (request.method === 'PUT') {
    const body = parseBody(request);
    if (!body || Object.keys(body).sort().join(',') !== 'body,title') {
      return sendJson(response, 400, { error: 'invalid_note' });
    }

    const title = cleanText(body.title, 120);
    const noteBody = cleanText(body.body, 4000);
    if (!title || !noteBody) return sendJson(response, 400, { error: 'invalid_note' });

    const { data, error } = await ctx.supabase
      .from('notes')
      .update({ title, content: noteBody })
      .eq('id', id)
      .eq('owner_id', ctx.login.userId)
      .select('id,owner_id,title,content')
      .maybeSingle();

    if (error) return sendJson(response, 500, { error: 'note_update_failed' });
    if (!data) return sendJson(response, 403, { error: 'note_forbidden' });
    if (data.owner_id !== ctx.login.userId) return denyOtherOwner(response);

    return sendJson(response, 200, { id: data.id, title: data.title, body: data.content });
  }

  const { data, error } = await ctx.supabase
    .from('notes')
    .delete()
    .eq('id', id)
    .eq('owner_id', ctx.login.userId)
    .select('id,owner_id')
    .maybeSingle();

  if (error) return sendJson(response, 500, { error: 'note_delete_failed' });
  if (!data) return sendJson(response, 403, { error: 'note_forbidden' });
  if (data.owner_id !== ctx.login.userId) return denyOtherOwner(response);

  return sendJson(response, 200, { id: data.id });
}
