import { createClient } from '@supabase/supabase-js';

function sendJson(response, status, body) {
  response.status(status);
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  return response.json(body);
}

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return sendJson(response, 405, { error: 'method_not_allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return sendJson(response, 503, { error: 'server_not_configured' });
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });

  const { data, error } = await supabase
    .from('notes')
    .select('title,content')
    .order('id', { ascending: true });

  if (error) {
    return sendJson(response, 500, { error: 'notes_unavailable' });
  }

  return sendJson(response, 200, { notes: data ?? [] });
}
