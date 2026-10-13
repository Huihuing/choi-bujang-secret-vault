// Temporary, server-owned Stage 8 diagnostics.
// All fields are fixed vocabulary; never log a supplied URL, query, token,
// resource ID, user ID, content, or raw verification exception.
const METHOD = new Set(['GET','POST','PUT','DELETE']);
const REASONS = new Set(['missing','format','issuer','expired','claims','signature','verification','config']);
export function auditNoteEntry(route, request) {
  if (!['/api/notes','/api/notes/:id'].includes(route)) throw new TypeError('invalid_audit_route');
  console.info('aleph_s08_entry', JSON.stringify({
    route,
    method: METHOD.has(request?.method) ? request.method : 'OTHER',
    authHeader: typeof request?.headers?.authorization === 'string' ? 'present' : 'absent',
  }));
}
export function auditNoteAuth(route, login, failureReason) {
  if (!['/api/notes','/api/notes/:id'].includes(route)) throw new TypeError('invalid_audit_route');
  const kind = ['judge','student'].includes(login?.kind) ? login.kind : 'null';
  console.info('aleph_s08_auth', JSON.stringify({
    route,
    kind,
    reason: kind !== 'null' ? 'ok' : REASONS.has(failureReason) ? failureReason : 'verification',
  }));
}
