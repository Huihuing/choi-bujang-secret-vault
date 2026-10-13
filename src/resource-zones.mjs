// The server checks the verified user against persisted resource ownership/privileges.
export const RESOURCE_ZONES = Object.freeze({ notes: 'notes', instructorNotices: 'instructor-notices' });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function exactResourcePath(rawUrl, resource, individual = false) {
  if (typeof rawUrl !== 'string' || !['notes','instructor-notices'].includes(resource)) return null;
  let url;
  try { url = new URL(rawUrl, 'https://resource.local'); } catch { return null; }
  if (url.search || url.hash) return null;
  const prefix = '/api/' + resource;
  if (!individual) return url.pathname === prefix ? prefix : null;
  const id = url.pathname.startsWith(prefix + '/') ? url.pathname.slice(prefix.length + 1) : '';
  return UUID.test(id) ? id.toLowerCase() : null;
}
export function ownsNote(note, verifiedUserId) {
  return typeof verifiedUserId === 'string' && UUID.test(verifiedUserId)
    && note !== null && typeof note === 'object' && typeof note.owner_id === 'string'
    && note.owner_id.toLowerCase() === verifiedUserId.toLowerCase();
}
export async function hasStoredInstructorAccess(supabase, login) {
  if (login?.kind !== 'student' || !UUID.test(login?.userId ?? '')) return false;
  const { data, error } = await supabase.from('instructor_memberships')
    .select('user_id').eq('user_id',login.userId).maybeSingle();
  if (error) throw new Error('instructor_permission_unavailable');
  return Boolean(data && data.user_id?.toLowerCase() === login.userId.toLowerCase());
}
