// Wazuh fixture reader. Never serialize entire events or arbitrary fields.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const defaultPath = fileURLToPath(new URL('../fixtures/brute-force.json', import.meta.url));

function safeText(value, max = 120) {
  if (typeof value !== 'string') return null;
  // Reject credentials, URLs, long opaque tokens, and control characters.
  if (/password|passwd|secret|token|api.?key|authorization|bearer|cookie|credential|https?:\/\//i.test(value)) return '[redacted]';
  if (/[\x00-\x1f\x7f]/.test(value) || value.length > max) return '[redacted]';
  return value;
}
function safeAccount(value) {
  if (typeof value !== 'string') return null;
  // Account IDs may be personal data. Do not disclose email or free-form identity.
  return /^[a-zA-Z0-9_.-]{1,48}$/.test(value) ? value : '[redacted]';
}
function normalize(event, index) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError(`Invalid alert at index ${index}`);
  const timestamp = event.timestamp ?? event['@timestamp'] ?? null;
  const rawIp = event.data?.srcip ?? event.srcip ?? event.source?.ip ?? null;
  const ip = typeof rawIp === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(rawIp) ? rawIp : null;
  const rawLevel = event.rule?.level;
  return {
    time: typeof timestamp === 'string' && !Number.isNaN(Date.parse(timestamp)) ? new Date(timestamp).toISOString() : null,
    sourceIp: ip,
    account: safeAccount(event.data?.dstuser ?? event.data?.srcuser ?? event.account ?? null),
    ruleLevel: Number.isInteger(Number(rawLevel)) && Number(rawLevel) >= 0 && Number(rawLevel) <= 16 ? Number(rawLevel) : null,
    description: safeText(event.rule?.description ?? event.description ?? null),
  };
}
export function parseAlerts(source) {
  const parsed = typeof source === 'string' ? JSON.parse(source) : source;
  const records = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.alerts) ? parsed.alerts : null;
  if (!records) throw new TypeError('Expected JSON alert array or { alerts: [...] }');
  return records.map(normalize);
}
export async function readAlerts(path = defaultPath) {
  return parseAlerts(await readFile(path, 'utf8'));
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fileURLToPath(new URL('file://' + process.argv[1]))) {
  try {
    const alerts = await readAlerts(process.argv[2] ?? defaultPath);
    for (const alert of alerts) console.log(JSON.stringify(alert));
    console.error(`alerts=${alerts.length} extracted=${alerts.length}`);
  } catch (error) {
    console.error(error.code === 'ENOENT' ? 'Fixture missing: xdr/fixtures/brute-force.json' : 'Unable to parse fixture');
    process.exitCode = 1;
  }
}
