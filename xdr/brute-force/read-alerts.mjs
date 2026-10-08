// Wazuh fixture reader. Only the five fields required by the exercise are exposed.
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultPath = fileURLToPath(new URL('../fixtures/brute-force.json', import.meta.url));

function safeText(value, max = 180) {
  if (typeof value !== 'string') return null;
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) return '[redacted]';
  const redacted = value
    .replace(/\b(password|passwd|secret|token|api[-_ ]?key|authorization|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1=[redacted]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]');
  return redacted.length <= max ? redacted : `${redacted.slice(0, max - 1)}…`;
}

function safeAccount(value) {
  if (typeof value !== 'string') return null;
  return /^[a-zA-Z0-9_.-]{1,48}$/.test(value) ? value : '[redacted]';
}

function normalize(event, index) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new TypeError(`Invalid alert at index ${index}`);
  }
  const timestamp = event.timestamp ?? event['@timestamp'] ?? null;
  const rawIp = event.data?.srcip ?? event.srcip ?? event.source?.ip ?? null;
  const rawLevel = Number(event.rule?.level ?? event.ruleLevel);
  return {
    time: typeof timestamp === 'string' && !Number.isNaN(Date.parse(timestamp))
      ? new Date(timestamp).toISOString()
      : null,
    sourceIp: typeof rawIp === 'string' && isIP(rawIp) ? rawIp : null,
    account: safeAccount(event.data?.dstuser ?? event.data?.srcuser ?? event.account ?? null),
    ruleLevel: Number.isInteger(rawLevel) && rawLevel >= 0 && rawLevel <= 16 ? rawLevel : null,
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const alerts = await readAlerts(process.argv[2] ?? defaultPath);
    for (const alert of alerts) console.log(JSON.stringify(alert));
    console.error(`alerts=${alerts.length} extracted=${alerts.length}`);
  } catch (error) {
    console.error(error?.code === 'ENOENT'
      ? 'Fixture missing: xdr/fixtures/brute-force.json'
      : 'Unable to parse fixture');
    process.exitCode = 1;
  }
}
