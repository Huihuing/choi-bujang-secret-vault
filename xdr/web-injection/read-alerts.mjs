import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultPath = fileURLToPath(new URL('../fixtures/web-injection.json', import.meta.url));

function safeDescription(value) {
  if (typeof value !== 'string') return null;
  if (/(?:password|passwd|token|secret|비밀번호|암호)\s*[:=]\s*[^\s,;]+|sb_(?:secret|publishable)_|eyJ[A-Za-z0-9_-]+\.|-----BEGIN/i.test(value)) {
    return '[redacted]';
  }
  return value.replace(/[\r\n]/g, ' ').slice(0, 500);
}

function safeAccount(value) {
  if (value == null) return null;
  return typeof value === 'string' && /^[a-zA-Z0-9_.-]{1,48}$/.test(value) ? value : '[redacted]';
}

export function extract(alert) {
  const timestamp = alert?.timestamp ?? alert?.['@timestamp'] ?? null;
  const sourceIp = alert?.data?.srcip ?? alert?.srcip ?? alert?.source?.ip ?? null;
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel);
  return {
    time: typeof timestamp === 'string' && Number.isFinite(Date.parse(timestamp))
      ? new Date(timestamp).toISOString()
      : null,
    sourceIp: typeof sourceIp === 'string' && isIP(sourceIp) ? sourceIp : null,
    account: safeAccount(alert?.data?.dstuser ?? alert?.data?.srcuser ?? alert?.account ?? null),
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: safeDescription(alert?.rule?.description ?? alert?.description ?? null),
  };
}

export function parseAlerts(source) {
  const parsed = typeof source === 'string' ? JSON.parse(source) : source;
  const records = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.alerts) ? parsed.alerts : null;
  if (!records) throw new TypeError('Expected JSON alert array or { alerts: [...] }');
  return records.map(extract);
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
      ? 'Fixture missing: xdr/fixtures/web-injection.json'
      : 'Unable to parse fixture');
    process.exitCode = 1;
  }
}
