import { readFile, writeFile } from 'node:fs/promises';

const rulesPath = new URL('./deny-rules.json', import.meta.url);

export function buildDenyRules(entries, { ttlMinutes = 15, now = Date.now() } = {}) {
  const grouped = new Map();
  const expiresAt = new Date(now + ttlMinutes * 60_000).toISOString();

  for (const entry of entries) {
    if (entry?.decision?.action !== 'block' || !entry?.alert?.sourceIp) continue;
    const sourceIp = entry.alert.sourceIp;
    const current = grouped.get(sourceIp) ?? {
      id: `xdr-brute-force-${sourceIp.replace(/[^a-zA-Z0-9]/g, '-')}`,
      effect: 'deny',
      match: { sourceIp },
      expiresAt,
      evidenceAlertIds: [],
      reason: entry.decision.reason,
    };
    if (!current.evidenceAlertIds.includes(entry.alertId)) current.evidenceAlertIds.push(entry.alertId);
    grouped.set(sourceIp, current);
  }

  return [...grouped.values()].sort((a, b) => a.match.sourceIp.localeCompare(b.match.sourceIp));
}

export async function writeDenyRules(entries, options) {
  const rules = buildDenyRules(entries, options);
  await writeFile(rulesPath, `${JSON.stringify({ rules }, null, 2)}\n`, 'utf8');
  return rules;
}

export async function isDeniedSource(sourceIp, at = Date.now()) {
  let document;
  try {
    document = JSON.parse(await readFile(rulesPath, 'utf8'));
  } catch {
    return false;
  }
  return (document.rules ?? []).some((rule) =>
    rule?.effect === 'deny'
    && rule?.match?.sourceIp === sourceIp
    && Date.parse(rule.expiresAt) > at
  );
}
