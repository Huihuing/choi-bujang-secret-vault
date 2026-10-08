import { readFile, writeFile } from 'node:fs/promises';
import { parseAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { writeDenyRules } from '../xdr/brute-force/ztna-bridge.mjs';

const moduleName = process.argv[2];
if (moduleName !== 'brute-force') {
  console.error('Usage: npm run xdr:run -- brute-force');
  process.exit(2);
}

const fixtureUrl = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
const resultUrl = new URL('../xdr/brute-force/result.json', import.meta.url);
const logUrl = new URL('../xdr/alerts.log', import.meta.url);

const source = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const rawAlerts = Array.isArray(source) ? source : source.alerts;
if (!Array.isArray(rawAlerts)) throw new TypeError('Fixture must be an array or { alerts: [...] }');

const extracted = parseAlerts(source);
if (extracted.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

function alertId(raw, index) {
  const value = raw?.id ?? raw?._id ?? raw?.alert_id;
  return typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(value)
    ? value
    : `fixture-${String(index + 1).padStart(3, '0')}`;
}

function mitreIds(raw) {
  const mitre = raw?.rule?.mitre;
  if (Array.isArray(mitre)) return mitre;
  if (Array.isArray(mitre?.id)) return mitre.id;
  if (typeof mitre?.id === 'string') return [mitre.id];
  return [];
}

function isFixtureNormal(raw) {
  if (raw?.fixture?.classification === 'normal' || raw?.expected === 'normal') return true;
  return mitreIds(raw).length === 0 && Number(raw?.rule?.level ?? 0) <= 3;
}

const entries = [];
for (let index = 0; index < rawAlerts.length; index += 1) {
  const decision = await decide(rawAlerts[index]);
  entries.push({
    alertId: alertId(rawAlerts[index], index),
    alert: extracted[index],
    decision,
    fixtureNormal: isFixtureNormal(rawAlerts[index]),
  });
}

const counts = { block: 0, alert: 0, record: 0 };
for (const entry of entries) counts[entry.decision.action] += 1;

const normalEventBlocks = entries.filter((entry) => entry.fixtureNormal && entry.decision.action === 'block');
const rules = await writeDenyRules(entries.filter((entry) => !entry.fixtureNormal));

const noteworthy = entries
  .filter((entry) => entry.decision.action === 'block' || entry.decision.action === 'alert')
  .map((entry) =>
    `${entry.alert.time} action=${entry.decision.action} source=${entry.alert.sourceIp ?? 'unknown'} confidence=${entry.decision.confidence.toFixed(2)} reason=${entry.decision.reason} alert=${entry.alertId}`
  );

await writeFile(logUrl, noteworthy.length ? `${noteworthy.join('\n')}\n` : '', 'utf8');

const result = {
  schema: 'aleph.xdr.result.v1',
  moduleKey: 'brute-force',
  counts,
  normalEventBlocks: normalEventBlocks.length,
  rulesWritten: rules.length,
  decisions: entries.map((entry) => ({
    alertId: entry.alertId,
    action: entry.decision.action,
    confidence: entry.decision.confidence,
    reason: entry.decision.reason,
  })),
};

await writeFile(resultUrl, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
console.log(`block=${counts.block} alert=${counts.alert} record=${counts.record} normalEventBlocks=${normalEventBlocks.length}`);
if (normalEventBlocks.length > 0) process.exitCode = 1;
