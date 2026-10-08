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

const alerts = parseAlerts(source);
if (alerts.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

function alertId(raw, index) {
  const value = raw?.id ?? raw?._id ?? raw?.alert_id;
  return typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(value)
    ? value
    : `fixture-${String(index + 1).padStart(3, '0')}`;
}

function isFixtureNormal(raw) {
  return raw?.fixture?.classification === 'normal' || raw?.expected === 'normal';
}

function contextFor(index) {
  const alert = alerts[index];
  const at = Date.parse(alert.time ?? '');
  if (!alert.sourceIp || !Number.isFinite(at)) {
    return { sameSourceFailures2m: 0, distinctAccounts5m: 0, upstreamPasswordSpray: false };
  }

  const sameSource2m = alerts.filter((candidate) => {
    const candidateAt = Date.parse(candidate.time ?? '');
    return candidate.sourceIp === alert.sourceIp
      && Number.isFinite(candidateAt)
      && Math.abs(candidateAt - at) <= 120_000;
  });

  const sameSource5m = alerts.filter((candidate) => {
    const candidateAt = Date.parse(candidate.time ?? '');
    return candidate.sourceIp === alert.sourceIp
      && Number.isFinite(candidateAt)
      && Math.abs(candidateAt - at) <= 300_000;
  });

  const distinctAccounts = new Set(
    sameSource5m.map((candidate) => candidate.account).filter((value) => value && value !== '[redacted]')
  ).size;

  const raw = rawAlerts[index];
  const groups = Array.isArray(raw?.rule?.groups) ? raw.rule.groups : [];
  const upstreamPasswordSpray = groups.some((value) => /password[-_ ]?spray/i.test(String(value)))
    || /password[-_ ]?spray/i.test(String(raw?.rule?.description ?? ''));

  return {
    sameSourceFailures2m: sameSource2m.length,
    distinctAccounts5m: distinctAccounts,
    upstreamPasswordSpray,
  };
}

const entries = [];
for (let index = 0; index < alerts.length; index += 1) {
  const alert = alerts[index];
  const decision = await decide({ ...alert, context: contextFor(index) });
  entries.push({
    alertId: alertId(rawAlerts[index], index),
    alert,
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

let existing = '';
try { existing = await readFile(logUrl, 'utf8'); } catch {}
const merged = [...new Set([...existing.split(/\r?\n/).filter(Boolean), ...noteworthy])];
await writeFile(logUrl, merged.length ? `${merged.join('\n')}\n` : '', 'utf8');

const evaluatedThrough = alerts
  .map((alert) => Date.parse(alert.time ?? ''))
  .filter(Number.isFinite)
  .sort((a, b) => b - a)[0];

const result = {
  module: 'brute-force',
  fixture: 'xdr/fixtures/brute-force.json',
  evaluatedThrough: Number.isFinite(evaluatedThrough) ? new Date(evaluatedThrough).toISOString() : null,
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
