import { readFile, writeFile } from 'node:fs/promises';

const moduleName = process.argv[2];

function mitreIds(raw) {
  const mitre = raw?.rule?.mitre;
  if (Array.isArray(mitre)) return mitre;
  if (Array.isArray(mitre?.id)) return mitre.id;
  if (typeof mitre?.id === 'string') return [mitre.id];
  return [];
}

function isNormal(raw, technique) {
  if (raw?.fixture?.classification === 'normal' || raw?.expected === 'normal') return true;
  return !mitreIds(raw).some((id) => typeof id === 'string' && id.startsWith(technique))
    && Number(raw?.rule?.level ?? 0) <= 3;
}

function alertId(raw, index) {
  const value = raw?.id ?? raw?._id ?? raw?.alert_id;
  return typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(value)
    ? value
    : `fixture-${String(index + 1).padStart(3, '0')}`;
}

async function runBruteForce() {
  const [{ parseAlerts }, { decide }, { writeDenyRules }] = await Promise.all([
    import('../xdr/brute-force/read-alerts.mjs'),
    import('../xdr/brute-force/decide.mjs'),
    import('../xdr/brute-force/ztna-bridge.mjs'),
  ]);
  const fixtureUrl = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
  const source = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rawAlerts = Array.isArray(source) ? source : source.alerts;
  if (!Array.isArray(rawAlerts)) throw new TypeError('Fixture must be an array or { alerts: [...] }');
  const extracted = parseAlerts(source);
  if (extracted.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

  const entries = [];
  for (let index = 0; index < rawAlerts.length; index += 1) {
    const output = await decide(rawAlerts[index]);
    entries.push({
      alertId: alertId(rawAlerts[index], index),
      alert: extracted[index],
      decision: output,
      fixtureNormal: isNormal(rawAlerts[index], 'T1110'),
    });
  }
  const counts = { block: 0, alert: 0, record: 0 };
  for (const entry of entries) counts[entry.decision.action] += 1;
  const normalEventBlocks = entries.filter((entry) => entry.fixtureNormal && entry.decision.action === 'block');
  const rules = await writeDenyRules(entries.filter((entry) => !entry.fixtureNormal));
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
  await writeFile(new URL('../xdr/brute-force/result.json', import.meta.url), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`block=${counts.block} alert=${counts.alert} record=${counts.record} normalEventBlocks=${normalEventBlocks.length}`);
  if (normalEventBlocks.length > 0) process.exitCode = 1;
}

async function runWebInjection() {
  const [{ readAlerts }, { decide }, connection] = await Promise.all([
    import('../xdr/web-injection/read-alerts.mjs'),
    import('../xdr/web-injection/decide.mjs'),
    import('../xdr/web-injection/connect.mjs'),
  ]);
  const fixtureUrl = new URL('../xdr/fixtures/web-injection.json', import.meta.url);
  const source = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rawAlerts = source?.alerts;
  if (!Array.isArray(rawAlerts)) throw new TypeError('Fixture must contain alerts');
  const extracted = await readAlerts(fixtureUrl);
  if (extracted.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

  const decisions = [];
  const rules = [];
  const counts = { block: 0, alert: 0, record: 0 };
  let normalEventBlocks = 0;

  for (let index = 0; index < rawAlerts.length; index += 1) {
    const raw = rawAlerts[index];
    const output = await decide(raw);
    decisions.push({
      alertId: alertId(raw, index),
      action: output.action,
      confidence: output.confidence,
      reason: output.reason,
    });
    counts[output.action] += 1;
    if (isNormal(raw, 'T1190') && output.action === 'block') normalEventBlocks += 1;
    const rule = connection.makeRule(raw, output, Date.parse(raw.timestamp));
    if (rule) rules.push(rule);
  }

  await connection.persistRules(rules);

  const logUrl = new URL('../xdr/alerts.log', import.meta.url);
  let existing = '';
  try { existing = await readFile(logUrl, 'utf8'); } catch {}
  const preserved = existing.split(/\r?\n/)
    .filter(Boolean)
    .filter((line) => !line.includes('"module":"web-injection"'));
  const webLines = decisions
    .filter((item) => item.action === 'block' || item.action === 'alert')
    .map((item) => JSON.stringify({
      module: 'web-injection',
      alertId: item.alertId,
      action: item.action,
      confidence: item.confidence,
      pattern: item.reason,
    }));
  const allLines = [...preserved, ...webLines];
  await writeFile(logUrl, allLines.length ? `${allLines.join('\n')}\n` : '', 'utf8');

  const result = {
    schema: 'aleph.xdr.result.v1',
    moduleKey: 'web-injection',
    counts,
    normalEventBlocks,
    rulesWritten: rules.length,
    decisions,
  };
  await writeFile(new URL('../xdr/web-injection/result.json', import.meta.url), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`block=${counts.block} alert=${counts.alert} record=${counts.record} normalEventBlocks=${normalEventBlocks}`);
  if (normalEventBlocks > 0) process.exitCode = 1;
}

if (moduleName === 'brute-force') await runBruteForce();
else if (moduleName === 'web-injection') await runWebInjection();
else {
  console.error('Usage: npm run xdr:run -- <brute-force|web-injection>');
  process.exitCode = 2;
}
