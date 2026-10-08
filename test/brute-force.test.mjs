import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide, configureJev } from '../xdr/brute-force/decide.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));

test('canonical fixture separates clear, ambiguous, and normal events', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) counts[(await decide(alert)).action] += 1;
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('high severity correlated T1110 does not depend on one description phrase', async () => {
  const alert = structuredClone(fixture.alerts[0]);
  alert.rule.description = 'Repeated authentication failures detected';
  alert.rule.mitre = { id: ['T1110.001'] };
  alert.data.count = '25';
  assert.equal((await decide(alert)).action, 'block');
  alert.data.count = '4';
  assert.equal((await decide(alert)).action, 'alert');
});

test('decide entry is standalone and Jev failure stays alert', async () => {
  const code = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  const entry = await import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'));
  assert.equal((await entry.decide(fixture.alerts[0])).action, 'block');
  entry.configureJev(async () => { throw new Error('offline'); });
  assert.equal((await entry.decide(fixture.alerts[10])).action, 'alert');
  configureJev(null);
});
