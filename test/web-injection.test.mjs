import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide, configureJev } from '../xdr/web-injection/decide.mjs';
import { readAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { createGuard, makeRule } from '../xdr/web-injection/connect.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));

test('web injection fixture extracts and classifies 8/9/9', async () => {
  assert.equal((await readAlerts()).length, fixture.alerts.length);
  const source = await readFile(new URL('../xdr/web-injection/decide.mjs', import.meta.url), 'utf8');
  const isolated = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const output = await isolated.decide(alert);
    assert.deepEqual(output, await decide(alert));
    counts[output.action] += 1;
    if (alert.rule.level >= 10) assert.equal(output.action, 'block');
    else if (alert.rule.level <= 3) assert.equal(output.action, 'record');
    else assert.equal(output.action, 'alert');
  }
  assert.deepEqual(counts, { block: 8, alert: 9, record: 9 });
});

test('encoded traversal blocks only when repeated and ordinary words stay normal', async () => {
  const alert = structuredClone(fixture.alerts[0]);
  alert.rule.description = 'Suspicious request';
  alert.data.url = '/files?p=%252e%252e%252f%252e%252e%252fnotes';
  assert.equal((await decide(alert)).action, 'block');
  alert.data.count = '1';
  assert.equal((await decide(alert)).action, 'alert');
  alert.rule.level = 3;
  alert.rule.mitre = [];
  alert.data.url = '/search?q=select-course';
  assert.equal((await decide(alert)).action, 'record');
});

test('Jev failure and high model score do not block an isolated request', async () => {
  configureJev(async () => { throw new Error('offline'); });
  assert.equal((await decide(fixture.alerts[8])).action, 'alert');
  configureJev(async () => ({ confidence: 0.99 }));
  assert.equal((await decide(fixture.alerts[8])).action, 'alert');
  configureJev(null);
});

test('web injection rules expire and preserve normal baseline requests', async () => {
  const rules = [];
  for (const alert of fixture.alerts) {
    const output = await decide(alert);
    const at = Date.parse(alert.timestamp);
    const rule = makeRule(alert, output, at);
    if (output.action === 'block') {
      assert.ok(rule);
      assert.equal(rule.alertId, alert.id);
      rules.push(rule);
    } else {
      assert.equal(rule, null);
    }
  }

  const baseline = {
    schema: 'aleph.decision.v1',
    requestId: 'test',
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [],
  };
  const guard = createGuard(async () => baseline, async () => rules);
  for (const alert of fixture.alerts) {
    const outcome = await guard(
      { requestId: 'test' },
      { sourceIp: alert.data.srcip, now: Date.parse(alert.timestamp) },
    );
    assert.equal(outcome.decision, alert.rule.level >= 10 ? 'deny' : 'allow');
  }
  const first = fixture.alerts[0];
  assert.deepEqual(
    await guard(
      { requestId: 'test' },
      { sourceIp: first.data.srcip, now: Date.parse(first.timestamp) + 16 * 60_000 },
    ),
    baseline,
  );
});
