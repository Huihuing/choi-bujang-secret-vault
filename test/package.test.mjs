import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import aiHandler from '../api/ai.js';
import threatHandler from '../api/threat-intel.js';
import {
  consumeQuota, explanationPayload, extractExplanation, parseExplanation,
} from '../src/package-ai.mjs';
import { KEV_URL, NVD_URL, lookupThreatIntel, validCve } from '../src/package-threat-intel.mjs';
import { RULE_IDS } from '../src/decider.mjs';

function response() {
  return {
    code: 200, headers: {}, body: null,
    status(value) { this.code = value; return this; },
    setHeader(key, value) { this.headers[key] = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

test('unauthenticated package endpoints fail closed even without server secrets', async () => {
  const aiRes = response();
  await aiHandler({ method: 'POST', headers: {}, body: { summary: 'blocked login', ruleIds: [] } }, aiRes);
  assert.equal(aiRes.code, 401);
  assert.equal(aiRes.body.error, 'authentication_required');
  assert.equal(aiRes.headers['Cache-Control'], 'no-store');
  const tiRes = response();
  await threatHandler({ method: 'GET', headers: {}, query: { cve: 'CVE-2021-44228' } }, tiRes);
  assert.equal(tiRes.code, 401);
  assert.equal(tiRes.body.error, 'authentication_required');
});

test('AI input is bounded, and provider choice/output budget are server-owned', () => {
  const body = { summary: 'Multiple failed login attempts were observed.', ruleIds: ['brute_force_01'] };
  assert.deepEqual(parseExplanation(body), body);
  assert.equal(parseExplanation({ summary: 'short' }), null);
  assert.equal(parseExplanation({ summary: 'x'.repeat(1201) }), null);
  assert.equal(parseExplanation({ ...body, url: 'http://localhost' }), null);
  assert.equal(parseExplanation({ ...body, ruleIds: ['../etc/passwd'] }), null);
  const payload = explanationPayload(body);
  assert.equal(payload.store, false);
  assert.equal(payload.max_output_tokens, 256);
  assert.equal(payload.model, 'gpt-4.1-mini');
  assert.equal(payload.input, JSON.stringify(body));
  assert.equal(extractExplanation({ output: [{ content: [{ type: 'output_text', text: 'Evidence unknown.' }] }] }), 'Evidence unknown.');
  assert.equal(extractExplanation({ output: [] }), null);
});

test('quota checks use a database RPC and reject errors instead of a process-local fallback', async () => {
  const calls = [];
  const db = { rpc: async (name, args) => {
    calls.push([name, args]);
    return { data: { allowed: true }, error: null };
  } };
  assert.deepEqual(await consumeQuota(db, 'verified-student'), { state: 'allowed' });
  assert.deepEqual(calls, [['package_ai_consume', { p_owner_id: 'verified-student' }]]);
  assert.equal((await consumeQuota({ rpc: async () => ({ error: 'offline' }) }, 'x')).state, 'unavailable');
  assert.deepEqual(await consumeQuota({ rpc: async () => ({
    data: { allowed: false, retryAfterSeconds: 30 },
  }) }, 'x'), { state: 'limited', retryAfterSeconds: 30 });
});

test('NVD and KEV data show individual retrieval time and known exploitation only if fetched', async () => {
  const called = [];
  const fakeFetch = async (url) => {
    called.push(url);
    return { ok: true, json: async () => url.startsWith(NVD_URL)
      ? { vulnerabilities: [{ cve: { id: 'CVE-2021-44228', published: '2021-12-10T00:00:00Z',
        lastModified: '2025-01-01T00:00:00Z', descriptions: [{ lang: 'en', value: 'Example CVE' }] } }] }
      : { catalogVersion: 'v1', dateReleased: '2026-10-01', vulnerabilities: [{
        cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', requiredAction: 'Apply fixes',
      }] } };
  };
  const result = await lookupThreatIntel('CVE-2021-44228', {
    fetcher: fakeFetch, now: () => new Date('2026-10-30T01:02:03.000Z'),
  });
  assert.equal(result.state, 'ok');
  assert.equal(result.sources.nvd.fetchedAt, '2026-10-30T01:02:03.000Z');
  assert.equal(result.sources.cisaKev.fetchedAt, '2026-10-30T01:02:03.000Z');
  assert.equal(result.sources.cisaKev.knownExploited, true);
  assert.equal(result.sources.nvd.found, true);
  assert.equal(called.length, 2);
  assert.ok(called[0].startsWith(NVD_URL));
  assert.equal(called[1], KEV_URL);
});

test('a failed upstream cannot be reported as safe or not exploited', async () => {
  const result = await lookupThreatIntel('CVE-2021-44228', {
    fetcher: async url => url.startsWith(NVD_URL)
      ? { ok: true, json: async () => ({ vulnerabilities: [] }) }
      : { ok: false, status: 503 },
    now: () => new Date('2026-10-30T00:00:00Z'),
  });
  assert.equal(result.state, 'partial');
  assert.equal(result.sources.nvd.found, false);
  assert.equal(result.sources.cisaKev.available, false);
  assert.equal(result.sources.cisaKev.knownExploited, null);
  assert.equal(result.sources.cisaKev.fetchedAt, null);
});

test('reject arbitrary URLs, malformed CVEs and unbounded parameters', () => {
  for (const id of ['https://evil.example', '../x', 'CVE-2021-1', 'cve-2021-44228', 'CVE-2021-44228?x=1']) {
    assert.equal(validCve(id), false);
  }
  assert.equal(validCve('CVE-2021-44228'), true);
});

test('package documents and server-side access decision files exist', async () => {
  for (const file of ['README.md', 'SELF-CHECK.md', 'ARCHITECTURE.md',
    'ARCHITECTURE.svg', 'RULES.md', 'THREAT-INTEL.md', 'SECURITY.md']) {
    const contents = await readFile(new URL('../package/' + file, import.meta.url), 'utf8');
    assert.ok(contents.length > 200, file);
  }
  assert.deepEqual(RULE_IDS, [
    'device_registered', 'step_up_required', 'resource_zone', 'instructor_write_protected',
  ]);
  const sql = await readFile(new URL('../db/package-ai-quota.sql', import.meta.url), 'utf8');
  assert.ok(sql.includes('pg_advisory_xact_lock'));
  assert.ok(sql.includes('service_role'));
  assert.ok(sql.includes('REVOKE ALL ON FUNCTION'));
});

test('only the two intended top-level package API functions were added', async () => {
  const entries = await readdir(new URL('../api/', import.meta.url), { withFileTypes: true });
  const files = entries.filter(e => e.isFile() && e.name.endsWith('.js')).map(e => e.name).sort();
  const original = [
    'app-request.js', 'device.js', 'instructor-notices.js', 'notes.js',
    'public-config.js', 'recovery-policy.js', 'restore.js',
    'war-room-check.js', 'war-room-summary.js', 'war-room.js',
  ];
  assert.deepEqual(files, [...original, 'ai.js', 'threat-intel.js'].sort());
});


test('Hobby compact routing keeps both authenticated endpoints on the existing function', async () => {
  const { default: dispatcher } = await import('../api/war-room-summary.js');
  for (const path of ['ai', 'threat-intel']) {
    const res = response();
    await dispatcher({ method: 'GET', query: { __package_route: path }, headers: {} }, res);
    assert.equal(res.code, 401, path);
    assert.equal(res.body.error, 'authentication_required');
  }
  const vercel = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  assert.equal(vercel.rewrites.length, 2);
  assert.ok(vercel.rewrites.every(entry =>
    entry.destination.startsWith('/api/war-room-summary?__package_route=')));
  const build = await readFile(new URL('../scripts/build-public.mjs', import.meta.url), 'utf8');
  assert.ok(build.includes("process.env.PACKAGE_HOBBY_COMPACT === '1'"));
  assert.ok(build.includes('PACKAGE_COMPACT_WRAPPER_MISMATCH'));
});
