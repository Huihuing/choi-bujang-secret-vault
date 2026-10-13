import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';

const baseline = () => ({
  requestId: 'fictional-req', deviceRegistered: true,
  subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
  recentEvents: [], stepUp: { verified: false, authAgeSeconds: null },
});
const risky = () => ({ ...baseline(),
  signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
});

function fiveKeys(res) { assert.deepEqual(Object.keys(res).sort(), ['decision','reasonCode','requestId','ruleIds','schema']); }

test('rule IDs only implemented rules', () => assert.deepEqual(RULE_IDS, ['device_registered', 'step_up_required', 'resource_zone', 'instructor_write_protected']));
test('registered device normal request allowed', async () => {const r=await decide(baseline()); fiveKeys(r); assert.equal(r.decision,'allow');});
test('unregistered/missing device denied regardless of risk or reauthentication', async () => {
  for (const value of [false, undefined, null, 'true', 1]) {const req={...risky(), deviceRegistered:value,stepUp:{verified:true,authAgeSeconds:0}};const r=await decide(req);fiveKeys(r);assert.equal(r.decision,'deny');assert.equal(r.reasonCode,'device_not_registered');}
});
test('verified synthetic multi-signal risk requires step_up', async () => {const r=await decide(risky());fiveKeys(r);assert.equal(r.decision,'step_up');assert.equal(r.reasonCode,'step_up_required');});
test('fresh engine verification on new request allows previously risky event', async () => {const req={...risky(), requestId:'req-after',stepUp:{verified:true,authAgeSeconds:60}};const r=await decide(req);assert.equal(r.requestId,'req-after');assert.equal(r.decision,'allow');});
test('stale, malformed or absent authAgeSeconds cannot bypass step_up', async () => {
  for (const stepUp of [undefined,{verified:true,authAgeSeconds:null},{verified:true,authAgeSeconds:'60'},{verified:true,authAgeSeconds:121},{verified:false,authAgeSeconds:0}]) {const r=await decide({...risky(),stepUp});assert.equal(r.decision,'step_up');}
});
test('region alone never causes risk', async () => {assert.equal((await decide({...baseline(),signals:{...baseline().signals,region:'foreign'}})).decision,'allow');});
test('missing or unknown signal provenance not promoted to verified risk', async () => {
  for (const signals of [undefined,{}, {source:'none',network:'unusual',hour:3},{network:'unusual',hour:3},{source:'client_header',network:'unusual',hour:3}]) {const r=await decide({...risky(),path:'/notes/11111111-1111-4111-8111-111111111111',signals});assert.equal(r.decision,'allow');}
});
test('client-provided headers never override engine verified signals', async () => {
  assert.equal((await decide({...baseline(),headers:{'x-network':'unusual','x-location':'foreign','x-hour':'3'},recentEvents:risky().recentEvents})).decision,'allow');
});
test('incomplete composite signals do not imply verified risk', async () => {
  for (const req of [{...risky(),recentEvents:[]},{...risky(),signals:{...risky().signals,network:'usual'}},{...risky(),signals:{...risky().signals,hour:14}}]) assert.equal((await decide(req)).decision,'allow');
});
