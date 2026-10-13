import test from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detect.mjs';

const start = Date.UTC(2026, 9, 1);
const events = (count, { subject = 'a_pseudonym', interval = 2000,
  at = start, method = 'GET' } = {}) => Array.from({ length: count }, (_, i) => ({
  at: new Date(at + interval * i).toISOString(),
  method, identity: { sub: subject },
}));
const observe = { action: 'observe' };

test('empty and normal reads do not revoke a verified identity', () => {
 assert.deepEqual(detect([]), observe);
 assert.deepEqual(detect(events(30)), observe);
 assert.deepEqual(detect(events(120)), observe);
 assert.deepEqual(detect(events(121,{interval:6001})), observe);
});
test('121st GET within 10-minute inclusive sliding window proposes revocation', () => {
 const burst=detect(events(121));
 assert.deepEqual(burst,{action:'propose_revocation',reasonCode:'burst_read',subject:'a_pseudonym'});
 assert.deepEqual(detect(events(121,{interval:5000})),burst); // 10-minute boundary
});
test('different identities do not share rate limits', () => {
 assert.deepEqual(detect([...events(100),...events(100,{subject:'b_pseudonym'})]),observe);
 assert.deepEqual(detect([...events(120),...events(121,{subject:'b_pseudonym'})]),
   {action:'propose_revocation',reasonCode:'burst_read',subject:'b_pseudonym'});
});
test('mixed methods, invalid timestamps and malformed pseudonyms cannot count as GET', () => {
 const mixed=[...events(120),...events(200,{method:'PUT'})];
 mixed.push(
  {at:'not a timestamp',method:'GET',identity:{sub:'a_pseudonym'}},
  {at:new Date(start).toISOString(),method:'GET',identity:{sub:' a_pseudonym '}},
  {at:new Date(start).toISOString(),method:'GET',identity:null},
  null, {}, {method:'GET',identity:{sub:'a_pseudonym'}},
 );
 assert.deepEqual(detect(mixed),observe);
});
test('out of order events and unrelated legitimate traffic are handled', () => {
 const original=events(121);
 assert.deepEqual(detect([...original].reverse()),
  {action:'propose_revocation',reasonCode:'burst_read',subject:'a_pseudonym'});
 assert.deepEqual(detect([...events(120),...events(1,{at:start+12*60*1000})]),observe);
});
test('do not read or emit uncontracted device, token, body or personal names', () => {
 const input=events(121).map(e=>({...e,secret:'SENSITIVE_VALUE',
  deviceId:'SHOULD_NOT_BE_USED',network:'unusual',token:'SECRET_TOKEN',
  identity:{...e.identity,realName:'SENSITIVE_NAME'}}));
 const result=detect(input);
 assert.deepEqual(result,{action:'propose_revocation',reasonCode:'burst_read',subject:'a_pseudonym'});
 const serial=JSON.stringify(result);
 for(const value of ['SENSITIVE_VALUE','SHOULD_NOT_BE_USED','SECRET_TOKEN','SENSITIVE_NAME'])
   assert.ok(!serial.includes(value));
});
test('invalid top-level input fails closed, never logs or mutates data', () => {
 assert.throws(()=>detect(null),{name:'TypeError',message:'invalid_detection_events'});
 const input=events(121);
 const before=JSON.stringify(input);
 const log=console.log;
 try {
  console.log=()=>{throw new Error('no debug logging');};
  assert.equal(detect(input).action,'propose_revocation');
 } finally {console.log=log;}
 assert.equal(JSON.stringify(input),before);
});
