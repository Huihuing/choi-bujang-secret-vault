import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { loadNote } from '../api/notes/[id].js';

const now = Math.floor(Date.now()/1000);
const run = '22222222-2222-4222-8222-222222222222';
const sub = '11111111-1111-4111-8111-111111111111';
const config = {
  judgeIssuer:'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl:'https://test-owner-jwt.vercel.app/',
  identityProvider:{
    issuer:'https://safeexample.supabase.co/auth/v1',
    jwksUrl:'https://safeexample.supabase.co/auth/v1/.well-known/jwks.json',
    audience:'authenticated',
  },
};
const {publicKey, privateKey} = await generateKeyPair('ES256');
const jwk = {...await exportJWK(publicKey), kid:'local-judge-identity-test', alg:'ES256', use:'sig'};
const auth = {auth:{async getClaims(){return {data:{claims:null},error:new Error('no student token')}}}};
const verify = createLoginVerifier({
  config, judgeKeySet:createLocalJWKSet({keys:[jwk]}), supabaseClient:auth,
});
async function token(identity, runId=run, subject=sub){
 return new SignJWT({aleph_role:'judge', aleph_identity:identity, aleph_run:runId})
  .setProtectedHeader({alg:'ES256',kid:jwk.kid})
  .setIssuer(config.judgeIssuer).setAudience('test-owner-jwt.vercel.app')
  .setSubject(subject).setIssuedAt(now).setExpirationTime(now+600).sign(privateKey);
}
const note='33333333-3333-4333-8333-333333333333';

test('A/B judge identity separation even if both signed tokens share one sub',async()=>{
 const a=await verify('Bearer '+await token('a'));
 const b=await verify('Bearer '+await token('b'));
 assert.equal(a.kind,'judge');
 assert.equal(b.kind,'judge');
 assert.notEqual(a.userId,b.userId);
 assert.match(a.userId,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
 assert.equal((await verify('Bearer '+await token('a'))).userId,a.userId);
 assert.notEqual((await verify('Bearer '+await token('a','44444444-4444-4444-8444-444444444444'))).userId,a.userId);
 assert.notEqual((await verify('Bearer '+await token('a',run,'55555555-5555-4555-8555-555555555555'))).userId,a.userId);
});

test('judge B never reads A note; A can still read own note',async()=>{
 const a=await verify('Bearer '+await token('a'));
 const b=await verify('Bearer '+await token('b'));
 const row={id:note,owner_id:a.userId,title:'sample',content:'sample'};
 let filteredOwner;
 function db(){
  let id, owner;
  return {from(table){
    assert.equal(table,'notes');
    return {
      select(){return this},
      eq(column,value){if(column==='id')id=value;if(column==='owner_id')owner=value;return this;},
      async maybeSingle(){filteredOwner=owner;return {data:id===row.id && owner===row.owner_id?row:null,error:null};},
    };
  }};
 }
 const own=await loadNote(db(),note,a.userId);
 assert.equal(own.data.id,note);
 const foreign=await loadNote(db(),note,b.userId);
 assert.equal(foreign.data,null);
 assert.equal(filteredOwner,b.userId);
});

test('normal Supabase student principal still uses the verified sub unchanged',async()=>{
 const studentSub='66666666-6666-4666-8666-666666666666';
 const studentToken = await new SignJWT({role:'authenticated'})
  .setProtectedHeader({alg:'ES256',kid:jwk.kid})
  .setIssuer(config.identityProvider.issuer)
  .setAudience('authenticated').setSubject(studentSub)
  .setIssuedAt(now).setExpirationTime(now+600).sign(privateKey);
 const studentVerifier = createLoginVerifier({
  config, judgeKeySet:createLocalJWKSet({keys:[jwk]}),
  supabaseClient:{auth:{async getClaims(){return {data:{claims:{
    iss:config.identityProvider.issuer,aud:'authenticated',role:'authenticated',
    sub:studentSub,exp:now+600,
  }},error:null};}}},
 });
 const student=await studentVerifier('Bearer '+studentToken);
 assert.equal(student.kind,'student');
 assert.equal(student.userId,studentSub);
});
