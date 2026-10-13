import test from 'node:test';
import assert from 'node:assert/strict';
import {auditNoteEntry,auditNoteAuth} from '../src/stage8-audit.mjs';
import {createLoginVerifier} from '../src/verify-login.mjs';
import {generateKeyPair,exportJWK,createLocalJWKSet,SignJWT} from 'jose';

const config={
  judgeIssuer:'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl:'https://test-auth-audit.vercel.app/',
  identityProvider:{
    issuer:'https://safeexample.supabase.co/auth/v1',
    audience:'authenticated',
    jwksUrl:'https://safeexample.supabase.co/auth/v1/.well-known/jwks.json',
  },
};
const {publicKey,privateKey}=await generateKeyPair('ES256');
const jwk={...await exportJWK(publicKey),kid:'safe-test',alg:'ES256',use:'sig'};
const verify=createLoginVerifier({config,
  judgeKeySet:createLocalJWKSet({keys:[jwk]}),
  supabaseClient:{auth:{async getClaims(){return {data:null,error:new Error('rejected')}}}},
});
async function judgeToken(options={}){
  const now=Math.floor(Date.now()/1000);
  return new SignJWT({
    aleph_role:'judge',aleph_identity:'a',aleph_run:'22222222-2222-4222-8222-222222222222',
  }).setProtectedHeader({alg:'ES256',kid:jwk.kid})
   .setIssuer(config.judgeIssuer).setAudience('test-auth-audit.vercel.app')
   .setSubject('11111111-1111-4111-8111-111111111111')
   .setIssuedAt(now-20).setExpirationTime(options.expired ? now-10 : now+200)
   .sign(privateKey);
}
test('only fixed route, method, auth-presence and classification appear in logs',()=>{
  const lines=[];
  const old=console.info;
  try {
    console.info=(...args)=>lines.push(args.join(' '));
    auditNoteEntry('/api/notes/:id',{method:'GET',url:'/api/notes/private-id?secret=abc',
      headers:{authorization:'Bearer FAKE_PRIVATE_TOKEN'}});
    auditNoteAuth('/api/notes/:id',null,'signature');
    auditNoteAuth('/api/notes',{kind:'judge',userId:'PRIVATE_USER_ID'},null);
  } finally {console.info=old;}
  assert.equal(lines.length,3);
  assert.match(lines[0],/aleph_s08_entry.*"route":"\\/api\\/notes\\/:id".*"method":"GET".*"authHeader":"present"/);
  assert.match(lines[1],/aleph_s08_auth.*"kind":"null".*"reason":"signature"/);
  assert.match(lines[2],/aleph_s08_auth.*"kind":"judge".*"reason":"ok"/);
  for(const forbidden of ['FAKE_PRIVATE_TOKEN','PRIVATE_USER_ID','private-id','abc']){
    assert.ok(!lines.join(' ').includes(forbidden),forbidden);
  }
});
test('verifier reports missing, format, issuer, expired, and success without changing authorisation',async()=>{
  let reason='unknown';
  assert.equal(await verify(null,x=>reason=x),null);assert.equal(reason,'missing');
  assert.equal(await verify('invalid',x=>reason=x),null);assert.equal(reason,'format');
  const otherIssuer=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:jwk.kid})
    .setIssuer('https://other.example.org').setAudience('test-auth-audit.vercel.app')
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  assert.equal(await verify('Bearer '+otherIssuer,x=>reason=x),null);assert.equal(reason,'issuer');
  assert.equal(await verify('Bearer '+await judgeToken({expired:true}),x=>reason=x),null);
  assert.equal(reason,'expired');
  reason='unknown';
  const login=await verify('Bearer '+await judgeToken(),x=>reason=x);
  assert.equal(login.kind,'judge');
  assert.equal(reason,'unknown');
});
