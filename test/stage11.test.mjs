import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {sha256,digestBody,verifyAssertion,verifyRegistration} from '../src/app-webauthn.mjs';
import {validSignedTarget,matchesSignedTarget} from '../api/app-request.js';
import {studentDeviceAccess,APP_APPROVED} from '../src/app-approval.mjs';

const rpID='choi-bujang-secret-vault-jwnp.vercel.app';
const origin='https://'+rpID;
const challenge=randomBytes(32).toString('base64url');
const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=pair.publicKey.export({format:'jwk'});
const credentialId=randomBytes(32).toString('base64url');
const credential={credential_id:credentialId,public_x:jwk.x,public_y:jwk.y,sign_count:0};
const clientJSON=(type,nonce=challenge,site=origin)=>Buffer.from(JSON.stringify({
 type,challenge:nonce,origin:site,crossOrigin:false,
}));
const b64=bytes=>Buffer.from(bytes).toString('base64url');
function authData(flags=5,count=1) {
 const b=Buffer.alloc(37);
 sha256(rpID).copy(b,0);b[32]=flags;b.writeUInt32BE(count,33);return b;
}
function assertion({nonce=challenge,site=origin,flags=5,count=1,signatureOverride}={}){
 const client=clientJSON('webauthn.get',nonce,site);
 const authenticator=authData(flags,count);
 const signature=signatureOverride??sign('sha256',Buffer.concat([authenticator,sha256(client)]),pair.privateKey);
 return {id:credentialId,rawId:credentialId,type:'public-key',response:{
  clientDataJSON:b64(client),authenticatorData:b64(authenticator),signature:b64(signature),
 }};
}
function attestation() {
 const rawID=Buffer.from(credentialId,'base64url');
 const cose=Buffer.concat([
  Buffer.from([0xa5,1,2,3,0x26,0x20,1,0x21,0x58,0x20]),
  Buffer.from(jwk.x,'base64url'),Buffer.from([0x22,0x58,0x20]),
  Buffer.from(jwk.y,'base64url'),
 ]);
 const body=Buffer.concat([
  authData(0x45,0),Buffer.alloc(16),
  Buffer.from([rawID.length>>8,rawID.length&255]),rawID,cose,
 ]);
 // CBOR map: fmt=none, attStmt={}, authData=raw byte string
 const obj=Buffer.concat([
  Buffer.from([0xa3,0x63,0x66,0x6d,0x74,0x64,0x6e,0x6f,0x6e,0x65,
   0x67,0x61,0x74,0x74,0x53,0x74,0x6d,0x74,0xa0,
   0x68,0x61,0x75,0x74,0x68,0x44,0x61,0x74,0x61,0x58,body.length]),
  body,
 ]);
 return {id:credentialId,rawId:credentialId,type:'public-key',
  response:{clientDataJSON:b64(clientJSON('webauthn.create')),attestationObject:b64(obj)}};
}
test('valid ES256 registration stores only public coordinates and pending remains separate',()=>{
 const r=verifyRegistration({response:attestation(),challenge,origin,rpID});
 assert.deepEqual(r,{credentialId,publicX:jwk.x,publicY:jwk.y,signCount:0});
 assert.ok(!JSON.stringify(r).includes('PRIVATE KEY'));
 assert.throws(()=>verifyRegistration({response:attestation(),challenge,origin:'https://evil.example',rpID}));
});
test('valid WebAuthn signature verifies origin, rpId, challenge, UV and counter',()=>{
 assert.equal(verifyAssertion({response:assertion(),challenge,origin,rpID,credential}),1);
 for(const options of [
  {challenge:b64(randomBytes(32))},{origin:'https://untrusted.example'},
  {rpID:'other.example'},{credential:{...credential,sign_count:1}},
 ]) assert.throws(()=>verifyAssertion({response:assertion(),challenge,origin,rpID,credential,...options}));
 assert.throws(()=>verifyAssertion({response:assertion({flags:1}),challenge,origin,rpID,credential}));
 assert.throws(()=>verifyAssertion({response:assertion({signatureOverride:randomBytes(70)}),challenge,origin,rpID,credential}));
});
test('method, path and JSON bytes are bound to one approved challenge',()=>{
 const original={method:'PUT',path:'/api/notes/11111111-1111-4111-8111-111111111111',
  body:JSON.stringify({title:'safe',body:'original'})};
 assert.ok(validSignedTarget(original));
 const saved={method:original.method,path:original.path,body_sha256:digestBody(original.body)};
 assert.equal(matchesSignedTarget(saved,original),true);
 for(const tamper of [
  {...original,path:'/api/notes/22222222-2222-4222-8222-222222222222'},
  {...original,path:original.path+'?id=2'},
  {...original,method:'DELETE',body:null},
  {...original,body:JSON.stringify({title:'safe',body:'changed'})},
  {...original,body:'{"body":"original","title":"safe"}'},
 ]) assert.equal(matchesSignedTarget(saved,tamper),false,JSON.stringify(tamper));
});
test('reject unsigned or unscoped routes, query alterations and collection updates',()=>{
 for(const input of [
  {method:'GET',path:'/api/notes',body:null},
  {method:'POST',path:'/api/notes',body:'{"title":"hi","body":"ok"}'},
  {method:'GET',path:'/api/instructor-notices',body:null},
 ])assert.equal(validSignedTarget(input),true);
 for(const input of [
  {method:'GET',path:'/api/notes',body:'ignored'},
  {method:'PUT',path:'/api/notes',body:'{}'},
  {method:'GET',path:'/api/notes?all=1',body:null},
  {method:'POST',path:'/api/restore',body:'{}'},
  {method:'DELETE',path:'/api/instructor-notices',body:null},
  {method:'PUT',path:'/api/notes/demo',body:'{}'},
  {method:'POST',path:'/api/notes',body:{title:'object'}},
  {method:'GET',path:'/api/notes',body:null,approved:true},
 ])assert.equal(validSignedTarget(input),false,JSON.stringify(input));
});
test('student direct API is denied without internal proof; judge contract survives',()=>{
 assert.equal(studentDeviceAccess({kind:'student'},{}),false);
 assert.equal(studentDeviceAccess({kind:'student'},{headers:{'x-device-approved':'true'}}),false);
 assert.equal(studentDeviceAccess({kind:'student'},{[APP_APPROVED]:true}),true);
 assert.equal(studentDeviceAccess({kind:'judge'},{}),true);
});
test('browser never persists session and protected data is not cached',async()=>{
 const {readFile}=await import('node:fs/promises');
 const js=await readFile(new URL('../public/app.js',import.meta.url),'utf8');
 const sw=await readFile(new URL('../public/sw.js',import.meta.url),'utf8');
 assert.ok(js.includes('persistSession:false'));
 assert.ok(!/\b(?:localStorage|sessionStorage|indexedDB)\s*\./u.test(js));
 assert.ok(sw.includes("url.pathname.startsWith('/api/')"));
 assert.ok(sw.includes('caches.match(event.request)'));
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.ok(html.includes('id="create-panel"') && html.includes('hidden'));
 assert.ok(html.includes('manifest.webmanifest'));
});
