// In-memory synthetic authenticators only. No Windows Hello, browser, database,
// API, deployment, key files, or private-key exports are used by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import {constants,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {sha256,verifyRegistration,verifyAssertion} from '../src/app-webauthn.mjs';

const rpID='watchdogs-rsa.test';
const origin='https://'+rpID;
const challenge=randomBytes(32).toString('base64url');
const b64=bytes=>Buffer.from(bytes).toString('base64url');
const keyPairs=new Map();
function rsaPair(bits=2048,exponent=65537){
 const name=bits+':'+exponent;
 if(!keyPairs.has(name))keyPairs.set(name,generateKeyPairSync('rsa',{
  modulusLength:bits,publicExponent:exponent,
 }));
 return keyPairs.get(name);
}

// RSA moduli and attestation authData exceed 255 bytes. Encode CBOR length 25
// with a full unsigned 16-bit length rather than truncating the fixture length.
function cborHead(major,length){
 if(!Number.isSafeInteger(length)||length<0||length>65535)throw Error('fixture_length');
 if(length<24)return Buffer.from([(major<<5)|length]);
 if(length<=255)return Buffer.from([(major<<5)|24,length]);
 const header=Buffer.alloc(3);header[0]=(major<<5)|25;header.writeUInt16BE(length,1);
 return header;
}
function cbor(value){
 if(Buffer.isBuffer(value))return Buffer.concat([cborHead(2,value.length),value]);
 if(typeof value==='string'){
  const bytes=Buffer.from(value);return Buffer.concat([cborHead(3,bytes.length),bytes]);
 }
 if(Number.isSafeInteger(value))return value<0?cborHead(1,-1-value):cborHead(0,value);
 if(value instanceof Map)return Buffer.concat([cborHead(5,value.size),
  ...[...value].flatMap(([key,item])=>[cbor(key),cbor(item)]),
 ]);
 throw Error('fixture_cbor_type');
}
function clientData(type,{nonce=challenge,site=origin}={}){
 return Buffer.from(JSON.stringify({type,challenge:nonce,origin:site,crossOrigin:false}));
}
function authenticator({flags=5,count=1,relyingParty=rpID}={}){
 const data=Buffer.alloc(37);sha256(relyingParty).copy(data);data[32]=flags;
 data.writeUInt32BE(count,33);return data;
}
function rsaCose(pair=rsaPair()){
 const jwk=pair.publicKey.export({format:'jwk'});
 return new Map([[1,3],[3,-257],[-1,Buffer.from(jwk.n,'base64url')],
  [-2,Buffer.from(jwk.e,'base64url')]]);
}
function registration({pair=rsaPair(),cose=rsaCose(pair),flags=0x45,count=0,
 relyingParty=rpID,nonce=challenge,site=origin,credentialId=b64(randomBytes(32))}={}){
 const rawId=Buffer.from(credentialId,'base64url');
 const idLength=Buffer.alloc(2);idLength.writeUInt16BE(rawId.length);
 const authData=Buffer.concat([authenticator({flags,count,relyingParty}),
  Buffer.alloc(16),idLength,rawId,cbor(cose)]);
 const attestationObject=cbor(new Map([
  ['fmt','none'],['attStmt',new Map()],['authData',authData],
 ]));
 return {id:credentialId,rawId:credentialId,type:'public-key',response:{
  clientDataJSON:b64(clientData('webauthn.create',{nonce,site})),
  attestationObject:b64(attestationObject),
 }};
}
function registeredCredential(pair=rsaPair()){
 const response=registration({pair});
 const saved=verifyRegistration({response,challenge,origin,rpID});
 return {response,saved,credential:{
  credential_id:saved.credentialId,key_algorithm:saved.keyAlgorithm,
  public_n:saved.publicN,public_e:saved.publicE,public_x:null,public_y:null,
  sign_count:saved.signCount,status:'approved',
 }};
}
function assertion({pair=rsaPair(),credentialId,flags=5,count=1,
 relyingParty=rpID,nonce=challenge,site=origin,padding=constants.RSA_PKCS1_PADDING}={}){
 const client=clientData('webauthn.get',{nonce,site});
 const authData=authenticator({flags,count,relyingParty});
 const signature=sign('sha256',Buffer.concat([authData,sha256(client)]),{
  key:pair.privateKey,padding,
  ...(padding===constants.RSA_PKCS1_PSS_PADDING?{saltLength:32}:{}),
 });
 return {id:credentialId,rawId:credentialId,type:'public-key',response:{
  clientDataJSON:b64(client),authenticatorData:b64(authData),signature:b64(signature),
 }};
}
function checkRegistration(response){return verifyRegistration({response,challenge,origin,rpID});}
function checkAssertion(response,credential){return verifyAssertion({response,credential,challenge,origin,rpID});}

test('synthetic RSA fixtures preserve 16-bit CBOR byte-string lengths',()=>{
 assert.deepEqual([...cborHead(2,256)],[0x59,0x01,0x00]);
 assert.deepEqual([...cborHead(2,512)],[0x59,0x02,0x00]);
 assert.equal(Buffer.from(registration().response.attestationObject,'base64url')[0],0xa3);
});

for(const bits of [2048,3072,4096]){
 test('synthetic RSA '+bits+' registration and approved-credential assertion retain public data only',()=>{
  const pair=rsaPair(bits),jwk=pair.publicKey.export({format:'jwk'});
  const {saved,credential}=registeredCredential(pair);
  assert.deepEqual(saved,{credentialId:credential.credential_id,keyAlgorithm:-257,
   publicN:jwk.n,publicE:jwk.e,signCount:0});
  assert.deepEqual(Object.keys(saved).sort(),['credentialId','keyAlgorithm','publicE','publicN','signCount']);
  assert.ok(!Object.values(saved).includes(pair.privateKey));
  const response=assertion({pair,credentialId:credential.credential_id});
  assert.equal(checkAssertion(response,credential),1);
 });
}

test('RSA registration rejects wrong origin, challenge, RP ID, UP, UV and credential IDs',()=>{
 for(const options of [
  {site:'https://untrusted.test'},{nonce:b64(randomBytes(32))},
  {relyingParty:'other.test'},{flags:0x44},{flags:0x41},{flags:0x05},
 ])assert.throws(()=>checkRegistration(registration(options)));
 const response=registration();response.id=b64(randomBytes(32));response.rawId=response.id;
 assert.throws(()=>checkRegistration(response));
 const mismatched=registration();mismatched.rawId=b64(randomBytes(32));
 assert.throws(()=>checkRegistration(mismatched));
});

test('RSA assertions reject wrong origin, challenge, RP ID, UP, UV and credential IDs',()=>{
 const {credential}=registeredCredential();
 for(const options of [
  {site:'https://untrusted.test'},{nonce:b64(randomBytes(32))},
  {relyingParty:'other.test'},{flags:4},{flags:1},
  {credentialId:b64(randomBytes(32))},
 ])assert.throws(()=>checkAssertion(assertion({credentialId:credential.credential_id,...options}),credential));
 const mismatched=assertion({credentialId:credential.credential_id});
 mismatched.rawId=b64(randomBytes(32));
 assert.throws(()=>checkAssertion(mismatched,credential));
});

test('RSA assertions reject a changed signature and a signature from another key',()=>{
 const {credential}=registeredCredential();
 const response=assertion({credentialId:credential.credential_id});
 const signature=Buffer.from(response.response.signature,'base64url');signature[0]^=1;
 response.response.signature=b64(signature);
 assert.throws(()=>checkAssertion(response,credential));
 const unrelated=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
 assert.throws(()=>checkAssertion(assertion({pair:unrelated,credentialId:credential.credential_id}),credential));
});

test('RSA positive counters reject replay, rollback and returning to zero',()=>{
 const {credential}=registeredCredential();
 const accepted=assertion({credentialId:credential.credential_id,count:3});
 assert.equal(checkAssertion(accepted,credential),3);
 const advanced={...credential,sign_count:3};
 assert.throws(()=>checkAssertion(accepted,advanced));
 for(const count of [0,1,2]){
  assert.throws(()=>checkAssertion(assertion({credentialId:credential.credential_id,count}),advanced));
 }
 assert.equal(checkAssertion(assertion({credentialId:credential.credential_id,count:4}),advanced),4);
});

test('RSA PKCS1 registration never accepts RSA-PSS signatures or PSS algorithm identifiers',()=>{
 const {credential}=registeredCredential();
 assert.throws(()=>checkAssertion(assertion({credentialId:credential.credential_id,
  padding:constants.RSA_PKCS1_PSS_PADDING}),credential));
 const cose=rsaCose();cose.set(3,-37);
 assert.throws(()=>checkRegistration(registration({cose})));
 assert.throws(()=>checkAssertion(assertion({credentialId:credential.credential_id}),{
  ...credential,key_algorithm:-37,
 }));
});

test('RSA registration rejects 1024-bit moduli and exponent three',()=>{
 for(const pair of [rsaPair(1024),rsaPair(2048,3)]){
  assert.throws(()=>checkRegistration(registration({pair})));
 }
});

test('RSA COSE rejects algorithm and key-type confusion',()=>{
 for(const [label,value] of [[1,2],[3,-7]]){
  const cose=rsaCose();cose.set(label,value);
  assert.throws(()=>checkRegistration(registration({cose})));
 }
});

test('RSA COSE rejects private, common-but-unsupported and unknown key fields',()=>{
 for(const key of [-3,-4,-5,-6,-7,-8,2,4,99]){
  const cose=rsaCose();cose.set(key,Buffer.from([1]));
  assert.throws(()=>checkRegistration(registration({cose})));
 }
});

test('RSA COSE modulus must be canonical unsigned and nonempty',()=>{
 for(const modulus of [Buffer.alloc(0),Buffer.alloc(256),
  Buffer.concat([Buffer.from([0]),rsaCose().get(-1)])]){
  const cose=rsaCose();cose.set(-1,modulus);
  assert.throws(()=>checkRegistration(registration({cose})));
 }
});

test('RSA assertions reject EC algorithm labels and mixed EC/RSA database public fields',()=>{
 const {credential}=registeredCredential();
 const response=assertion({credentialId:credential.credential_id});
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
 for(const changed of [
  {...credential,key_algorithm:-7},
  {...credential,key_algorithm:undefined},
  {...credential,public_x:ec.x,public_y:ec.y},
  {...credential,public_n:undefined},
  {...credential,public_e:undefined},
 ])assert.throws(()=>checkAssertion(response,changed));
});

test('ES256 registration shape and legacy/explicit algorithm assertions remain unchanged',()=>{
 const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const jwk=pair.publicKey.export({format:'jwk'});
 const cose=new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],
  [-3,Buffer.from(jwk.y,'base64url')]]);
 const response=registration({pair,cose});
 const saved=checkRegistration(response);
 assert.deepEqual(saved,{credentialId:response.id,publicX:jwk.x,publicY:jwk.y,signCount:0});
 const client=clientData('webauthn.get'),authData=authenticator();
 const signed={id:saved.credentialId,rawId:saved.credentialId,type:'public-key',response:{
  clientDataJSON:b64(client),authenticatorData:b64(authData),
  signature:b64(sign('sha256',Buffer.concat([authData,sha256(client)]),pair.privateKey)),
 }};
 const credential={credential_id:saved.credentialId,public_x:jwk.x,public_y:jwk.y,sign_count:0};
 assert.equal(checkAssertion(signed,credential),1);
 assert.equal(checkAssertion(signed,{...credential,key_algorithm:-7,public_n:null,public_e:null}),1);
 assert.throws(()=>checkAssertion(signed,{...credential,key_algorithm:-257,public_n:null,public_e:null}));
});
