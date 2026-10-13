// Minimal ES256 WebAuthn verifier for the Stage 11 origin, with strict inputs.
// Private keys stay in the platform authenticator; only public x/y are stored.
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
const B64=/^[A-Za-z0-9_-]{1,24000}$/u;
const base64=value=>Buffer.from(value).toString('base64url');
export const sha256=value=>createHash('sha256').update(value).digest();
export const digestBody=body=>base64(sha256(body??''));
function decode(value,max=20000){
 if(typeof value!=='string'||!B64.test(value)||value.length>max*2)throw Error('invalid_webauthn_data');
 const bytes=Buffer.from(value,'base64url');
 if(bytes.length>max||base64(bytes)!==value)throw Error('invalid_webauthn_data');
 return bytes;
}
function cbor(b,offset=0,depth=0){
 if(depth>8 || offset>=b.length)throw Error('invalid_cbor');
 const octet=b[offset++],major=octet>>5,small=octet&31;
 let n;
 if(small<24)n=small;
 else if(small===24){if(offset+1>b.length)throw Error('invalid_cbor');n=b[offset++];}
 else if(small===25){if(offset+2>b.length)throw Error('invalid_cbor');n=b.readUInt16BE(offset);offset+=2;}
 else if(small===26){if(offset+4>b.length)throw Error('invalid_cbor');n=b.readUInt32BE(offset);offset+=4;}
 else throw Error('unsupported_cbor');
 if(major===0)return {v:n,pos:offset};
 if(major===1)return {v:-1-n,pos:offset};
 if(major===2||major===3){
  if(offset+n>b.length)throw Error('invalid_cbor');
  const bytes=b.subarray(offset,offset+n);
  const v=major===2?bytes:new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  return {v,pos:offset+n};
 }
 if(major===4){
  if(n>128)throw Error('invalid_cbor');
  const v=[];for(let i=0;i<n;i++){const out=cbor(b,offset,depth+1);v.push(out.v);offset=out.pos;}
  return {v,pos:offset};
 }
 if(major===5){
  if(n>128)throw Error('invalid_cbor');
  const v=new Map();
  for(let i=0;i<n;i++){
   const k=cbor(b,offset,depth+1);const value=cbor(b,k.pos,depth+1);
   if(v.has(k.v))throw Error('duplicate_cbor_key');
   v.set(k.v,value.v);offset=value.pos;
  }
  return {v,pos:offset};
 }
 if(major===7 && (n===20||n===21||n===22))return {v:n===22?null:n===21,pos:offset};
 throw Error('unsupported_cbor');
}
function clientData(encoded,{challenge,origin,type}){
 const raw=decode(encoded,8192);
 let json;
 try{json=JSON.parse(raw.toString('utf8'));}catch{throw Error('invalid_client_data');}
 if(json?.type!==type||json.challenge!==challenge||json.origin!==origin||
  json.crossOrigin===true)throw Error('invalid_client_binding');
 return raw;
}
function checkedAuthenticator(data,rpID,registered=false) {
 if(data.length<37)throw Error('invalid_authenticator_data');
 if(!sha256(rpID).equals(data.subarray(0,32)))throw Error('wrong_rp_id');
 const flags=data[32];
 // UP and UV both required; never let an installation badge count as identity.
 if(!(flags&1)||!(flags&4)||(registered&&!(flags&64)))throw Error('user_verification_required');
 return {flags,count:data.readUInt32BE(33)};
}
export function verifyRegistration({response,challenge,origin,rpID}){
 if(response?.type!=='public-key'||!response.id||
  response.id!==response.rawId||!response.response)throw Error('invalid_registration_response');
 clientData(response.response.clientDataJSON,{challenge,origin,type:'webauthn.create'});
 const obj=decode(response.response.attestationObject,16000);
 const parsed=cbor(obj);
 if(parsed.pos!==obj.length || !(parsed.v instanceof Map) ||
  parsed.v.get('fmt')!=='none' ||
  !(parsed.v.get('attStmt') instanceof Map) ||
  parsed.v.get('attStmt').size!==0)throw Error('invalid_attestation');
 const auth=parsed.v.get('authData');
 if(!Buffer.isBuffer(auth))throw Error('invalid_attestation_data');
 const status=checkedAuthenticator(auth,rpID,true);
 if(auth.length<55)throw Error('invalid_credential_data');
 const len=auth.readUInt16BE(53);
 if(len===0||len>1024||55+len>=auth.length)throw Error('invalid_credential_id');
 const id=base64(auth.subarray(55,55+len));
 if(id!==response.id)throw Error('credential_id_mismatch');
 const cose=cbor(auth,55+len);
 if(!(cose.v instanceof Map)||cose.pos!==auth.length ||
  cose.v.get(1)!==2||cose.v.get(3)!==-7||cose.v.get(-1)!==1 ||
  !Buffer.isBuffer(cose.v.get(-2)) || cose.v.get(-2).length!==32 ||
  !Buffer.isBuffer(cose.v.get(-3)) || cose.v.get(-3).length!==32)throw Error('unsupported_credential_key');
 const x=base64(cose.v.get(-2)),y=base64(cose.v.get(-3));
 // Reject invalid elliptic curve points before saving the public key.
 createPublicKey({key:{kty:'EC',crv:'P-256',x,y},format:'jwk'});
 return {credentialId:id,publicX:x,publicY:y,signCount:status.count};
}
export function verifyAssertion({response,challenge,origin,rpID,credential}){
 if(response?.type!=='public-key'||response.id!==credential?.credential_id ||
  response.rawId!==response.id||!response.response)throw Error('invalid_assertion_response');
 const data=clientData(response.response.clientDataJSON,
  {challenge,origin,type:'webauthn.get'});
 const auth=decode(response.response.authenticatorData,4096);
 const status=checkedAuthenticator(auth,rpID);
 const sig=decode(response.response.signature,2048);
 const key=createPublicKey({key:{
  kty:'EC',crv:'P-256',x:credential.public_x,y:credential.public_y,
 },format:'jwk'});
 if(!verifySignature('sha256',Buffer.concat([auth,sha256(data)]),key,sig))
  throw Error('invalid_signature');
 const previous=Number(credential.sign_count);
 if(!Number.isSafeInteger(previous)||previous<0||
   (status.count!==0 && status.count<=previous) ||
   (previous>0 && status.count===0))throw Error('cloned_credential_counter');
 return status.count;
}
