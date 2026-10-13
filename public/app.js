import {createClient} from 'https://esm.sh/@supabase/supabase-js@2.117.2';

const $=selector=>document.querySelector(selector);
const loginForm=$('#login-form'),logoutButton=$('#logout-button');
const deviceSection=$('#device-panel'),deviceStatus=$('#device-status');
const requestButton=$('#device-request'),refreshButton=$('#device-refresh');
const createPanel=$('#create-panel'),createForm=$('#create-form'),notes=$('#notes');
const authStatus=$('#auth-status'),loginButton=$('#login-button');
const status=$('#connection-status'),installStatus=$('#install-status');
let currentSession=null,approved=false,supabase=null;
const b64Decode=input=>{
 const string=atob(input.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-input.length%4)%4));
 return Uint8Array.from(string,c=>c.charCodeAt(0));
};
const b64Encode=buffer=>{
 const bytes=new Uint8Array(buffer);
 let raw='';for(const b of bytes)raw+=String.fromCharCode(b);
 return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
};
const show=($element,text,error=false)=>{
 $element.textContent=text;
 $element.classList.toggle('error',error);
};
function lockedNotes(message='서버의 기기 승인이 확인되기 전에는 보호 자료가 표시되지 않습니다.'){
 const li=document.createElement('li');li.textContent=message;notes.replaceChildren(li);
 createPanel.hidden=true;approved=false;
}
function displayAuth(session,message){
 currentSession=session??null;
 loginForm.hidden=Boolean(session);logoutButton.hidden=!session;
 deviceSection.hidden=!session;
 show(authStatus,message|| (session?'로그인 확인됨 · 기기 인증 필요':'로그인하지 않음'));
 if(!session){lockedNotes('로그인하고 승인된 기기 인증을 완료해야 자료가 열립니다.');
   show(deviceStatus,'기기 승인 요청 전');}
}
async function jsonFetch(path,options={}){
 if(!currentSession?.access_token)throw Error('로그인이 필요합니다.');
 const response=await fetch(path,{cache:'no-store',...options,headers:{
  'Content-Type':'application/json',
  Authorization:'Bearer '+currentSession.access_token,...options.headers,
 }});
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw Error(data.error||'서버에서 요청을 거부했습니다.');
 return data;
}
function registrationOptions(o){
 return {...o,challenge:b64Decode(o.challenge),
  user:{...o.user,id:b64Decode(o.user.id)},
  excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:b64Decode(c.id)})),
 };
}
function authenticationOptions(o){
 return {...o,challenge:b64Decode(o.challenge),
  allowCredentials:(o.allowCredentials||[]).map(c=>({...c,id:b64Decode(c.id)})),
 };
}
function serializeCredential(credential,operation){
 const r=credential.response;
 return operation==='create'?{
  id:credential.id,rawId:b64Encode(credential.rawId),type:credential.type,
  response:{clientDataJSON:b64Encode(r.clientDataJSON),
   attestationObject:b64Encode(r.attestationObject)},
 }:{
  id:credential.id,rawId:b64Encode(credential.rawId),type:credential.type,
  response:{clientDataJSON:b64Encode(r.clientDataJSON),
   authenticatorData:b64Encode(r.authenticatorData),
   signature:b64Encode(r.signature)},
 };
}
async function enrollDevice(){
 if(!window.PublicKeyCredential||!navigator.credentials?.create)
  throw Error('이 브라우저에서는 기기 보안 인증을 지원하지 않습니다.');
 show(deviceStatus,'기기 보안 인증을 요청하고 있습니다.');
 const registration=await jsonFetch('/api/device',{method:'POST',
  body:JSON.stringify({action:'begin'})});
 const credential=await navigator.credentials.create({
  publicKey:registrationOptions(registration.options),
 });
 if(!credential)throw Error('기기 보안 인증이 취소됐습니다.');
 const done=await jsonFetch('/api/device',{method:'POST',body:JSON.stringify({
  action:'finish',challengeId:registration.challengeId,
  response:serializeCredential(credential,'create'),
 })});
 if(done.status!=='pending'||done.approved!==false)
  throw Error('서버의 승인 대기 결과가 확인되지 않았습니다.');
 lockedNotes();
 show(deviceStatus,'등록 요청 완료 · 서버 관리자 승인 대기 중. 승인 버튼만으로 보호 자료가 열리지 않습니다.');
}
async function signedRequest(path,{method='GET',body=null}={}){
 if(!approved)throw Error('기기 승인을 먼저 확인하세요.');
 const target={path,method,body};
 const beginning=await jsonFetch('/api/app-request',{method:'POST',
  body:JSON.stringify({action:'begin',target})});
 if(!navigator.credentials?.get)throw Error('기기 보안 인증을 지원하지 않습니다.');
 const assertion=await navigator.credentials.get({
  publicKey:authenticationOptions(beginning.options),
 });
 if(!assertion)throw Error('기기 서명 절차가 취소됐습니다.');
 return jsonFetch('/api/app-request',{method:'POST',body:JSON.stringify({
  action:'execute',target,challengeId:beginning.challengeId,
  proof:serializeCredential(assertion,'get'),
 })});
}
function makeNote(note){
 const li=document.createElement('li'),title=document.createElement('strong');
 const content=document.createElement('span'),actions=document.createElement('div');
 title.textContent=note.title;content.textContent=note.body;
 actions.className='actions';
 const edit=document.createElement('button'),remove=document.createElement('button');
 edit.type='button';edit.className='secondary';edit.textContent='수정';
 remove.type='button';remove.className='danger';remove.textContent='삭제';
 edit.addEventListener('click',async()=>{
  const t=window.prompt('수정할 제목',note.title);
  if(t===null)return;
  const b=window.prompt('수정할 내용',note.body);
  if(b===null)return;
  try{
   await signedRequest('/api/notes/'+encodeURIComponent(note.id),{
    method:'PUT',body:JSON.stringify({title:t,body:b}),
   });await loadNotes();
  }catch(e){window.alert(e.message);}
 });
 remove.addEventListener('click',async()=>{
  if(!window.confirm('이 가상 메모를 삭제할까요?'))return;
  try{await signedRequest('/api/notes/'+encodeURIComponent(note.id),{method:'DELETE'});await loadNotes();}
  catch(e){window.alert(e.message);}
 });
 actions.append(edit,remove);li.append(title,content,actions);return li;
}
async function loadNotes(){
 if(!currentSession||!approved){lockedNotes();return;}
 const data=await signedRequest('/api/notes');
 if(!Array.isArray(data?.notes))throw Error('서버 응답을 확인할 수 없습니다.');
 if(!data.notes.length){const li=document.createElement('li');
  li.textContent='등록된 가상 메모가 없습니다.';notes.replaceChildren(li);}
 else notes.replaceChildren(...data.notes.map(makeNote));
 createPanel.hidden=false;
}
async function checkDevice(){
 lockedNotes();
 if(!currentSession)return;
 const state=await jsonFetch('/api/device');
 if(!state.approved){
  show(deviceStatus,state.pendingCount?
   '서버 관리자 승인 대기 중 · 아직 보호 자료 접근 불가':
   '등록된 승인 기기가 없습니다. 아래에서 기기 등록을 요청하세요.');
  return;
 }
 approved=true;
 show(deviceStatus,'서버 승인 기록 확인됨 · 보호 자료 요청마다 보안 인증기 서명 검증');
 try{await loadNotes();}
 catch(e){lockedNotes('기기 서명 검증 또는 보호 자료 읽기에 실패했습니다. '+e.message);
  show(deviceStatus,'승인 기록은 있으나 서명 검증을 완료하지 못했습니다.',true);}
}
function updateNetwork(){
 const online=navigator.onLine;
 show(status,online?'온라인 · 보호 요청은 서버에서 확인합니다.':
  '오프라인 · 이전 보호 자료를 저장하지 않으며, 다시 연결하면 로그인해 주세요.',!online);
}
window.addEventListener('online',updateNetwork);
window.addEventListener('offline',()=>{updateNetwork();lockedNotes();});
updateNetwork();
show(installStatus,window.matchMedia('(display-mode: standalone)').matches?
 '앱 화면으로 실행 중 · 설치 상태가 기기 승인을 뜻하지 않습니다.':
 '브라우저 메뉴에서 「앱 설치」 또는 「홈 화면에 추가」를 선택할 수 있습니다. 설치만으로 승인되지는 않습니다.');
if('serviceWorker' in navigator){
 navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(()=>{});
}
try{
 const r=await fetch('/api/public-config',{cache:'no-store'});
 if(!r.ok)throw Error('로그인 공개 설정을 불러오지 못했습니다.');
 const config=await r.json();
 // Never persist access/refresh tokens or device keys to localStorage,
 // sessionStorage, IndexedDB, Cache Storage or service-worker caches.
 supabase=createClient(config.url,config.publishableKey,{auth:{
  persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,
 }});
 displayAuth(null,'로그인 후 서버에 기기 등록을 요청하세요.');
}catch(e){displayAuth(null);show(authStatus,e.message,true);}
loginForm.addEventListener('submit',async event=>{
 event.preventDefault();if(!supabase)return;
 loginButton.disabled=true;show(authStatus,'계정을 확인하는 중입니다.');
 const {data,error}=await supabase.auth.signInWithPassword({
  email:$('#email').value.trim(),password:$('#password').value,
 });
 $('#password').value='';loginButton.disabled=false;
 if(error){show(authStatus,'로그인 실패: '+error.message,true);return;}
 displayAuth(data.session);
 try{await checkDevice();}catch(e){show(deviceStatus,e.message,true);}
});
logoutButton.addEventListener('click',async()=>{
 if(supabase)await supabase.auth.signOut();
 displayAuth(null);
});
requestButton.addEventListener('click',async()=>{
 requestButton.disabled=true;
 try{await enrollDevice();}catch(e){show(deviceStatus,e.message,true);}
 finally{requestButton.disabled=false;}
});
refreshButton.addEventListener('click',async()=>{
 refreshButton.disabled=true;
 try{await checkDevice();}catch(e){show(deviceStatus,e.message,true);}
 finally{refreshButton.disabled=false;}
});
createForm.addEventListener('submit',async event=>{
 event.preventDefault();
 try{
  await signedRequest('/api/notes',{method:'POST',body:JSON.stringify({
   title:$('#new-title').value,body:$('#new-body').value,
  })});
  createForm.reset();await loadNotes();
 }catch(e){window.alert(e.message);}
});
