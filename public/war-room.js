// Stage 12 operations screen. Only server-returned evidence is rendered.
// All displayed note/engine fields are labels; no private records are fetched.
const byId=id=>document.getElementById(id);
const labels={
 public_home:'공개 시작 화면 · 정상',
 public_manifest:'설치형 manifest · 정상',
 deployment_identity:'배포 식별 정보 · 정상',
 anonymous_notes:'무인증 메모 목록 · 거부',
 anonymous_note_item:'무인증 메모 단건 · 거부',
 anonymous_notices:'무인증 강사 공지 · 거부',
 anonymous_device_status:'무인증 기기 상태 · 거부',
 unsigned_app_request:'서명 없는 비로그인 앱 요청 · 거부',
 anonymous_restore:'무인증 메모 복구 · 거부',
 anonymous_policy:'무인증 정책 조회 · 거부',
 invalid_resource_path:'허용되지 않은 메모 경로 · 거부',
 anonymous_note_create:'무인증 메모 등록 · 거부',
};
const textNode=(tag,value)=>{const x=document.createElement(tag);x.textContent=String(value);return x;};
const dateString=value=>value?new Date(value).toLocaleString('ko-KR'):'미실행';
function cell(row,value){
 const cell=textNode('td',value);row.append(cell);return cell;
}
function renderOfficialSlots(){
 const body=byId('war-official-rows');
 body.replaceChildren();
 for(let n=1;n<=41;n++){
  const row=document.createElement('tr');
  cell(row,'#'+String(n).padStart(2,'0'));
  cell(row,'공식 개별 사건 명세 미연동');
  cell(row,'심판 기준 미연결');
  cell(row,'미확인');
  cell(row,'—');
  body.append(row);
 }
}
export function mountWarRoom(getAccessToken){
 const section=byId('war-room');
 const message=byId('war-room-status'),metrics=byId('war-metrics');
 const checksBody=byId('war-check-rows'),specsHolder=byId('war-probes');
 const refresh=byId('war-refresh');
 renderOfficialSlots();
 let records=[],specs=[],busy=false;
 function show(messageText,isError=false){
  message.textContent=messageText;
  message.classList.toggle('error',isError);
 }
 function clear(){
  section.hidden=true;metrics.replaceChildren();checksBody.replaceChildren();
  specsHolder.replaceChildren();records=[];specs=[];show('로그인 후 확인할 수 있습니다.');
 }
 async function api(method,path,body){
  const token=getAccessToken();
  if(!token)throw Error('로그인해야 서버 기록을 확인할 수 있습니다.');
  const response=await fetch(path,{
   method,cache:'no-store',headers:{
    Authorization:'Bearer '+token,
    ...(body?{'Content-Type':'application/json'}:{}),
   },...(body?{body:JSON.stringify(body)}:{}),
  });
  const result=await response.json().catch(()=>({}));
  if(!response.ok)throw Error(result.error||'운영 기록을 가져오지 못했습니다. (HTTP '+response.status+')');
  return result;
 }
 function renderMetrics(summary){
  if(summary?.schema!=='byteback.operations.v1')throw Error('운영 응답 형식이 맞지 않습니다.');
  const cells=[
   ['판정기 등록 규칙',summary.policyRules?.count+'개 · 코드 등록 (심판 실측 아님)'],
   ['탐지 사건 실측',summary.detector?.observedEventCount===null?'엔진 사건 로그 미연결':'서버 확인 '+summary.detector.observedEventCount+'건'],
   ['9단계 회수 집행',summary.revocation?.engineRevocationCount===null?'운영 엔진 기록 미연결':String(summary.revocation.engineRevocationCount)],
   ['내 기기 승인/대기/회수',[summary.devices?.approved,summary.devices?.pending,summary.devices?.revoked].join(' / ')+'건'],
   ['검증된 정책 백업',summary.recovery?.verified===true?
     summary.recovery.baselineVersion+' · 시험 정책 차이 '+summary.recovery.changedPolicyCount+'건':'검증되지 않음'],
   ['내 계정 복구 감사 기록',summary.recovery?.currentAccountRestoreEvents+'건'],
   ['저장된 안전 HTTP 검사',summary.selfChecks?.recordedCount+'건'],
   ['공식 41종 공격 결과',summary.officialAssault?.importedJudgements===0?
     '0/41건 연동 · 나머지 41건 미확인':'공식 기록 연결 상태 별도 확인'],
  ];
  metrics.replaceChildren(...cells.map(([name,value])=>{
   const item=document.createElement('div');item.className='war-metric';
   item.append(textNode('span',name),textNode('strong',value));
   return item;
  }));
  const commit=byId('war-commit');commit.textContent=summary.commit?.slice(0,12)||'배포 커밋은 /aleph.json에서 확인';
  byId('war-confirmed-at').textContent=dateString(summary.checkedAt);
 }
 function renderChecks(){
  const latest=new Map();
  for(const record of records){
   if(!latest.has(record.probeId))latest.set(record.probeId,record);
  }
  checksBody.replaceChildren();
  specsHolder.replaceChildren();
  for(const spec of specs){
   const row=document.createElement('tr');
   const record=latest.get(spec.id);
   cell(row,'S'+spec.step+' · '+(labels[spec.id]||spec.id));
   cell(row,spec.method+' '+spec.path);
   cell(row,'HTTP '+spec.expectedStatus);
   cell(row,record?.observedStatus===null?'요청 실패':record?.observedStatus!==undefined?
    'HTTP '+record.observedStatus:'미실행');
   cell(row,!record?'미실행':record.passed?'실측 일치':'실측 불일치');
   cell(row,record?.requestId||'—');
   cell(row,dateString(record?.observedAt));
   checksBody.append(row);
   const button=document.createElement('button');
   button.type='button';button.className='secondary war-probe';
   button.textContent=(labels[spec.id]||spec.id)+' 실행';
   button.disabled=busy;
   button.addEventListener('click',async()=>{
    if(busy)return;
    busy=true;specsHolder.querySelectorAll('button').forEach(x=>x.disabled=true);
    show('안전 HTTP 요청을 실제 서버에 전송하고 결과를 기록 중입니다.');
    try{
     const result=await api('POST','/api/war-room-check',{probeId:spec.id});
     if(result.schema!=='byteback.probes.v1')throw Error('검사 결과 형식이 일치하지 않습니다.');
     await refreshAll();
     show('실제 검사 기록: '+(result.passed?'HTTP 예상값 일치':'예상값 불일치')+
      ' · '+result.requestId+' · '+dateString(result.observedAt),!result.passed);
    }catch(err){show('검사 실패: '+err.message,true);}
    finally{busy=false;specsHolder.querySelectorAll('button').forEach(x=>x.disabled=false);}
   });
   specsHolder.append(button);
  }
  // These cases require real authorized participants or the official judge;
  // they must remain not executed until independent evidence is imported.
  for(const [caseName,expected] of [
   ['서명된 승인 기기 정상 메모 조회','본인 메모만 HTTP 200'],
   ['심판 A의 정상 메모 조회','심판 실측 허용'],
   ['심판 B의 A 메모 접근','심판 실측 거부'],
   ['회수된 신원의 재요청','심판 실측 거부'],
   ['복원 뒤 서명 없는 메모 변경','심판 실측 거부'],
   ['복구 후 1~11단계 교차 회귀','심판 종합 판정'],
  ]){
   const row=document.createElement('tr');
   cell(row,caseName);cell(row,'운영 심판/승인 기기');
   cell(row,expected);cell(row,'미실행');cell(row,'미확인');
   cell(row,'—');cell(row,'—');checksBody.append(row);
  }
 }
 async function refreshAll(){
  if(!getAccessToken()){clear();return;}
  section.hidden=false;
  const [summary,history]=await Promise.all([
   api('GET','/api/war-room'),api('GET','/api/war-room-check'),
  ]);
  if(history?.schema!=='byteback.probes.v1'||!Array.isArray(history.specs)||
   !Array.isArray(history.checks))throw Error('검사 기록 응답 형식이 맞지 않습니다.');
  records=history.checks;specs=history.specs;
  renderMetrics(summary);renderChecks();
  show('운영 API 응답 확인 · '+dateString(summary.checkedAt)+
   ' · 공식 41종 총공세 결과는 별도 심판 평가입니다.');
 }
 async function reload(){
  refresh.disabled=true;show('실제 서버 기록을 확인하고 있습니다.');
  try{await refreshAll();}catch(error){metrics.replaceChildren();
    checksBody.replaceChildren();specsHolder.replaceChildren();
    show('운영 기록 조회 실패: '+error.message,true);
  }finally{refresh.disabled=false;}
 }
 refresh.addEventListener('click',()=>{void reload();});
 clear();
 return {clear,refresh:reload};
}
