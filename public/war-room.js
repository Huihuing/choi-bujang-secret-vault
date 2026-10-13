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
 // App-local verified evidence only; does not contradict the
 // independent judge verdict where some attacks have been defeated.
 const row=document.createElement('tr');
 cell(row,'공식 전체 41종 (과제 기준)');
 cell(row,'이 앱의 공식 사건별 검증 기록: 모두 미실행');
 cell(row,'심판 원장 미연결');
 cell(row,'확인된 막음 0건 · 확인된 통과 0건 (앱 증거 기준)');
 cell(row,'실제 공식 판정과 별개');
 body.append(row);
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
  const measured=value=>Number.isSafeInteger(value)&&value>=0
    ? value+'건 (현재 학생 계정 DB 실측)':'미확인 · 서버 실측 자료 없음';
  const deviceNumbers=[summary.devices?.approved,summary.devices?.pending,summary.devices?.revoked];
  const deviceValue=deviceNumbers.every(n=>Number.isSafeInteger(n)&&n>=0)
    ? deviceNumbers.map(String).join(' / ')+'건 (현재 계정 DB 실측)'
    : '미확인 · 기기 DB 측정 없음';
  const codeCount=summary.policyRules?.source==='repository_code_only'
    && Number.isSafeInteger(summary.policyRules.count)
    ? summary.policyRules.count+'개 · 소스코드 선언, 엔진 실측 아님':'미확인';
  const recoveryOk=summary.recovery?.verified===true
    && typeof summary.recovery.baselineVersion==='string'
    && Number.isSafeInteger(summary.recovery.changedPolicyCount);
  const cells=[
   ['판정기 규칙 (코드)',codeCount],
   ['탐지 사건 (운영 실측)','미확인 · 제공 엔진 사건 로그 미연결'],
   ['회수 집행 (운영 실측)','미확인 · 제공 엔진 회수 로그 미연결'],
   ['내 기기 승인 / 대기 / 회수',deviceValue],
   ['검증된 정책 기준 사본',recoveryOk?
     summary.recovery.baselineVersion+' · 시험 정책 차이 '+summary.recovery.changedPolicyCount+'건 (DB 실측)'
      :'미확인 · 검증된 서버 수치 없음'],
   ['내 계정 복구 감사 기록',measured(summary.recovery?.currentAccountRestoreEvents)],
   ['내 계정 안전 HTTP 검사 기록',measured(summary.selfChecks?.recordedCount)],
   ['공식 총공세 확인 기록','41건 미실행 · 막음 0건 · 통과 0건 (이 앱의 공식 증거 확인 기준; 실제 판정 아님)'],
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
