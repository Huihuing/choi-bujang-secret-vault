// 워치독스 개인 PC 읽기 전용 화면. 예시 값·자동 조회·설정 쓰기는 없음.
const byId=id=>document.getElementById(id);
const make=(tag,text,cls)=>{
  const element=document.createElement(tag);
  if(text!==undefined)element.textContent=String(text);
  if(cls)element.className=cls;
  return element;
};
const lastFive=[];
let logData=null;
let logState='idle';
let logError=null;
const validTime=v=>typeof v==='string'&&Number.isFinite(Date.parse(v));
const actual=item=>item?.status==='ok'
  &&(typeof item.value==='string'&&item.value.trim()||typeof item.value==='number'&&Number.isFinite(item.value))
  &&typeof item.source==='string'&&item.source.trim()&&validTime(item.measuredAt);
const validLog=item=>['ok','partial'].includes(item?.status)
  &&[item.warningCount,item.errorCount,item.sampled].every(v=>Number.isSafeInteger(v)&&v>=0)
  &&item.warningCount+item.errorCount===item.sampled&&item.sampled<=1000
  &&validTime(item.measuredAt);
const observed=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))
  ?new Date(v).toLocaleString('ko-KR',{dateStyle:'medium',timeStyle:'medium'}):'측정 시각 확인 불가';
const reason=v=>typeof v==='string'&&v.trim()?v:'조회 실패 이유 확인 불가';
function status(node,message,kind){
  node.textContent=message;node.dataset.state=kind||'idle';
}
function metric(label,item,phase){
  const card=make('article',undefined,'metric');
  card.appendChild(make('h3',label));
  if(phase==='idle'||phase==='loading'){
    card.dataset.state=phase;
    card.appendChild(make('strong',phase==='idle'?'조회 전':'조회 중','metric-value'));
    card.appendChild(make('p',phase==='idle'?'아직 측정하지 않음 · 다시 조회를 눌러 주세요.':'새 측정값을 기다리고 있습니다.','metric-detail'));
    return card;
  }
  const unavailable=!actual(item);
  card.dataset.state=unavailable?'unavailable':'ok';
  if(unavailable){
    card.appendChild(make('strong','확인 불가','metric-value'));
    card.appendChild(make('p',reason(item?.reason),'metric-detail'));
    card.appendChild(make('p','다음 행동: 일반 사용자 조회 권한과 측정 서비스를 확인한 뒤 다시 조회하세요.','metric-detail'));
  }else{
    card.appendChild(make('strong',String(item.value)+' '+(item.unit||''),'metric-value'));
    card.appendChild(make('p',item.detail||'측정 세부 정보 없음','metric-detail'));
  }
  card.appendChild(make('p','출처: '+(item?.source||'확인 불가'),'source'));
  card.appendChild(make('p','측정: '+observed(item?.measuredAt),'time'));
  return card;
}
function putStatusCards(targetId,items,phase){
  const node=byId(targetId);node.replaceChildren(...items.map(([title,value])=>metric(title,value,phase)));
}
function pushHistory(fields){
  if(![fields?.cpu,fields?.memory,fields?.disk].some(actual))return;
  lastFive.unshift({
    at:[fields.cpu,fields.memory,fields.disk].find(actual).measuredAt,
    cpu:actual(fields.cpu)?fields.cpu.value:null,
    memory:actual(fields.memory)?fields.memory.value:null,
    disk:actual(fields.disk)?fields.disk.value:null,
  });
  if(lastFive.length>5)lastFive.length=5;
}
function renderHistory(){
  const list=byId('history-list');list.replaceChildren();
  if(lastFive.length===0){list.appendChild(make('li','실제 측정 기록 없음'));return;}
  for(const [index,sample] of lastFive.entries()){
    const li=make('li',undefined,'history-item');
    li.appendChild(make('span',observed(sample.at),'history-at'));
    const parts=[
      sample.cpu===null?'CPU 확인 불가':'CPU '+sample.cpu+' %',
      sample.memory===null?'메모리 확인 불가':'메모리 '+sample.memory+' GiB',
      sample.disk===null?'디스크 확인 불가':'디스크 여유 '+sample.disk+' GiB',
    ];
    li.appendChild(make('strong',parts.join(' · '),'history-reading'));
    if(index===0&&lastFive.length>1&&Number.isFinite(sample.cpu)&&Number.isFinite(lastFive[1].cpu)){
      const delta=Math.round((sample.cpu-lastFive[1].cpu)*10)/10;
      li.appendChild(make('small','직전 측정 대비 CPU '+(delta>=0?'+':'')+delta+' %p','history-delta'));
    }
    list.appendChild(li);
  }
}
function renderPc(data){
  const fields=data?.fields||{};
  putStatusCards('pc-cards',[
    ['CPU 사용률',fields.cpu],
    ['메모리 사용량',fields.memory],
    ['디스크 남은 공간',fields.disk],
  ]);
  pushHistory(fields);renderHistory();
  const count=[fields.cpu,fields.memory,fields.disk].filter(actual).length;
  status(byId('pc-status'),'실제 조회: '+count+'개 확인 / 3개 항목 · 요청 완료 '+observed(data?.queriedAt),count===3?'ok':count===0?'error':'partial');
}
function eventCard(name,data){
  const card=make('article',undefined,'event-card');
  card.appendChild(make('h3',name+' · Windows 기록'));
  if(!validLog(data)){
    card.dataset.state='unavailable';
    card.appendChild(make('strong','확인 불가'));
    card.appendChild(make('p',reason(data?.reason)));
    card.appendChild(make('p','다음 행동: 일반 사용자 로그 읽기 권한을 확인한 뒤 네트워크·방화벽을 다시 조회하세요.'));
  }else{
    card.dataset.state=data.status==='partial'?'partial':'ok';
    const title=data.status==='partial'?'최대 1000개 표본(전체 아님)':'최근 24시간 조회';
    card.appendChild(make('p',title,'event-scope'));
    card.appendChild(make('strong','경고 '+data.warningCount+'건 · 오류 '+data.errorCount+'건'));
    if(data.status==='partial')card.appendChild(make('p','전체 건수 확인 불가 · '+reason(data.reason)));
  }
  card.appendChild(make('p','출처: '+(data?.source||'Get-WinEvent'),'source'));
  card.appendChild(make('p','측정: '+observed(data?.measuredAt),'time'));
  return card;
}
function renderEvents(){
  const holder=byId('event-cards'),kind=byId('event-filter').value;
  holder.replaceChildren();
  if(!logData){
    const message=logState==='loading'?'Windows 이벤트 기록 조회 중':logState==='error'
      ?'Windows 기록 확인 불가: '+reason(logError)+' · 일반 사용자 조회 권한과 로컬 측정 도구를 확인한 뒤 다시 조회하세요.'
      :'아직 Windows 이벤트 기록을 조회하지 않았습니다.';
    holder.appendChild(make('p',message,'empty'));return;
  }
  for(const name of ['System','Application']){
    if(kind==='all'||kind===name)holder.appendChild(eventCard(name,logData[name]));
  }
}
function renderNetwork(data){
  const fields=data?.fields||{};
  putStatusCards('network-cards',[
    ['물리 네트워크 연결',fields.network],
    ['Windows 방화벽 프로필',fields.firewall],
  ]);
  logData=fields.logs||{};
  logState='ready';logError=null;
  renderEvents();
  const count=[fields.network,fields.firewall].filter(actual).length;
  const logs=[logData.System,logData.Application];
  const logCount=logs.filter(validLog).length;
  const complete=count===2&&logs.every(x=>validLog(x)&&x.status==='ok');
  status(byId('network-status'),'실제 Windows 조회: '+count+'개 확인 / 2개 구성 · 기록 '+logCount+'개 확인 / 2개 로그 · 요청 완료 '+observed(data?.queriedAt),complete?'ok':count===0&&logCount===0?'error':'partial');
}
async function get(path){
  let response;
  try{
    response=await fetch(path,{method:'GET',cache:'no-store',credentials:'omit'});
  }catch{return{ok:false,error:{code:'NETWORK_FAILURE',message:'로컬 측정 서비스에 접속하지 못했습니다.'}};}
  try{
    const payload=await response.json();
    if(response.ok&&payload?.ok===true)return payload;
    return{ok:false,error:payload?.error||{code:'RESPONSE_ERROR',message:'조회 응답 확인 불가'}};
  }catch{return{ok:false,error:{code:'INVALID_RESPONSE',message:'조회 자료를 읽지 못했습니다.'}};}
}
async function refreshPc(){
  const button=byId('refresh-pc');button.disabled=true;
  putStatusCards('pc-cards',[['CPU 사용률',null],['메모리 사용량',null],['디스크 남은 공간',null]],'loading');
  status(byId('pc-status'),'조회 중 · 실제 Windows 값을 새로 읽는 중…','loading');
  try{
    const result=await get('/api/pc');
    if(result.ok&&result.data?.schema==='watchdogs.local-monitor.v1'&&result.data.sampleType==='measured'&&result.data.section==='pc'){
      renderPc(result.data);
    }else{
      putStatusCards('pc-cards',[
        ['CPU 사용률',{reason:reason(result.error?.message)}],['메모리 사용량',{reason:reason(result.error?.message)}],['디스크 남은 공간',{reason:reason(result.error?.message)}],
      ]);
      status(byId('pc-status'),'확인 불가: '+reason(result.error?.message)+' · Windows 권한/측정 서비스 상태를 확인한 뒤 다시 조회하세요.','error');
    }
  }finally{button.disabled=false;}
}
async function refreshNetwork(){
  const button=byId('refresh-network');button.disabled=true;
  putStatusCards('network-cards',[['물리 네트워크 연결',null],['Windows 방화벽 프로필',null]],'loading');
  logData=null;logState='loading';logError=null;renderEvents();
  status(byId('network-status'),'조회 중 · 네트워크·방화벽·Windows 기록을 읽는 중…','loading');
  status(byId('sdp-status'),'기존 보안 Agent SDP 연결 상태를 읽는 중…','loading');
  try{
    const [actual,sdp]=await Promise.all([get('/api/network'),get('/api/sdp')]);
    if(actual.ok&&actual.data?.schema==='watchdogs.local-monitor.v1'&&actual.data.sampleType==='measured'&&actual.data.section==='network'){
      renderNetwork(actual.data);
    }else{
      putStatusCards('network-cards',[['물리 네트워크 연결',{reason:reason(actual.error?.message)}],['Windows 방화벽 프로필',{reason:reason(actual.error?.message)}]]);
      logData=null;logState='error';logError=actual.error?.message;renderEvents();
      status(byId('network-status'),'확인 불가: '+reason(actual.error?.message)+' · 읽기 권한을 확인하고 다시 조회하세요.','error');
    }
    if(sdp.ok){
      status(byId('sdp-status'),sdp.data.label+' · 측정: '+observed(sdp.data.checkedAt)+' · 출처: '+sdp.data.source,
        sdp.data.mode==='connected'?'ok':'partial');
    }else{
      status(byId('sdp-status'),'SDP 상태 확인 불가: '+reason(sdp.error?.message)+' · 기존 워치독스 앱의 연결 표시를 따로 확인하세요.','error');
    }
  }finally{button.disabled=false;}
}
byId('refresh-pc').addEventListener('click',refreshPc);
byId('refresh-network').addEventListener('click',refreshNetwork);
byId('event-filter').addEventListener('change',renderEvents);
putStatusCards('pc-cards',[['CPU 사용률',null],['메모리 사용량',null],['디스크 남은 공간',null]],'idle');
putStatusCards('network-cards',[['물리 네트워크 연결',null],['Windows 방화벽 프로필',null]],'idle');
