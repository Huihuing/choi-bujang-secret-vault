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
const observed=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))
  ?new Date(v).toLocaleString('ko-KR',{dateStyle:'medium',timeStyle:'medium'}):'측정 시각 확인 불가';
const reason=v=>typeof v==='string'&&v.trim()?v:'조회 실패 이유 확인 불가';
function status(node,message,kind){
  node.textContent=message;node.dataset.state=kind||'idle';
}
function metric(label,item){
  const card=make('article',undefined,'metric');
  const unavailable=!item||item.status!=='ok'
    ||!(typeof item.value==='string'||(typeof item.value==='number'&&Number.isFinite(item.value)));
  card.dataset.state=unavailable?'unavailable':'ok';
  card.appendChild(make('h3',label));
  if(unavailable){
    card.appendChild(make('strong','확인 불가','metric-value'));
    card.appendChild(make('p',reason(item?.reason),'metric-detail'));
  }else{
    card.appendChild(make('strong',String(item.value)+' '+(item.unit||''),'metric-value'));
    card.appendChild(make('p',item.detail||'측정 세부 정보 없음','metric-detail'));
  }
  card.appendChild(make('p','출처: '+(item?.source||'확인 불가'),'source'));
  card.appendChild(make('p','측정: '+observed(item?.measuredAt),'time'));
  return card;
}
function putStatusCards(targetId,items){
  const node=byId(targetId);node.replaceChildren(...items.map(([title,value])=>metric(title,value)));
}
function pushHistory(fields){
  if(fields?.cpu?.status!=='ok' && fields?.memory?.status!=='ok' && fields?.disk?.status!=='ok')return;
  lastFive.unshift({
    at:fields.cpu?.measuredAt||fields.memory?.measuredAt||fields.disk?.measuredAt,
    cpu:fields.cpu?.status==='ok'?fields.cpu.value:null,
    memory:fields.memory?.status==='ok'?fields.memory.value:null,
    disk:fields.disk?.status==='ok'?fields.disk.value:null,
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
  const count=[fields.cpu,fields.memory,fields.disk].filter(x=>x?.status==='ok').length;
  status(byId('pc-status'),'실제 조회: '+count+'개 확인 / 3개 항목 · 요청 완료 '+observed(data?.queriedAt),count===3?'ok':'partial');
}
function eventCard(name,data){
  const card=make('article',undefined,'event-card');
  card.appendChild(make('h3',name+' · Windows 기록'));
  if(!data||data.status==='unavailable'){
    card.dataset.state='unavailable';
    card.appendChild(make('strong','확인 불가'));
    card.appendChild(make('p',reason(data?.reason)));
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
  if(!logData){holder.appendChild(make('p','아직 Windows 이벤트 기록을 조회하지 않았습니다.','empty'));return;}
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
  logData=fields.logs||null;
  renderEvents();
  const count=[fields.network,fields.firewall].filter(x=>x?.status==='ok').length;
  status(byId('network-status'),'실제 Windows 조회: '+count+'개 확인 / 2개 구성 · 요청 완료 '+observed(data?.queriedAt),count===2?'ok':'partial');
}
async function get(path){
  let response;
  try{
    response=await fetch(path,{method:'GET',cache:'no-store',credentials:'omit'});
  }catch{return{ok:false,error:{code:'NETWORK_FAILURE',message:'로컬 측정 서비스에 접속하지 못했습니다.'}};}
  try{
    const payload=await response.json();
    if(payload?.ok===true)return payload;
    return{ok:false,error:payload?.error||{code:'RESPONSE_ERROR',message:'조회 응답 확인 불가'}};
  }catch{return{ok:false,error:{code:'INVALID_RESPONSE',message:'조회 자료를 읽지 못했습니다.'}};}
}
async function refreshPc(){
  const button=byId('refresh-pc');button.disabled=true;
  status(byId('pc-status'),'실제 Windows 값을 새로 읽는 중…','loading');
  try{
    const result=await get('/api/pc');
    if(result.ok&&result.data?.schema==='watchdogs.local-monitor.v1'&&result.data.section==='pc'){
      renderPc(result.data);
    }else{
      putStatusCards('pc-cards',[
        ['CPU 사용률',null],['메모리 사용량',null],['디스크 남은 공간',null],
      ]);
      status(byId('pc-status'),'확인 불가: '+reason(result.error?.message)+' · Windows 권한/측정 서비스 상태를 확인한 뒤 다시 조회하세요.','error');
    }
  }finally{button.disabled=false;}
}
async function refreshNetwork(){
  const button=byId('refresh-network');button.disabled=true;
  status(byId('network-status'),'네트워크·방화벽·Windows 기록을 읽는 중…','loading');
  status(byId('sdp-status'),'기존 보안 Agent SDP 연결 상태를 읽는 중…','loading');
  try{
    const [actual,sdp]=await Promise.all([get('/api/network'),get('/api/sdp')]);
    if(actual.ok&&actual.data?.schema==='watchdogs.local-monitor.v1'&&actual.data.section==='network'){
      renderNetwork(actual.data);
    }else{
      putStatusCards('network-cards',[['물리 네트워크 연결',null],['Windows 방화벽 프로필',null]]);
      logData=null;
      const eventArea=byId('event-cards');
      eventArea.replaceChildren(make('p','Windows 기록 확인 불가: '+reason(actual.error?.message)+' · 일반 사용자 조회 권한과 로컬 측정 도구를 확인한 뒤 다시 조회하세요.','empty'));
      status(byId('network-status'),'확인 불가: '+reason(actual.error?.message)+' · 읽기 권한을 확인하고 다시 조회하세요.','error');
    }
    if(sdp.ok){
      status(byId('sdp-status'),sdp.data.label+' · 측정: '+observed(sdp.data.checkedAt)+' · 출처: '+sdp.data.source,
        sdp.data.mode==='disconnected'?'partial':'ok');
    }else{
      status(byId('sdp-status'),'SDP 상태 확인 불가: '+reason(sdp.error?.message)+' · 기존 워치독스 앱의 연결 표시를 따로 확인하세요.','error');
    }
  }finally{button.disabled=false;}
}
byId('refresh-pc').addEventListener('click',refreshPc);
byId('refresh-network').addEventListener('click',refreshNetwork);
byId('event-filter').addEventListener('change',renderEvents);
putStatusCards('pc-cards',[['CPU 사용률',null],['메모리 사용량',null],['디스크 남은 공간',null]]);
putStatusCards('network-cards',[['물리 네트워크 연결',null],['Windows 방화벽 프로필',null]]);
