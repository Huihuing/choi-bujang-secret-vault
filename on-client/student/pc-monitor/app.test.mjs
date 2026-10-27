// 합성 응답과 최소 DOM만 사용하는 UI 모의 검사입니다.
// Windows 측정, 실제 브라우저 조작, 네트워크 요청 또는 SDP 운영 검증이 아닙니다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const source=await readFile(new URL('./app.js',import.meta.url),'utf8');
const html=await readFile(new URL('./index.html',import.meta.url),'utf8');
const at='2026-10-26T01:02:03.000Z';

class Element {
  constructor(tag='div'){
    this.tagName=tag.toUpperCase();this.children=[];this.dataset={};
    this.className='';this.disabled=false;this.value='';this.listeners=new Map();
    this.attributes=new Map();this.text='';
  }
  set textContent(value){this.text=String(value??'');this.children=[];}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join('');}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(...children){this.text='';this.children=[...children];}
  setAttribute(name,value){this.attributes.set(name,String(value));}
  getAttribute(name){return this.attributes.get(name)??null;}
  addEventListener(name,listener){
    const list=this.listeners.get(name)||[];list.push(listener);this.listeners.set(name,list);
  }
  async emit(name){
    await Promise.all((this.listeners.get(name)||[]).map(listener=>listener({target:this})));
  }
}

function harness({hosted=false}={}){
  const nodes=new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>[id,new Element()]));
  nodes.get('event-filter').value='all';
  nodes.get('timeline-filter').value='all';
  const requests=[];
  const replies=new Map();
  const context=vm.createContext({
    document:{
      documentElement:{dataset:{watchdogsHosted:hosted?'true':'false'}},
      getElementById(id){assert.ok(nodes.has(id),'알려진 화면 요소: '+id);return nodes.get(id);},
      createElement(tag){return new Element(tag);},
    },
    fetch:async(path,options)=>{
      requests.push({path,options});
      const queue=replies.get(path)||[];
      assert.ok(queue.length,'준비한 모의 응답만 사용: '+path);
      const next=queue.shift();
      if(next instanceof Error)throw next;
      const payload=await next;
      return{ok:payload?.ok===true,status:payload?.ok===true?200:503,json:async()=>payload};
    },
  });
  vm.runInContext(source,context,{filename:'app.js'});
  return{
    nodes,requests,
    node:id=>nodes.get(id),
    queue(path,...payloads){replies.set(path,[...(replies.get(path)||[]),...payloads]);},
    click:id=>nodes.get(id).emit('click'),
    filter:async value=>{nodes.get('event-filter').value=value;await nodes.get('event-filter').emit('change');},
    timeline:async value=>{nodes.get('timeline-filter').value=value;await nodes.get('timeline-filter').emit('change');},
  };
}

const field=(value,unit,sourceName='모의 Windows 출처')=>({
  status:'ok',value,unit,source:sourceName,measuredAt:at,reason:null,detail:'모의 측정 세부 정보',
});
const missing=(reason='모의 읽기 권한 부족')=>({
  status:'unavailable',value:null,unit:null,source:'모의 Windows 출처',measuredAt:at,reason,detail:null,
});
const log=(overrides={})=>({
  status:'ok',errorCount:1,warningCount:2,sampled:3,limit:1000,windowHours:24,
  measuredAt:at,source:'Get-WinEvent',reason:null,...overrides,
});
const pc=(fields={})=>({ok:true,data:{
  schema:'watchdogs.local-monitor.v1',section:'pc',sampleType:'measured',queriedAt:at,
  fields:{cpu:field(12.5,'%','Win32_Processor.LoadPercentage'),memory:field(4.25,'GiB'),disk:field(100.75,'GiB'),...fields},
}});
const network=(fields={})=>({ok:true,data:{
  schema:'watchdogs.local-monitor.v1',section:'network',sampleType:'measured',queriedAt:at,
  fields:{network:field(1,'개'),firewall:field('조회됨','프로필'),logs:{System:log(),Application:log()},...fields},
}});
const sdp=(mode='disconnected')=>({ok:true,data:{mode,label:mode==='demo'?'예제(demo) · 실제 SDP 연결 아님':'SDP 미연결',checkedAt:at,source:'모의 진단'}});
const failure=(message='모의 수집 시간 초과')=>({ok:false,error:{code:'MOCK_FAILURE',message}});
const cards=(h,id)=>h.node(id).children;
const content=(h,id)=>h.node(id).textContent;
const localAt=new Date(at).toLocaleString('ko-KR',{dateStyle:'medium',timeStyle:'medium'});

test('모의 UI: 처음에는 조회 전이며 자동 요청이나 실패 이유를 표시하지 않는다',()=>{
  const h=harness();
  assert.equal(h.requests.length,0);
  for(const id of ['pc-cards','network-cards']){
    for(const card of cards(h,id)){
      assert.equal(card.dataset.state,'idle');
      assert.match(card.textContent,/조회 전/);
      assert.match(card.textContent,/아직 측정하지 않음/);
      assert.doesNotMatch(card.textContent,/확인 불가|조회 실패 이유/);
    }
  }
});

test('모의 UI: PC 성공 응답의 값·단위·출처·시각을 표시하고 버튼을 복구한다',async()=>{
  const h=harness();h.queue('/api/pc',pc());await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'ok');
  assert.match(content(h,'pc-cards'),/12\.5 %/);
  assert.match(content(h,'pc-cards'),/4\.25 GiB/);
  assert.match(content(h,'pc-cards'),/100\.75 GiB/);
  assert.match(content(h,'pc-cards'),/Win32_Processor\.LoadPercentage/);
  assert.ok(content(h,'pc-cards').includes(localAt));
  assert.equal(h.node('refresh-pc').disabled,false);
  assert.equal(h.requests[0].options.method,'GET');
  assert.equal(h.requests[0].options.credentials,'omit');
});

test('모의 UI: PC 재조회 중에는 이전 현재값을 지우고 로딩과 버튼 잠금을 표시한다',async()=>{
  const h=harness();h.queue('/api/pc',pc());await h.click('refresh-pc');
  let release;h.queue('/api/pc',new Promise(resolve=>{release=resolve;}));
  const pending=h.click('refresh-pc');
  assert.equal(h.node('refresh-pc').disabled,true);
  assert.equal(h.node('pc-status').dataset.state,'loading');
  assert.doesNotMatch(content(h,'pc-cards'),/12\.5 %|4\.25 GiB|100\.75 GiB/);
  assert.match(content(h,'pc-cards'),/조회 중/);
  release(pc());await pending;
  assert.equal(h.node('refresh-pc').disabled,false);
});

test('모의 UI: PC 일부 실패는 partial이며 항목별 사유를 보존한다',async()=>{
  const h=harness();h.queue('/api/pc',pc({memory:missing('모의 메모리 조회 거부')}));
  await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'partial');
  assert.match(content(h,'pc-cards'),/12\.5 %/);
  assert.match(content(h,'pc-cards'),/모의 메모리 조회 거부/);
  assert.doesNotMatch(content(h,'pc-cards'),/4\.25 GiB/);
});

test('모의 UI: PC 세 항목 모두 확인 불가면 error이며 이력을 만들지 않는다',async()=>{
  const h=harness();h.queue('/api/pc',pc({cpu:missing(),memory:missing(),disk:missing()}));
  await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'error');
  assert.doesNotMatch(content(h,'history-list'),/CPU \d/);
});

test('모의 UI: PC API 실패 이유를 카드와 상태에 남기고 이전 값을 제거한다',async()=>{
  const h=harness();h.queue('/api/pc',pc(),failure('모의 WMI 도구 시작 실패'));
  await h.click('refresh-pc');await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'error');
  assert.match(content(h,'pc-status'),/모의 WMI 도구 시작 실패/);
  assert.match(content(h,'pc-cards'),/모의 WMI 도구 시작 실패/);
  assert.doesNotMatch(content(h,'pc-cards'),/12\.5 %/);
  assert.equal(h.node('refresh-pc').disabled,false);
});

test('모의 UI: 실제 fetch 대신 주입한 접속 예외도 실패 후 버튼을 복구한다',async()=>{
  const h=harness();h.queue('/api/pc',new Error('모의 연결 끊김'));await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'error');
  assert.match(content(h,'pc-status'),/로컬 측정 서비스에 접속하지 못했습니다/);
  assert.equal(h.node('refresh-pc').disabled,false);
});

test('모의 UI: 재조회 성공으로 실패 상태와 실패 사유를 교체한다',async()=>{
  const h=harness();h.queue('/api/pc',failure('모의 최초 실패'),pc());
  await h.click('refresh-pc');await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'ok');
  assert.doesNotMatch(content(h,'pc-cards'),/모의 최초 실패/);
  assert.match(content(h,'pc-cards'),/12\.5 %/);
});

test('모의 UI: PC 최근 이력은 성공한 최대 5회이며 CPU 변화는 %p다',async()=>{
  const h=harness();
  h.queue('/api/pc',...[10,11,12,13,14,15].map(value=>pc({cpu:field(value,'%')})));
  for(let i=0;i<6;i++)await h.click('refresh-pc');
  const items=cards(h,'history-list');
  assert.equal(items.length,5);
  assert.match(items[0].textContent,/CPU 15 %/);
  assert.match(items[0].textContent,/\+1 %p/);
  assert.doesNotMatch(content(h,'history-list'),/CPU 10 %/);
});

test('모의 UI: 네트워크와 두 이벤트 로그가 성공하면 Windows 조회는 ok다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',sdp());
  await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'ok');
  assert.match(content(h,'network-cards'),/1 개/);
  assert.equal(cards(h,'event-cards').length,2);
  assert.match(content(h,'event-cards'),/경고 2건 · 오류 1건/);
  assert.equal(h.node('sdp-status').dataset.state,'partial');
  assert.match(content(h,'sdp-status'),/SDP 미연결/);
  assert.equal(h.node('refresh-network').disabled,false);
});

test('모의 UI: 네트워크 재조회 로딩은 이전 현재값과 이벤트 값을 제거한다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',sdp());
  await h.click('refresh-network');
  let release;h.queue('/api/network',new Promise(resolve=>{release=resolve;}));h.queue('/api/sdp',sdp());
  const pending=h.click('refresh-network');
  assert.equal(h.node('refresh-network').disabled,true);
  assert.equal(h.node('network-status').dataset.state,'loading');
  assert.doesNotMatch(content(h,'network-cards'),/1 개|조회됨 프로필/);
  assert.doesNotMatch(content(h,'event-cards'),/경고 2건 · 오류 1건/);
  release(network());await pending;
  assert.equal(h.node('refresh-network').disabled,false);
});

test('모의 UI: 네트워크 성공이어도 이벤트 로그 실패가 있으면 partial이다',async()=>{
  const h=harness();
  h.queue('/api/network',network({logs:{System:log({status:'unavailable',errorCount:null,warningCount:null,sampled:null,reason:'모의 System 권한 부족'}),Application:log()}}));
  h.queue('/api/sdp',sdp());await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'partial');
  assert.match(content(h,'event-cards'),/모의 System 권한 부족/);
  assert.doesNotMatch(content(h,'event-cards'),/경고 null건|오류 null건/);
});

test('모의 UI: 1000건 상한 이벤트는 partial과 전체 건수 확인 불가를 표시한다',async()=>{
  const h=harness();
  h.queue('/api/network',network({logs:{System:log({status:'partial',errorCount:400,warningCount:600,sampled:1000,reason:'모의 표본 상한'}),Application:log()}}));
  h.queue('/api/sdp',sdp());await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'partial');
  assert.match(content(h,'event-cards'),/전체 건수 확인 불가/);
  assert.match(content(h,'event-cards'),/모의 표본 상한/);
});

test('모의 UI: 이벤트 필터는 종류를 고르며 추가 조회를 실행하지 않는다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',sdp());
  await h.click('refresh-network');const count=h.requests.length;
  await h.filter('Application');
  assert.equal(cards(h,'event-cards').length,1);
  assert.match(content(h,'event-cards'),/Application/);
  assert.doesNotMatch(content(h,'event-cards'),/System/);
  assert.equal(h.requests.length,count);
});

test('모의 UI: 네트워크 API 실패 뒤 이벤트 필터를 바꿔도 실패 이유를 유지한다',async()=>{
  const h=harness();h.queue('/api/network',failure('모의 Windows 기록 시간 초과'));h.queue('/api/sdp',sdp());
  await h.click('refresh-network');
  await h.filter('System');
  assert.equal(h.node('network-status').dataset.state,'error');
  assert.match(content(h,'event-cards'),/모의 Windows 기록 시간 초과/);
  assert.doesNotMatch(content(h,'event-cards'),/아직.*조회하지|조회 전/);
  assert.equal(h.node('refresh-network').disabled,false);
});

test('모의 UI: SDP demo를 실제 연결 성공 상태로 표시하지 않는다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',sdp('demo'));
  await h.click('refresh-network');
  assert.equal(h.node('sdp-status').dataset.state,'partial');
  assert.match(content(h,'sdp-status'),/실제 SDP 연결 아님/);
});

test('모의 UI: SDP 조회 실패는 Windows 조회 성공과 독립적으로 표시한다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',failure('모의 SDP 서버 미실행'));
  await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'ok');
  assert.equal(h.node('sdp-status').dataset.state,'error');
  assert.match(content(h,'sdp-status'),/모의 SDP 서버 미실행/);
});

test('모의 타임라인: 조회 전 빈 기록과 세 기능 진입을 제공하고 자동 수집하지 않는다',()=>{
  const h=harness();
  assert.equal(h.requests.length,0);
  assert.match(content(h,'timeline-summary'),/아직 조회한 기록이 없습니다/);
  assert.match(content(h,'timeline-list'),/첫 기록/);
  assert.match(html,/aria-label="핵심 기능 3가지"/);
  assert.match(html,/href="#timeline"/);
  assert.match(html,/href="#pc"/);
  assert.match(html,/href="#network"/);
});

test('모의 타임라인: 실패와 복구 모두 보존하고 현재 수치와 과거 기록을 구분한다',async()=>{
  const h=harness();h.queue('/api/pc',pc(),failure('모의 WMI 연결 실패'),pc({cpu:field(20,'%')}));
  await h.click('refresh-pc');await h.click('refresh-pc');
  let rows=cards(h,'timeline-list');
  assert.equal(rows.length,2);
  assert.equal(rows[0].dataset.state,'error');
  assert.match(rows[0].textContent,/확인 불가.*모의 WMI 연결 실패/);
  assert.doesNotMatch(rows[0].textContent,/CPU 12\.5/);
  assert.match(rows[1].textContent,/CPU 12\.5 %/);
  assert.doesNotMatch(content(h,'pc-cards'),/12\.5 %/);
  await h.click('refresh-pc');rows=cards(h,'timeline-list');
  assert.equal(rows.length,3);
  assert.equal(rows[0].dataset.state,'ok');
  assert.match(rows[0].textContent,/CPU 20 %/);
  assert.equal(rows[1].dataset.state,'error');
  assert.doesNotMatch(content(h,'pc-cards'),/모의 WMI 연결 실패/);
  assert.match(rows[0].textContent,/조회 완료/);
  assert.ok(rows[0].textContent.includes('CPU 측정: '+localAt));
});

test('모의 타임라인: PC 일부 확인 불가와 로그 표본 상한을 정상으로 바꾸지 않는다',async()=>{
  const h=harness();
  h.queue('/api/pc',pc({memory:missing('모의 메모리 권한 부족')}));
  await h.click('refresh-pc');
  assert.equal(cards(h,'timeline-list')[0].dataset.state,'partial');
  assert.match(content(h,'timeline-list'),/메모리 확인 불가 · 모의 메모리 권한 부족/);
  h.queue('/api/network',network({logs:{System:log({status:'partial',errorCount:400,warningCount:600,sampled:1000}),Application:log()}}));
  h.queue('/api/sdp',sdp());await h.click('refresh-network');await h.timeline('events');
  const rows=cards(h,'timeline-list');
  assert.equal(rows.length,1);
  assert.equal(rows[0].dataset.state,'partial');
  assert.match(rows[0].textContent,/최대 1000개 표본, 전체 건수 확인 불가/);
  assert.match(rows[0].textContent,/침해·공격 탐지 결과가 아닙니다/);
});

test('모의 타임라인: 종류 필터와 빈 결과는 원래 기록을 바꾸거나 새 요청하지 않는다',async()=>{
  const h=harness();h.queue('/api/pc',pc());await h.click('refresh-pc');
  h.queue('/api/network',network());h.queue('/api/sdp',sdp());await h.click('refresh-network');
  const requests=h.requests.length;
  await h.timeline('events');
  assert.equal(cards(h,'timeline-list').length,1);
  assert.match(content(h,'timeline-list'),/Windows 기록/);
  assert.doesNotMatch(content(h,'timeline-list'),/CPU 12\.5 %/);
  await h.timeline('sdp');
  assert.equal(cards(h,'timeline-list')[0].dataset.state,'disconnected');
  assert.match(content(h,'timeline-list'),/SDP 미연결/);
  assert.doesNotMatch(content(h,'timeline-list'),/실제 조회/);
  await h.timeline('all');assert.equal(cards(h,'timeline-list').length,4);
  assert.equal(h.requests.length,requests);
  const empty=harness();empty.queue('/api/pc',pc());await empty.click('refresh-pc');await empty.timeline('events');
  assert.match(content(empty,'timeline-list'),/선택한 종류의 조회 기록이 없습니다/);
});

test('모의 타임라인: 20건 상한·완료순 정렬·새 탭 초기화를 지킨다',async()=>{
  const h=harness();h.queue('/api/pc',...Array.from({length:22},(_,index)=>pc({cpu:field(index,'%')})));
  for(let index=0;index<22;index++)await h.click('refresh-pc');
  const rows=cards(h,'timeline-list');
  assert.equal(rows.length,20);
  assert.match(rows[0].textContent,/CPU 21 %/);
  assert.match(rows[19].textContent,/CPU 2 %/);
  assert.match(content(h,'timeline-summary'),/최근 20건 중 20건/);
  assert.match(content(harness(),'timeline-summary'),/아직 조회한 기록이 없습니다/);
});

test('모의 타임라인: 요청 시작 순서 대신 실제 완료 순서를 기록한다',async()=>{
  const h=harness();let release;
  h.queue('/api/pc',new Promise(resolve=>{release=resolve;}));
  const pending=h.click('refresh-pc');
  h.queue('/api/network',network());h.queue('/api/sdp',sdp('demo'));await h.click('refresh-network');
  release(pc());await pending;
  const rows=cards(h,'timeline-list');
  assert.equal(rows[0].dataset.kind,'pc');
  assert.equal(rows[1].dataset.kind,'sdp');
  assert.equal(rows[1].dataset.state,'demo');
  assert.match(rows[1].textContent,/실제 SDP 연결 아님/);
});

test('모의 타임라인: SDP 응답 형식이 틀려도 PC 조회와 구별하고 버튼을 복구한다',async()=>{
  const h=harness();h.queue('/api/network',network());h.queue('/api/sdp',{ok:true,data:{mode:'connected'}});
  await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'ok');
  assert.equal(h.node('sdp-status').dataset.state,'error');
  assert.equal(h.node('refresh-network').disabled,false);
  await h.timeline('sdp');
  assert.equal(cards(h,'timeline-list')[0].dataset.state,'error');
  assert.doesNotMatch(content(h,'timeline-list'),/어댑터 구성됨/);
});

test('모의 웹 연결: 웹 화면도 자동 조회하지 않고 수동 GET만 내 PC의 고정 주소로 보낸다',async()=>{
  const h=harness({hosted:true});
  assert.equal(h.requests.length,0);
  assert.equal(h.node('connection-help').hidden,false);
  assert.match(content(h,'local-connection'),/자료실 서버로 보내지 않습니다/);
  h.queue('http://127.0.0.1:5191/api/pc',pc());await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'ok');
  assert.equal(h.requests[0].path,'http://127.0.0.1:5191/api/pc');
  const options=h.requests[0].options;
  assert.equal(options.method,'GET');assert.equal(options.credentials,'omit');
  assert.equal(options.cache,'no-store');assert.equal(options.mode,'cors');
  assert.equal(options.redirect,'error');assert.equal(options.referrerPolicy,'no-referrer');
  assert.deepEqual(Object.keys(options.headers),['Accept']);
  assert.equal(options.headers.Accept,'application/json');
  assert.equal(options.body,undefined);
});

test('모의 웹 연결: PC 값과 SDP는 원격 자료실 API를 거치지 않는다',async()=>{
  const h=harness({hosted:true});
  h.queue('http://127.0.0.1:5191/api/network',network());h.queue('http://127.0.0.1:5191/api/sdp',sdp());
  await h.click('refresh-network');
  assert.equal(h.node('network-status').dataset.state,'ok');
  assert.match(content(h,'sdp-status'),/SDP 미연결/);
  assert.deepEqual(h.requests.map(request=>request.path),[
    'http://127.0.0.1:5191/api/network','http://127.0.0.1:5191/api/sdp',
  ]);
  for(const request of h.requests)assert.equal(request.options.credentials,'omit');
});

test('모의 웹 연결: 로컬 실행/권한 거부는 확인 불가와 다음 행동으로 남긴다',async()=>{
  const h=harness({hosted:true});h.queue('http://127.0.0.1:5191/api/pc',new Error('모의 로컬 네트워크 권한 거부'));
  await h.click('refresh-pc');
  assert.equal(h.node('pc-status').dataset.state,'error');
  assert.match(content(h,'pc-status'),/측정기 실행과 브라우저의 로컬 네트워크 접근 허용/);
  assert.match(content(h,'timeline-list'),/확인 불가/);
  assert.doesNotMatch(content(h,'pc-cards'),/12\.5 %/);
  assert.equal(h.node('refresh-pc').disabled,false);
  assert.equal(harness().node('connection-help').hidden,true);
});
