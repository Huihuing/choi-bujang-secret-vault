// Public, read-only operational evidence. Never loads note bodies or user data.
// All counts on this panel are taken directly from an authenticated server-to-DB
// aggregate read and are not a stand-in for ALEPH SDP's official judge results.
const $=id=>document.getElementById(id);
const panel=$('war-public-metrics');
const status=$('war-public-status');
const stamp=$('war-public-time');
const commit=$('war-public-commit');
const button=$('war-public-refresh');
function formatCount(v){
 return Number.isSafeInteger(v)&&v>=0?v+'건 (DB 집계)':'미확인';
}
function cell(label,value){
 const div=document.createElement('div');
 div.className='war-metric';
 const title=document.createElement('span');title.textContent=label;
 const number=document.createElement('strong');number.textContent=value;
 div.append(title,number);return div;
}
export function publicMetrics(data){
 if(data?.schema!=='byteback.public-operations.v1'||
   data.source!=='server_database_aggregate')throw Error('서버 기록 형식 불일치');
 const dev=data.deviceState,rec=data.recovery,probes=data.safeHttpChecks;
 if(!dev||!rec||!probes)return null;
 const signed=Number.isSafeInteger(data.policyRules?.declaredInSource)
  ? data.policyRules.declaredInSource+'개 (소스 선언, 엔진 검증 아님)':'미확인';
 return [
  ['판정 규칙',signed],
  ['탐지 사건 (제공 엔진)','미확인 · 운영 사건 로그 미연결'],
  ['회수 집행 (제공 엔진)','미확인 · 운영 회수 로그 미연결'],
  ['기기 승인 / 대기 / 회수',
    [dev.approved,dev.pending,dev.revoked].map(formatCount).join(' / ')],
  ['검증된 기준 백업',typeof rec.version==='string'?
    rec.version+' · 정책 변경 '+formatCount(rec.changedPolicyEntries):
    '미확인 · 서버 정책 백업 누락'],
  ['DB 복원 감사',formatCount(rec.verifiedRestoreEvents)],
  ['안전 HTTP 검사의 실측 기록',
    formatCount(probes.recorded)+' · 기대 상태 일치 '+formatCount(probes.expectedStatusMatched)],
  ['공식 41종 공격 (제공 심판)','미확인 · 사건별 공식 기록 미연결'],
 ];
}
export async function refreshPublicOps(perform=fetch){
 button.disabled=true;
 status.textContent='읽기 전용 운영 집계 API를 확인 중입니다.';
 try{
  const response=await perform('/api/war-room-summary',{method:'GET',cache:'no-store',
   headers:{'Accept':'application/json'}});
  if(!response.ok)throw Error('운영 서버가 집계를 제공하지 않음 (HTTP '+response.status+')');
  const data=await response.json();
  const metrics=publicMetrics(data);
  if(!metrics)throw Error('서버 기록을 확인할 수 없습니다.');
  const date=Date.parse(data.observedAt);
  if(!Number.isFinite(date))throw Error('기록 시각이 유효하지 않습니다.');
  panel.replaceChildren(...metrics.map(([label,value])=>cell(label,value)));
  stamp.textContent=new Date(date).toLocaleString('ko-KR');
  commit.textContent=data.commit?.slice(0,12)||'배포 식별자 미확인';
  status.textContent='서버 집계 API 실측 확인 · 응답 상태 HTTP '+response.status+
    ' · 제공 ALEPH 엔진 및 공식 심판 기록은 별도입니다.';
  status.classList.remove('error');
  return data;
 }catch(err){
  panel.replaceChildren();
  stamp.textContent='미확인';
  commit.textContent='미확인';
  status.textContent='운영 집계 미확인: '+err.message;
  status.classList.add('error');
  return null;
 }finally{button.disabled=false;}
}
button.addEventListener('click',()=>{void refreshPublicOps();});
void refreshPublicOps();
