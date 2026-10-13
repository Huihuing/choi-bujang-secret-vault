import test from 'node:test';
import assert from 'node:assert/strict';
import {decide,RULE_IDS} from '../src/decider.mjs';
import {exactResourcePath,ownsNote,hasStoredInstructorAccess} from '../src/resource-zones.mjs';
import {loadNote} from '../api/notes/[id].js';
import {fixtureRequests} from '../scripts/fixture-7.mjs';
const a='11111111-1111-4111-8111-111111111111',b='22222222-2222-4222-8222-222222222222';
const id='33333333-3333-4333-8333-333333333333';
const request=(method='GET',path='/notes/'+id,route='GET /notes/:id',service='notes')=>({
  requestId:'r8',subjectId:'student_pseudonym',deviceId:'a'.repeat(16),deviceRegistered:true,
  service,method,path,route,signals:{source:'none',region:'unknown',network:'unknown',hour:12},
  recentEvents:[],stepUp:{verified:false,authAgeSeconds:null},
});
test('implemented rule IDs',()=>assert.deepEqual([...RULE_IDS],['device_registered','step_up_required','resource_zone','instructor_write_protected']));
test('verified single-note routes are allowed, GET collection is never allowed',async()=>{
 const {normal}=fixtureRequests();
 assert.equal((await decide(normal)).decision,'allow');
 for(const r of [
  request(), request('PUT','/notes/'+id,'PUT /notes/:id'),
  request('DELETE','/notes/'+id,'DELETE /notes/:id'),
  {...request(),subjectId:'another_verified_student'},
  {...request(),deviceId:'bbbbbbbbbbbbbbbb'},
  {...request(),classId:'different_verified_class'},
  {...request(),projectId:'different_verified_project'},
  {...normal,method:'PUT',route:'PUT /notes/:id'},
 ]) assert.equal((await decide(r)).decision,'allow',JSON.stringify(r));
 for(const r of [
  request('GET','/notes','GET /notes'),
  {...normal,path:'/notes',route:'GET /notes'},
  {...normal,path:'/notes',route:'GET /notes',subjectId:'another_learner'},
  {...normal,path:'/notes',route:'GET /notes',deviceId:'bbbbbbbbbbbbbbbb'},
  {...normal,path:'/notes',route:'GET /notes',projectId:'other_project'},
 ]) assert.equal((await decide(r)).decision,'deny',JSON.stringify(r));
 assert.equal((await decide(request('POST','/notes','POST /notes'))).decision,'allow');
 assert.equal((await decide({...normal,path:'/notes',route:'POST /notes',method:'POST'})).decision,'allow');
});
test('unknown path, query control and same-depth export denied',async()=>{
  for(const r of [
    request('GET','/notes/export','GET /notes/:id'),
    request('GET','/notes/demo/extra','GET /notes/:id'),
    request('GET','/notes/'+id+'?export=1','GET /notes/:id'),
    request('GET','/notes/'+id,'GET /notes'),
    request('GET','/notes//'+id,'GET /notes/:id'),
    request('PATCH','/notes/'+id,'PATCH /notes/:id'),
    request('GET','/notes/'+id,'GET /notes/:id','wrong_service'),
    {...request(),deviceId:'bad'}, {...request(),subjectId:''},
  ]) {const x=await decide(r);assert.equal(x.decision,'deny');assert.equal(x.reasonCode,'resource_not_allowed');}
});
test('unregistered always denied',async()=>{
  assert.equal((await decide({...request(),deviceRegistered:false})).reasonCode,'device_not_registered');
});
test('student and spoofed instructor cannot write notices through v1 decider',async()=>{
  for(const [method,path,route] of [
    ['POST','/instructor-notices','POST /instructor-notices'],
    ['PUT','/instructor-notices/'+id,'PUT /instructor-notices/:id'],
  ]) {
    const x=await decide({...request(method,path,route,'instructor-notices'),role:'instructor'});
    assert.equal(x.decision,'deny');assert.equal(x.reasonCode,'instructor_required');
  }
  assert.equal((await decide(request('GET','/instructor-notices/'+id,'GET /instructor-notices/:id','instructor-notices'))).decision,'allow');
});
test('server resource IDs are canonical, and queries cannot select zone or privilege',()=>{
  assert.equal(exactResourcePath('/api/notes','notes'),'/api/notes');
  assert.equal(exactResourcePath('/api/notes/'+id,'notes',true),id);
  assert.equal(exactResourcePath('/api/instructor-notices/'+id,'instructor-notices',true),id);
  for(const u of ['/api/notes?owner_id='+b,'/api/notes?export=1','/api/notes/'+id+'?role=instructor','/api/notes/export']) {
    assert.equal(exactResourcePath(u,'notes',u.startsWith('/api/notes/')),null);
  }
  assert.equal(exactResourcePath('/api/notes/'+id,'instructor-notices',true),null);
});
test('owner checked against saved owner_id, not request body role',()=>{
  assert.equal(ownsNote({owner_id:a},a),true);
  assert.equal(ownsNote({owner_id:a,role:'instructor'},b),false);
  assert.equal(ownsNote({owner_id:b},a),false);
});
test('only a stored, verified student instructor membership passes',async()=>{
  const db={from(table){assert.equal(table,'instructor_memberships');return {select(){return this},eq(){return this},async maybeSingle(){return {data:{user_id:a},error:null}}}}};
  assert.equal(await hasStoredInstructorAccess(db,{kind:'judge',userId:a,role:'instructor'}),false);
  assert.equal(await hasStoredInstructorAccess(db,{kind:'student',userId:a}),true);
  assert.equal(await hasStoredInstructorAccess(db,{kind:'student',userId:b,role:'instructor'}),false);
});
test('stage7 composite risk and step-up remain',async()=>{
 const {normal}=fixtureRequests();
 const r={...normal,signals:{source:'judge_fixture',region:'foreign',network:'unusual',hour:3},
 recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]};
 assert.equal((await decide(r)).decision,'step_up');
 assert.equal((await decide({...r,stepUp:{verified:true,authAgeSeconds:60}})).decision,'allow');
});

test('single-note SQL constrains owner before fetching any title or content', async()=>{
  const foreignOwner='99999999-9999-4999-8999-999999999999';
  const path=[];
  const query={
    select(columns){path.push(['select',columns]);return this;},
    eq(column,value){path.push(['eq',column,value]);return this;},
    async maybeSingle(){
      const noteId=path.find(x=>x[0]==='eq'&&x[1]==='id')?.[2];
      const owner=path.find(x=>x[0]==='eq'&&x[1]==='owner_id')?.[2];
      if (noteId===id && owner===foreignOwner) {
        throw new Error('Attempted to fetch foreign-owner content');
      }
      return {data:noteId===id && owner===a?{id,owner_id:a,title:'owned',content:'owned'}:null,error:null};
    },
  };
  const db={from(table){assert.equal(table,'notes');return query;}};
  const owner=await loadNote(db,id,a);
  assert.equal(owner.data.owner_id,a);
  assert.deepEqual(path.filter(x=>x[0]==='eq'),[['eq','id',id],['eq','owner_id',a]]);
  path.length=0;
  const denied=await loadNote(db,id,b);
  assert.equal(denied.data,null);
  assert.deepEqual(path.filter(x=>x[0]==='eq'),[['eq','id',id],['eq','owner_id',b]]);
});

test('isolated judge-style decider preserves owner and denies cross-zone requests',async()=>{
 const {readFile}=await import('node:fs/promises');
 const code=await readFile(new URL('../src/decider.mjs',import.meta.url),'utf8');
 const {decide: isolated}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const {normal}=fixtureRequests();
 assert.equal((await isolated(normal)).decision,'allow');
 assert.equal((await isolated({...normal,subjectId:'other_learner'})).decision,'allow');
 assert.equal((await isolated({...normal,path:'/notes/'+id})).decision,'allow');
 assert.equal((await isolated({...normal,deviceId:'bbbbbbbbbbbbbbbb'})).decision,'allow');
 assert.equal((await isolated({...normal,path:'/notes',route:'GET /notes'})).decision,'deny');
 assert.equal((await isolated({...normal,method:'PUT',route:'PUT /notes/:id'})).decision,'allow');
});

test('verified source does not turn cross-zone collection into a granted resource',async()=>{
 const {normal}=fixtureRequests();
 for(const changes of [
   {subjectId:'another_learner'}, {classId:'another_class'}, {projectId:'another_project'},
   {deviceId:'bbbbbbbbbbbbbbbb'}, {service:'instructor-notices'},
 ]) {
   const r={...normal,path:'/notes',route:'GET /notes',...changes};
   assert.equal((await decide(r)).decision,'deny');
 }
});

test('no broad note read and no notice/class/instructor write regardless of service label',async()=>{
 const {normal}=fixtureRequests();
 for(const method of ['GET','HEAD','OPTIONS']) {
  assert.equal((await decide({...normal,path:'/notes',route:method+' /notes',method})).decision,'deny');
 }
 for(const [service,prefix] of [
  ['instructor-notices','/instructor-notices'],
  ['announcements','/announcements'],
  ['class-notices','/class-notices'],
  ['instructor-materials','/instructor-materials'],
 ]) for(const method of ['POST','PUT','PATCH','DELETE']) {
  for(const [path,route] of [[prefix,method+' '+prefix],[prefix+'/'+id,method+' '+prefix+'/:id']]){
   const r={...normal,service,method,path,route};
   assert.equal((await decide(r)).decision,'deny',JSON.stringify(r));
  }
 }
 assert.equal((await decide(request('GET','/instructor-notices/'+id,'GET /instructor-notices/:id','instructor-notices'))).decision,'allow');
});
