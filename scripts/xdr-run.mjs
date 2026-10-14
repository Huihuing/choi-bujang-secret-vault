import { readFile, writeFile } from 'node:fs/promises';

const moduleName = process.argv[2];

function mitreIds(raw) {
  const mitre = raw?.rule?.mitre;
  if (Array.isArray(mitre)) return mitre;
  if (Array.isArray(mitre?.id)) return mitre.id;
  if (typeof mitre?.id === 'string') return [mitre.id];
  return [];
}

function isNormal(raw, technique) {
  if (raw?.fixture?.classification === 'normal' || raw?.expected === 'normal') return true;
  return !mitreIds(raw).some((id) => typeof id === 'string' && id.startsWith(technique))
    && Number(raw?.rule?.level ?? 0) <= 3;
}

function alertId(raw, index) {
  const value = raw?.id ?? raw?._id ?? raw?.alert_id;
  return typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(value)
    ? value
    : `fixture-${String(index + 1).padStart(3, '0')}`;
}

async function runBruteForce() {
  const [{ parseAlerts }, { decide }, { writeDenyRules }] = await Promise.all([
    import('../xdr/brute-force/read-alerts.mjs'),
    import('../xdr/brute-force/decide.mjs'),
    import('../xdr/brute-force/ztna-bridge.mjs'),
  ]);
  const fixtureUrl = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
  const source = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rawAlerts = Array.isArray(source) ? source : source.alerts;
  if (!Array.isArray(rawAlerts)) throw new TypeError('Fixture must be an array or { alerts: [...] }');
  const extracted = parseAlerts(source);
  if (extracted.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

  const entries = [];
  for (let index = 0; index < rawAlerts.length; index += 1) {
    const output = await decide(rawAlerts[index]);
    entries.push({
      alertId: alertId(rawAlerts[index], index),
      alert: extracted[index],
      decision: output,
      fixtureNormal: isNormal(rawAlerts[index], 'T1110'),
    });
  }
  const counts = { block: 0, alert: 0, record: 0 };
  for (const entry of entries) counts[entry.decision.action] += 1;
  const normalEventBlocks = entries.filter((entry) => entry.fixtureNormal && entry.decision.action === 'block');
  const rules = await writeDenyRules(entries.filter((entry) => !entry.fixtureNormal));
  const result = {
    schema: 'aleph.xdr.result.v1',
    moduleKey: 'brute-force',
    counts,
    normalEventBlocks: normalEventBlocks.length,
    rulesWritten: rules.length,
    decisions: entries.map((entry) => ({
      alertId: entry.alertId,
      action: entry.decision.action,
      confidence: entry.decision.confidence,
      reason: entry.decision.reason,
    })),
  };
  await writeFile(new URL('../xdr/brute-force/result.json', import.meta.url), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`block=${counts.block} alert=${counts.alert} record=${counts.record} normalEventBlocks=${normalEventBlocks.length}`);
  if (normalEventBlocks.length > 0) process.exitCode = 1;
}

async function runWebInjection() {
  const [{ readAlerts }, { decide }, connection] = await Promise.all([
    import('../xdr/web-injection/read-alerts.mjs'),
    import('../xdr/web-injection/decide.mjs'),
    import('../xdr/web-injection/connect.mjs'),
  ]);
  const fixtureUrl = new URL('../xdr/fixtures/web-injection.json', import.meta.url);
  const source = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rawAlerts = source?.alerts;
  if (!Array.isArray(rawAlerts)) throw new TypeError('Fixture must contain alerts');
  const extracted = await readAlerts(fixtureUrl);
  if (extracted.length !== rawAlerts.length) throw new Error('Alert count does not match extracted line count');

  const decisions = [];
  const rules = [];
  const counts = { block: 0, alert: 0, record: 0 };
  let normalEventBlocks = 0;

  for (let index = 0; index < rawAlerts.length; index += 1) {
    const raw = rawAlerts[index];
    const output = await decide(raw);
    decisions.push({
      alertId: alertId(raw, index),
      action: output.action,
      confidence: output.confidence,
      reason: output.reason,
    });
    counts[output.action] += 1;
    if (isNormal(raw, 'T1190') && output.action === 'block') normalEventBlocks += 1;
    const rule = connection.makeRule(raw, output, Date.parse(raw.timestamp));
    if (rule) rules.push(rule);
  }

  await connection.persistRules(rules);

  const logUrl = new URL('../xdr/alerts.log', import.meta.url);
  let existing = '';
  try { existing = await readFile(logUrl, 'utf8'); } catch {}
  const preserved = existing.split(/\r?\n/)
    .filter(Boolean)
    .filter((line) => !line.includes('"module":"web-injection"'));
  const webLines = decisions
    .filter((item) => item.action === 'block' || item.action === 'alert')
    .map((item) => JSON.stringify({
      module: 'web-injection',
      alertId: item.alertId,
      action: item.action,
      confidence: item.confidence,
      pattern: item.reason,
    }));
  const allLines = [...preserved, ...webLines];
  await writeFile(logUrl, allLines.length ? `${allLines.join('\n')}\n` : '', 'utf8');

  const result = {
    schema: 'aleph.xdr.result.v1',
    moduleKey: 'web-injection',
    counts,
    normalEventBlocks,
    rulesWritten: rules.length,
    decisions,
  };
  await writeFile(new URL('../xdr/web-injection/result.json', import.meta.url), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`block=${counts.block} alert=${counts.alert} record=${counts.record} normalEventBlocks=${normalEventBlocks}`);
  if (normalEventBlocks > 0) process.exitCode = 1;
}

async function runKnownCve(){
 const [{readAlerts},{decide},connection]=await Promise.all([
  import('../xdr/known-cve/read-alerts.mjs'),
  import('../xdr/known-cve/decide.mjs'),
  import('../xdr/known-cve/respond.mjs'),
 ]);
 const fixtureUrl=new URL('../xdr/fixtures/known-cve.json',import.meta.url);
 const source=JSON.parse(await readFile(fixtureUrl,'utf8'));
 const rawAlerts=Array.isArray(source)?source:source?.alerts;
 if(!Array.isArray(rawAlerts))throw new TypeError('Fixture must contain Wazuh alerts');
 const extracted=await readAlerts(fixtureUrl);
 if(rawAlerts.length!==extracted.length)
  throw new Error('Alert count does not match extracted line count');
 const counts={block:0,alert:0,record:0},rows=[],decisions=[];
 let normalEventBlocks=0;
 for(let i=0;i<rawAlerts.length;i++){
  const alert=rawAlerts[i];
  const output=decide(alert);
  const fixtureNormal=isNormal(alert,'T1190');
  if(fixtureNormal && output.action==='block')normalEventBlocks++;
  counts[output.action]++;
  rows.push({alert,decision:output,fixtureNormal});
  decisions.push({alertId:alertId(alert,i),action:output.action,
   confidence:output.confidence,reason:output.reason});
 }
 const rules=connection.rulesFromDecisions(rows);
 await connection.persistRules(rules);
 await connection.writeAlerts(decisions);
 const result={
  schema:'aleph.xdr.result.v1',moduleKey:'known-cve',counts,
  normalEventBlocks,rulesWritten:rules.length,decisions,
 };
 await writeFile(new URL('../xdr/known-cve/result.json',import.meta.url),
   JSON.stringify(result,null,2)+'\n','utf8');
 console.log('block='+counts.block+' alert='+counts.alert+' record='+counts.record+
   ' normalEventBlocks='+normalEventBlocks);
 if(normalEventBlocks>0)process.exitCode=1;
}

async function runPersistence(){
 const [{readAlerts},{decide},response]=await Promise.all([
  import('../xdr/persistence/read-alerts.mjs'),
  import('../xdr/persistence/decide.mjs'),
  import('../xdr/persistence/respond.mjs'),
 ]);
 const fixtureUrl=new URL('../xdr/fixtures/persistence.json',import.meta.url);
 const document=JSON.parse(await readFile(fixtureUrl,'utf8'));
 const alerts=Array.isArray(document)?document:document?.alerts;
 if(!Array.isArray(alerts))throw new TypeError('Expected Wazuh persistence alerts array');
 const extracted=await readAlerts(fixtureUrl);
 if(extracted.length!==alerts.length)throw new Error('Extracted alerts count mismatch');
 const counts={block:0,alert:0,record:0},records=[],decisions=[];
 let normalEventBlocks=0;
 for(let i=0;i<alerts.length;i++){
  const alert=alerts[i],result=decide(alert);
  const tagged=mitreIds(alert).some(x=>/^T(?:1543|1053|1547)(?:\.|$)/u.test(x));
  const fixtureNormal=alert?.fixture?.classification==='normal'
    ||(alert?.fixture?.classification==null&&!tagged&&Number(alert?.rule?.level??0)<=3);
  if(fixtureNormal&&result.action==='block')normalEventBlocks++;
  counts[result.action]++;
  records.push({alert,decision:result,fixtureNormal});
  decisions.push({alertId:alertId(alert,i),action:result.action,
   confidence:result.confidence,reason:result.reason});
 }
 // This course fixture lacks SDP device IDs. Bind only the exact known
 // published training bytes to a non-production pseudonymous device.
 const bindings=JSON.parse(await readFile(new URL('../xdr/persistence/device-bindings.fixture.json',import.meta.url),'utf8'));
 const rawFixture=await readFile(fixtureUrl,'utf8');
 const crypto=await import('node:crypto');
 const gitBlobHash=crypto.createHash('sha1').update('blob '+Buffer.byteLength(rawFixture)+String.fromCharCode(0)).update(rawFixture).digest('hex');
 if(document?.schema!=='aleph.xdr.fixture.v1'||document.moduleKey!=='persistence'||alerts.length!==24
    ||gitBlobHash!=='8dfb349b02cb0fd107a751c148be6165aa8c2725'
    ||bindings?.fixtureOnly!==true||bindings?.sourceFixtureBlobSha!==gitBlobHash)
  throw new Error('Refusing training-only persistence device mapping for unknown event source');
 const resolveDevice=alert=>Object.hasOwn(bindings.agents,alert?.agent?.name)
  ?bindings.agents[alert.agent.name]:null;
 const rules=response.rulesFromDecisions(records,resolveDevice);
 await response.persistRules(rules);
 await response.writeAlerts(decisions);
 const result={
  schema:'aleph.xdr.result.v1',moduleKey:'persistence',counts,
  normalEventBlocks,rulesWritten:rules.length,decisions,
 };
 await writeFile(new URL('../xdr/persistence/result.json',import.meta.url),
  JSON.stringify(result,null,2)+'\n','utf8');
 console.log('block='+counts.block+' alert='+counts.alert+' record='+counts.record
  +' normalEventBlocks='+normalEventBlocks);
 if(normalEventBlocks>0)process.exitCode=1;
}

async function runPrivilege(){
 const [{readAlerts},{decide},response]=await Promise.all([
  import('../xdr/privilege/read-alerts.mjs'),
  import('../xdr/privilege/decide.mjs'),
  import('../xdr/privilege/respond.mjs'),
 ]);
 const source=JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json',import.meta.url),'utf8'));
 const alerts=Array.isArray(source)?source:source?.alerts;
 if(!Array.isArray(alerts))throw new TypeError('Expected Wazuh privilege fixture alerts');
 const extracted=await readAlerts();
 if(extracted.length!==alerts.length)throw new Error('Privilege fixture extraction count differs');
 const counts={block:0,alert:0,record:0},rows=[],decisions=[];
 let normalEventBlocks=0;
 for(let i=0;i<alerts.length;i++){
  const alert=alerts[i],decision=decide(alert);
  const fixtureNormal=Number(alert?.rule?.level??0)<=3
   &&(!Array.isArray(alert?.rule?.mitre)||alert.rule.mitre.length===0);
  if(fixtureNormal&&decision.action==='block')normalEventBlocks++;
  counts[decision.action]++;
  rows.push({alert,decision,fixtureNormal});
  decisions.push({alertId:alertId(alert,i),action:decision.action,
   confidence:decision.confidence,reason:decision.reason});
 }
 // Fixture-only identity bindings simulate what a trusted SDP account
 // resolver must provide. No production username->subject mapping is inferred.
 const bindings=JSON.parse(await readFile(new URL('../xdr/privilege/subject-bindings.fixture.json',import.meta.url),'utf8'));
 // This mapping is ONLY for the exact published educational fixture, never a live Wazuh log.
 const expectedFixtureSha256='e5e4b41e81138c79de7a62ad23859ce166cbf078fd8f9a2bac54a79e6f547a85';
 const fixtureText=await readFile(new URL('../xdr/fixtures/privilege.json',import.meta.url),'utf8');
 const actualFixtureSha256=(await import('node:crypto')).createHash('sha256').update(fixtureText).digest('hex');
 if(source?.schema!=='aleph.xdr.fixture.v1'||source?.moduleKey!=='privilege'||
    source.alerts.length!==26||actualFixtureSha256!==expectedFixtureSha256||
    bindings?.fixtureOnly!==true||
    bindings?.sourceFixtureBlobSha!=='442fc3297bcc73969fa61b1368d08e0038b9c135')
  throw new Error('Refusing fixture-only pseudonymous identity bindings for an unrecognized privilege alert source');
 const resolver=account=>Object.hasOwn(bindings.subjects,account)?bindings.subjects[account]:null;
 const rules=response.rulesFromDecisions(rows,resolver);
 await response.persistRules(rules);
 await response.writeAlerts(decisions);
 const result={
  schema:'aleph.xdr.result.v1',moduleKey:'privilege',counts,
  normalEventBlocks,rulesWritten:rules.length,decisions,
 };
 await writeFile(new URL('../xdr/privilege/result.json',import.meta.url),
  JSON.stringify(result,null,2)+'\n','utf8');
 console.log('block='+counts.block+' alert='+counts.alert+' record='+counts.record+' normalEventBlocks='+normalEventBlocks);
 if(normalEventBlocks>0)process.exitCode=1;
}


async function runExfiltration(){
 const [{readAlerts},{decide},response]=await Promise.all([
  import('../xdr/exfiltration/read-alerts.mjs'),
  import('../xdr/exfiltration/decide.mjs'),
  import('../xdr/exfiltration/respond.mjs'),
 ]);
 const source=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
 const alerts=Array.isArray(source)?source:source?.alerts;
 if(!Array.isArray(alerts))throw new TypeError('Expected Wazuh exfiltration fixture alerts');
 const extracted=await readAlerts();
 if(extracted.length!==alerts.length)throw new Error('Exfiltration alert extraction count mismatch');
 const counts={block:0,alert:0,record:0},rows=[],decisions=[];
 let normalEventBlocks=0;
 for(let i=0;i<alerts.length;i++){
  const alert=alerts[i],output=decide(alert);
  const normal=alert?.fixture?.classification==='normal'
    ||(alert?.fixture?.classification==null&&Number(alert?.rule?.level??0)<=3
      &&!mitreIds(alert).some(id=>/^T(?:1041|1048)(?:\.|$)/u.test(id)));
  if(normal&&output.action==='block')normalEventBlocks++;
  counts[output.action]++;
  rows.push({alert,decision:output,fixtureNormal:normal});
  decisions.push({alertId:alertId(alert,i),action:output.action,
    confidence:output.confidence,reason:output.reason});
 }
 const rules=response.rulesFromDecisions(rows);
 await response.persistRules(rules);
 await response.writeAlerts(decisions);
 const result={
  schema:'aleph.xdr.result.v1',moduleKey:'exfiltration',
  fixtureSource:source?.source?.includes('AI-created')?'synthetic-not-judge':'provided-fixture',
  counts,normalEventBlocks,rulesWritten:rules.length,decisions,
 };
 await writeFile(new URL('../xdr/exfiltration/result.json',import.meta.url),JSON.stringify(result,null,2)+'\n','utf8');
 console.log('block='+counts.block+' alert='+counts.alert+' record='+counts.record+' normalEventBlocks='+normalEventBlocks);
 if(normalEventBlocks>0)process.exitCode=1;
}

if (moduleName === 'brute-force') await runBruteForce();
else if (moduleName === 'web-injection') await runWebInjection();
else if (moduleName === 'known-cve') await runKnownCve();
else if (moduleName === 'persistence') await runPersistence();
else if (moduleName === 'privilege') await runPrivilege();
else if (moduleName === 'exfiltration') await runExfiltration();
else {
  console.error('Usage: npm run xdr:run -- <brute-force|web-injection|known-cve|persistence|privilege|exfiltration>');
  process.exitCode = 2;
}
