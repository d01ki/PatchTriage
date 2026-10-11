// Run with: node --test tests/webapp_state.test.cjs
// Exercise the shipped inline JavaScript with deterministic API responses.
// No browser, network, package dependencies or real evidence are required.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '../src/patchtriage/webapp/page.py'), 'utf8');
const script = template.split('<script>')[1].split('</script>')[0]
  .replace('__SSVC_LABELS__', '{}').replace('__HUMAN_IMPACT__', '{}')
  .replace(/\nboot\(\)\.catch\(showBootError\);\s*$/, '');

function runtime() {
  const elements = new Map(), storage = new Map(), notices = [];
  let now = Date.now();
  const sandbox = {
    console, AbortController,
    Date: class extends Date { static now() { return now; } },
    setTimeout: (fn, ms) => setTimeout(() => { now += ms; fn(); }, ms >= 15000 ? ms : 0),
    clearTimeout,
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, {
          value: '', disabled: false, innerHTML: '', textContent: '',
          addEventListener() {}, querySelectorAll() {return [];},
          classList: {toggle() {}}, options: [], selectedIndex: 0,
        });
        return elements.get(id);
      },
      querySelectorAll() { return []; },
    },
    sessionStorage: {getItem: k => storage.get(k) || null, setItem: (k,v) => storage.set(k,v)},
    fetch: async () => { throw new Error('Unexpected network request'); },
    notices,
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(script, ctx);
  const run = code => vm.runInContext(code, ctx);
  run(`renderResults=()=>{};renderTargets=()=>{};updateKpis=()=>{};
       notify=(message,error)=>notices.push({message,error});
       booting=false;CFG={backends:['rules'],limits:{active_jobs_per_session:2}};`);
  return {ctx, run, storage, notices};
}
const summary = id => ({target_id:id,report_url:'/report/'+id,total:4,run_generation:'new'});
const retryable = () => Object.assign(new Error('connection lost'),{retryable:true});
const targets = n => Array.from({length:n},(_,i)=>({id:'target'+i,source_file:true,input_revision:1}));
const flush = () => new Promise(resolve=>setImmediate(resolve));

test('temporary polling failures reconnect to the same job and yield its report', async () => {
  const r=runtime();let calls=0;
  r.ctx.api=async (method,url)=>{
    assert.equal(method,'GET');assert.equal(url,'/api/jobs/job-one');
    if(++calls<3)throw retryable();
    return {state:'succeeded',summary:summary('target0')};
  };
  const result=await r.run(`waitForJob('job-one','target0')`);
  assert.equal(result.report_url,'/report/target0');assert.equal(calls,3);
});

test('polling exhaustion stays disconnected, not a failed assessment', async () => {
  const r=runtime();let calls=0;r.ctx.api=async()=>{calls++;throw retryable();};
  assert.equal(await r.run(`watchJob('target0','job-one')`),false);
  assert.equal(r.run(`STATUS.get('target0').state`),'disconnected');
  assert.equal(r.run(`STATUS.get('target0').jobId`),'job-one');assert.equal(calls,5);
});

test('server failure is persistent and never emits a completed report', async () => {
  const r=runtime();r.ctx.api=async()=>({state:'failed',error:'pipeline failed'});
  assert.equal(await r.run(`watchJob('target0','job-one')`),false);
  assert.equal(r.run(`STATUS.get('target0').state`),'failed');
  assert.equal(r.run(`RESULTS.has('target0')`),false);
});

test('successful state with a missing summary is not rendered as a success', async () => {
  const r=runtime();r.ctx.api=async()=>({state:'succeeded'});
  assert.equal(await r.run(`watchJob('target0','job-one')`),false);
  assert.equal(r.run(`STATUS.get('target0').state`),'disconnected');
  assert.equal(r.run(`RESULTS.size`),0);
});

test('Run all respects the server capacity and produces every result', async () => {
  const r=runtime();r.ctx.fixtures=targets(7);r.run('TARGETS=fixtures');
  const active=new Set(), polls=new Map();let maxActive=0,posts=0;
  r.ctx.api=async(method,url)=>{
    if(method==='POST'){
      const id=url.split('/')[3];assert(!active.has(id));active.add(id);posts++;
      maxActive=Math.max(maxActive,active.size);return {job_id:id};
    }
    const id=url.split('/').at(-1),count=(polls.get(id)||0)+1;polls.set(id,count);
    if(count<3)return {state:'running'};
    active.delete(id);return {state:'succeeded',summary:summary(id)};
  };
  const results=await r.run('runTargets(TARGETS.map(t=>t.id))');
  assert(results.every(Boolean));assert.equal(posts,7);assert.equal(maxActive,2);
  assert.equal(r.run('RESULTS.size'),7);assert.equal(r.run('STATUS.size'),0);
  assert.equal(r.storage.get('patchtriage-queue'),'[]');
});

test('double Run while submission is pending starts only one assessment', async () => {
  const r=runtime();r.ctx.fixtures=targets(1);r.run('TARGETS=fixtures');
  let accept, posts=0;
  r.ctx.api=async(method)=>{
    if(method==='POST'){posts++;return new Promise(resolve=>accept=resolve);}
    return {state:'succeeded',summary:summary('target0')};
  };
  const first=r.run(`runTargets(['target0'])`), second=r.run(`runTargets(['target0'])`);
  assert.equal(posts,1);
  assert.equal(JSON.parse(r.storage.get('patchtriage-queue')).length,1);
  accept({job_id:'job-one'});await Promise.all([first,second]);
  assert.equal(r.run('RESULTS.size'),1);
});

test('lost POST response recovers the accepted job without resubmitting', async () => {
  const r=runtime();r.ctx.fixtures=targets(1);r.run('TARGETS=fixtures');let posts=0;
  r.ctx.api=async(method,url)=>{
    if(method==='POST'){posts++;throw retryable();}
    if(url==='/api/jobs?latest=1')return [{target_id:'target0',job_id:'accepted',created_at:Date.now()/1000+1}];
    return {state:'succeeded',summary:summary('target0')};
  };
  assert((await r.run(`runTargets(['target0'])`)).every(Boolean));assert.equal(posts,1);
});

test('a full queue backs off before retrying instead of failing the target', async () => {
  const r=runtime();r.ctx.fixtures=targets(1);r.run('TARGETS=fixtures');let posts=0;
  r.ctx.api=async(method,url)=>{
    if(method==='POST'){
      if(++posts===1)throw Object.assign(new Error('queue full'),{status:429,retryable:true});
      return {job_id:'accepted'};
    }
    if(url==='/api/jobs?latest=1')return [];
    return {state:'succeeded',summary:summary('target0')};
  };
  assert((await r.run(`runTargets(['target0'])`)).every(Boolean));assert.equal(posts,2);
});

test('refresh includes a job finishing between discovery and summary loading', async () => {
  const r=runtime();r.ctx.fixtures=targets(1);r.run('TARGETS=fixtures');const calls=[];
  r.ctx.api=async(method,url)=>{
    calls.push(url);
    if(url==='/api/jobs?latest=1')return [{target_id:'target0',job_id:'finishing',state:'running'}];
    if(url==='/api/summaries')return [summary('target0')];
    return {state:'succeeded',summary:summary('target0')};
  };
  await r.run('resumeActiveJobs()');await flush();
  assert.equal(calls[0],'/api/jobs?latest=1');assert.equal(calls[1],'/api/summaries');
  assert.equal(r.run(`RESULTS.get('target0').report_url`),'/report/target0');
});

test('refresh restores unsent targets and does not duplicate the active job', async () => {
  const r=runtime();r.ctx.fixtures=targets(2);r.run('TARGETS=fixtures');let posts=0;
  r.storage.set('patchtriage-queue',JSON.stringify(targets(2).map(t=>({id:t.id,backend:'rules',queuedAt:1,revision:1}))));
  r.ctx.api=async(method,url)=>{
    if(url==='/api/jobs?latest=1')return [{target_id:'target0',job_id:'target0',state:'running',created_at:2}];
    if(url==='/api/summaries')return [];
    if(method==='POST'){posts++;assert(url.includes('target1'));return {job_id:'target1'};}
    const id=url.split('/').at(-1);return {state:'succeeded',summary:summary(id)};
  };
  await r.run('resumeActiveJobs()');await flush();await flush();
  assert.equal(posts,1);assert.equal(r.run('RESULTS.size'),2);
});

test('malformed JSON with HTTP 200 is an error, never a completed response', async () => {
  const r=runtime();r.ctx.fetch=async()=>({ok:true,status:200,json:async()=>{throw new Error('not JSON');}});
  await assert.rejects(r.run(`api('GET','/api/jobs/job-one')`),error=>error.retryable===true);
});

test('first boot establishes the session before requesting targets', async () => {
  const r=runtime();const calls=[];let finishConfig;
  r.ctx.syncSsvcContext=()=>{};
  r.ctx.loadConfig=async()=>{calls.push('config');await new Promise(resolve=>finishConfig=resolve);};
  r.ctx.loadTargets=async()=>{calls.push('targets');};
  r.ctx.resumeActiveJobs=async()=>{calls.push('jobs');};
  const pending=r.run('boot()');assert.deepEqual(calls,['config']);finishConfig();await pending;
  assert.deepEqual(calls,['config','targets','jobs']);
});

test('a missing job after server restart offers a new run, not endless reconnects', async () => {
  const r=runtime();r.ctx.api=async()=>{throw Object.assign(new Error('no such job'),{status:404});};
  assert.equal(await r.run(`watchJob('target0','expired')`),false);
  assert.equal(r.run(`STATUS.get('target0').state`),'interrupted');
  assert.match(r.run(`STATUS.get('target0').error`),/restart/);
});

test('a lost submission with no recoverable job offers retry without resubmitting', async () => {
  const r=runtime();let calls=0;
  r.ctx.api=async(method,url)=>{calls++;assert.equal(method,'GET');assert.equal(url,'/api/jobs?latest=1');return [];};
  r.run(`STATUS.set('target0',{state:'disconnected'})`);
  await r.run(`reconnectTarget('target0')`);
  assert.equal(calls,1);assert.equal(r.run(`STATUS.get('target0').state`),'interrupted');
});
