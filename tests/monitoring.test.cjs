const {test}=require('node:test');
const assert=require('node:assert/strict');
const M=require('../hy2bridge/web/monitoring.js');
const now=1000;
function node(id,metrics={},extra={}){return {id,name:id,state:'healthy',seen_at:now,metrics,...extra};}
test('missing, null and malformed values are never converted to zero usage',()=>{
  for(const value of [undefined,null,-1,NaN,Infinity,'0',101])assert.equal(M.describe(node('n',{cpu_percent:value}),now).cpu,null);
  assert.equal(M.describe(node('n',{cpu_percent:0}),now).cpu,0);
  assert.equal(M.capacity(100,null),null);assert.equal(M.capacity(0,0),null);assert.equal(M.capacity(100,200),null);
  assert.equal(M.capacity(100,0).percent,100);
});
test('stale nodes retain their last timestamp but contribute no resources to totals',()=>{
  const metrics={cpu_percent:99,mem_total_bytes:100,mem_available_bytes:2,disk_total_bytes:200,disk_free_bytes:0};
  const stale=M.describe(node('old',metrics,{seen_at:969}),now),fresh=M.describe(node('new',metrics),now);
  assert.equal(stale.state,'offline');assert.equal(stale.cpu,null);assert.equal(stale.ram,null);
  const s=M.summarize([stale,fresh]);assert.equal(s.cpuCount,1);assert.equal(s.ram.used,98);assert.equal(s.disk.total,200);
});
test('resource warnings and critical disk capacity surface in the attention filter',()=>{
  const r=M.describe(node('hot',{cpu_percent:96,mem_total_bytes:100,mem_available_bytes:20,disk_total_bytes:100,disk_free_bytes:8}),now);
  assert.equal(r.attention,true);assert.equal(r.alerts.length,3);assert.equal(r.alerts.filter(a=>a.level===2).length,2);
});
test('sorting places highest usage first and unknown usage last',()=>{
  const a=M.describe(node('a',{cpu_percent:0}),now),b=M.describe(node('b',{cpu_percent:97}),now),c=M.describe(node('c'),now);
  assert.deepEqual(M.sort([c,a,b],'cpu').map(r=>r.node.id),['b','a','c']);
  assert.equal(M.summarize([]).cpuMax,null);
});

test('stale resources do not claim a connected native VPN is offline',()=>{
  const r=M.describe(node('native',{cpu_percent:20},{seen_at:900,status_source:'marzban'}),now);
  assert.equal(r.state,'healthy');assert.equal(r.cpu,null);assert.equal(r.unavailable,true);
});

test('history distinguishes an active failure, recovery and an unsampled interval',()=>{
  assert.equal(M.bucket([]).state,'unknown');
  const recovered=M.bucket([{minute:1,state:'offline'},{minute:2,state:'healthy'}]);
  assert.equal(recovered.state,'degraded');assert.equal(recovered.last,'healthy');assert.equal(recovered.failures,1);
  assert.equal(M.bucket([{minute:1,state:'healthy'},{minute:2,state:'offline'}]).state,'offline');
});
