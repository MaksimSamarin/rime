const {test}=require('node:test');
const assert=require('node:assert/strict');
const M=require('../hy2bridge/web/monitoring.js');
const now=1000;
function node(id,metrics={},extra={}){return {id,name:id,state:'healthy',seen_at:now,metrics,...extra};}

test('an explicitly selected tunnel has its own dated result and keeps the direct result intact',()=>{
  const direct={state:'unavailable',passed:false,checked_at:now,fresh:true,origin:'Direct fixture'};
  const value=node('exit',{}, {client_access:direct,tunnel_access:{active:true,checked_at:now,passed:true,fresh:true,entry_name:'Entry'}});
  assert.equal(M.access(value,now).label,'VPN через Entry');
  assert.equal(M.access(value,now).state,'healthy');
  assert.equal(value.client_access,direct);
  assert.equal(M.access(value,now+181).state,'unknown');
  value.tunnel_access.passed=false;
  assert.equal(M.access(value,now).state,'offline');
});

test('proxy failure does not label a verified VPN tunnel as unavailable',()=>{
  const value=node('exit',{}, {tunnel_access:{active:true,fresh:true,checked_at:now,passed:false,vpn_passed:true,proxies_passed:false,entry_name:'Entry'}});
  assert.equal(M.access(value,now).state,'healthy');
  assert(M.describe(value,now).alerts.some(alert=>alert.text==='Прокси через вход требуют проверки'));
  value.tunnel_access.vpn_passed=null;
  assert.equal(M.access(value,now).state,'unknown');
});

test('local resource health cannot clear a failed or stale client probe',()=>{
  const resources={cpu_percent:10,mem_total_bytes:100,mem_available_bytes:90,disk_total_bytes:100,disk_free_bytes:90,service_healthy:true};
  const failed=M.describe(node('n',resources,{client_access:{state:'unavailable',fresh:true,checked_at:now}}),now);
  assert.equal(failed.cpu,10);assert.equal(failed.attention,true);assert(failed.alerts.some(a=>a.level===2));
  const stale=M.describe(node('n',resources,{client_access:{state:'unknown',fresh:false,checked_at:500}}),now);
  assert.equal(stale.attention,true);assert(stale.alerts.length>0);
});
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

test('VPN availability requires a recent dated client payload observation',()=>{
  const resources={service_healthy:true};
  const fresh=node('n',resources,{client_access:{state:'available',passed:true,fresh:true,checked_at:now,origin:'Test origin'}});
  assert.equal(M.access(fresh,now).state,'healthy');
  assert.equal(M.access(fresh,now+181).state,'unknown');
  assert.equal(M.access({...fresh,client_access:{state:'available',fresh:true}},now).state,'unknown');
  assert.equal(M.access({...fresh,client_access:{...fresh.client_access,checked_at:now+100}},now).state,'unknown');
  assert.equal(M.access(node('service',resources),now).state,'unknown');
});

test('server stop, node quota and disabled state take precedence over older success',()=>{
  const fresh=node('n',{service_healthy:false},{client_access:{state:'available',fresh:true,passed:true,checked_at:now-1}});
  assert.equal(M.access(fresh,now).label,'Служба остановлена');
  assert.equal(M.access({...fresh,quota:{blocked:true}},now).label,'Квота исчерпана');
  assert.equal(M.access({...fresh,enabled:0},now).state,'disabled');
});

test('the panel is counted separately from gateway VPN availability',()=>{
  const panel=M.describe(node('panel',{cpu_percent:2},{role:'panel'}),now);
  const gateway=M.describe(node('gateway',{cpu_percent:2},{client_access:{state:'available',passed:true,fresh:true,checked_at:now}}),now);
  const unknown=M.describe(node('unknown',{cpu_percent:2}),now);
  const summary=M.summarize([panel,gateway,unknown]);
  assert.equal(panel.access.label,'Панель отвечает');
  assert.equal(summary.vpnCount,2);assert.equal(summary.vpnAvailable,1);assert.equal(summary.vpnUnknown,1);
});

test('chart scale includes zero and uses readable upper bounds',()=>{
  const scale=M.chartScale([null,NaN,-1,8.64*1024**3]);
  assert.equal(scale.unit,'GiB');assert.equal(scale.upper,10*1024**3);
  assert.equal(M.chartScale([0,0]).maximum,0);
  assert(M.chartScale([0,0]).upper>0);
  assert.equal(M.chartScale(new Array(200000).fill(1024)).upper,1024);
});
