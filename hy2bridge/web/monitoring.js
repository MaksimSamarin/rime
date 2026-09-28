/* Resource calculations shared by the overview and its regression checks. */
(function(root){
  'use strict';
  const valid=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
  const percent=n=>valid(n)&&n<=100?n:null;
  function capacity(total,free){
    if(!valid(total)||total===0||!valid(free)||free>total)return null;
    return {total,free,used:total-free,percent:100*(total-free)/total};
  }
  function describe(node,now){
    const m=node.metrics||{},age=valid(node.seen_at)?Math.max(0,now-node.seen_at):null;
    const fresh=age!==null&&age<=30;
    const cpu=fresh?percent(m.cpu_percent):null;
    const ram=fresh?capacity(m.mem_total_bytes,m.mem_available_bytes):null;
    const disk=fresh?capacity(m.disk_total_bytes,m.disk_free_bytes):null;
    const alerts=[];
    if(node.quota?.enabled&&node.quota.percent>=80)alerts.push({text:node.quota.blocked?'Лимит VPN исчерпан':'Трафик ≥'+(node.quota.percent>=95?'95%':'80%'),level:node.quota.percent>=95?2:1});
    if(cpu!==null&&cpu>=80)alerts.push({text:'CPU '+(cpu>=95?'критично':'высокая загрузка'),level:cpu>=95?2:1});
    if(ram&&ram.percent>=80)alerts.push({text:'RAM '+(ram.percent>=95?'критично':'высокая загрузка'),level:ram.percent>=95?2:1});
    if(disk&&disk.percent>=80)alerts.push({text:disk.percent>=90?'Диск: мало места':'Диск заполнен ≥80%',level:disk.percent>=90?2:1});
    const unavailable=cpu===null||!ram||!disk;
    const disabled=node.enabled===0||node.native_status==='disabled';
    const state=disabled?'disabled':(node.state==='offline'||(age!==null&&!fresh&&node.status_source!=='marzban'))?'offline':node.state==='unknown'?'unknown':node.state;
    const severity=Math.max(state==='offline'?4:state==='degraded'?2:0,...alerts.map(a=>a.level),unavailable?1:0);
    return {node,age,fresh,cpu,ram,disk,alerts,unavailable,state,severity,attention:!disabled&&(severity>0)};
  }
  function summarize(rows){
    const cpus=rows.filter(r=>r.cpu!==null),sum=key=>{
      const available=rows.filter(r=>r[key]);
      return {count:available.length,total:available.reduce((s,r)=>s+r[key].total,0),used:available.reduce((s,r)=>s+r[key].used,0),free:available.reduce((s,r)=>s+r[key].free,0)};
    };
    return {count:rows.length,online:rows.filter(r=>!['offline','unknown','disabled'].includes(r.state)).length,
      attention:rows.filter(r=>r.attention).length,missing:rows.filter(r=>r.unavailable).length,
      cpuCount:cpus.length,cpuMax:cpus.length?Math.max(...cpus.map(r=>r.cpu)):null,ram:sum('ram'),disk:sum('disk')};
  }
  function sort(rows,key){
    const val=r=>key==='cpu'?r.cpu:key==='ram'?r.ram?.percent:key==='disk'?r.disk?.percent:r.severity;
    return [...rows].sort((a,b)=>{
      if(key!=='name') {const x=val(a),y=val(b);if(x==null&&y!=null)return 1;if(y==null&&x!=null)return -1;if(x!==y)return y-x;}
      return a.node.name.localeCompare(b.node.name,'ru');
    });
  }
  function bucket(samples){
    if(!samples.length)return {state:'unknown',last:'unknown',failures:0,count:0};
    const ordered=[...samples].sort((a,b)=>a.minute-b.minute),last=ordered[ordered.length-1].state;
    const failures=ordered.filter(s=>s.state==='offline'||s.state==='degraded').length;
    return {state:last==='healthy'&&failures?'degraded':last,last,failures,count:ordered.length};
  }
  const api={describe,summarize,sort,capacity,bucket};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.RimeMonitor=api;
})(typeof window!=='undefined'?window:globalThis);
