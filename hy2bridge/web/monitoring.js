/* Resource calculations shared by the overview and its regression checks. */
(function(root){
  'use strict';
  const valid=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
  const percent=n=>valid(n)&&n<=100?n:null;
  function capacity(total,free){
    if(!valid(total)||total===0||!valid(free)||free>total)return null;
    return {total,free,used:total-free,percent:100*(total-free)/total};
  }
  function access(node,now){
    if(node.enabled===0||node.native_status==='disabled')return {state:'disabled',label:'Отключена',detail:'Нода отключена в панели'};
    const age=valid(node.seen_at)?Math.max(0,now-node.seen_at):null;
    const resourcesFresh=age!==null&&age<=30&&node.seen_at<=now+15;
    if(node.role==='panel')return {state:resourcesFresh?'healthy':'unknown',label:resourcesFresh?'Панель отвечает':'Ответ устарел',detail:'Сервер панели'};
    if(node.quota?.blocked)return {state:'offline',label:'Квота исчерпана',detail:'VPN-доступ ограничен лимитом ноды'};
    const tunnel=node.tunnel_access;
    if(tunnel?.active){
      const fresh=valid(tunnel.checked_at)&&now-tunnel.checked_at<=180&&tunnel.fresh!==false;
      const passed=Object.hasOwn(tunnel,'vpn_passed')?tunnel.vpn_passed:tunnel.passed;
      return {state:!fresh||passed==null?'unknown':passed?'healthy':'offline',
        label:!fresh?'Проба туннеля устарела':passed==null?'VPN через вход не проверен':passed?'VPN через '+tunnel.entry_name:'VPN через вход недоступен',
        detail:'Сервер панели → '+tunnel.entry_name+' → выходная нода',sampleAge:valid(tunnel.checked_at)?now-tunnel.checked_at:null};
    }
    const sample=node.client_access||{},sampleAge=valid(sample.checked_at)?Math.max(0,now-sample.checked_at):null;
    const fresh=sampleAge!==null&&sampleAge<=180&&sample.checked_at<=now+15&&sample.fresh!==false;
    if(resourcesFresh&&node.metrics?.service_healthy===false&&(!fresh||node.seen_at>sample.checked_at))return {state:'offline',label:'Служба остановлена',detail:'Свежая проверка на сервере',sampleAge};
    if(fresh&&sample.state==='available'&&sample.passed!==false)return {state:'healthy',label:'VPN доступен',detail:sample.origin||'Клиентская проба',sampleAge};
    if(fresh&&sample.state==='unavailable')return {state:'offline',label:'VPN недоступен',detail:sample.origin||'Клиентская проба',sampleAge};
    return {state:'unknown',label:sample.checked_at&&!fresh?'Проба устарела':'VPN не проверен',detail:sample.origin||'Нужна клиентская проба',sampleAge};
  }
  function chartScale(values){
    const maximum=values.reduce((maximum,value)=>valid(value)?Math.max(maximum,value):maximum,0);
    const unitIndex=Math.min(4,Math.max(0,Math.floor(Math.log2(Math.max(maximum,1))/10)));
    const unitBytes=1024**unitIndex,scaled=Math.max(maximum/unitBytes,1);
    const power=10**Math.floor(Math.log10(scaled));
    const step=[1,2,5,10].find(value=>value*power>=scaled)||10;
    return {maximum,upper:step*power*unitBytes,unitBytes,unit:['B','KiB','MiB','GiB','TiB'][unitIndex]};
  }
  function describe(node,now){
    const m=node.metrics||{},age=valid(node.seen_at)?Math.max(0,now-node.seen_at):null;
    const fresh=age!==null&&age<=30&&node.seen_at<=now+15;
    const cpu=fresh?percent(m.cpu_percent):null;
    const ram=fresh?capacity(m.mem_total_bytes,m.mem_available_bytes):null;
    const disk=fresh?capacity(m.disk_total_bytes,m.disk_free_bytes):null;
    const alerts=[];
    if(node.tunnel_access?.active&&node.tunnel_access.fresh&&node.tunnel_access.proxies_passed===false)alerts.push({text:'Прокси через вход требуют проверки',level:1});
    if(node.tunnel_access?.active&&node.tunnel_access.fresh&&node.tunnel_access.ssh_passed===false)alerts.push({text:'SSH-маршрут через вход недоступен',level:1});
    if(node.quota?.enabled&&node.quota.percent>=80)alerts.push({text:node.quota.blocked?'Лимит VPN исчерпан':'Трафик ≥'+(node.quota.percent>=95?'95%':'80%'),level:node.quota.percent>=95?2:1});
    if(cpu!==null&&cpu>=80)alerts.push({text:'CPU '+(cpu>=95?'критично':'высокая загрузка'),level:cpu>=95?2:1});
    if(ram&&ram.percent>=80)alerts.push({text:'RAM '+(ram.percent>=95?'критично':'высокая загрузка'),level:ram.percent>=95?2:1});
    if(disk&&disk.percent>=80)alerts.push({text:disk.percent>=90?'Диск: мало места':'Диск заполнен ≥80%',level:disk.percent>=90?2:1});
    const clientAccess=access(node,now);
    if(node.role!=='panel'&&node.client_access){
      const a=node.client_access;
      if(clientAccess.state==='offline')alerts.push({text:clientAccess.label,level:2});
      else if(clientAccess.state==='unknown')alerts.push({text:!a.checked_at?'Нет клиентской пробы':clientAccess.label,level:1});
    }
    if(node.status_source==='marzban'&&m.control_healthy===false)alerts.push({text:'Нет прямой связи управления',level:1});
    const unavailable=cpu===null||!ram||!disk;
    const disabled=node.enabled===0||node.native_status==='disabled';
    const state=disabled?'disabled':(node.state==='offline'||(age!==null&&!fresh&&node.status_source!=='marzban'))?'offline':node.state==='unknown'?'unknown':node.state;
    const accessSeverity=node.role==='panel'||disabled?0:clientAccess.state==='offline'?2:clientAccess.state==='unknown'?1:0;
    const severity=Math.max(state==='offline'?4:state==='degraded'?2:0,...alerts.map(a=>a.level),unavailable?1:0,accessSeverity);
    return {node,age,fresh,cpu,ram,disk,alerts,unavailable,state,access:clientAccess,severity,attention:!disabled&&(severity>0)};
  }
  function summarize(rows){
    const cpus=rows.filter(r=>r.cpu!==null),sum=key=>{
      const available=rows.filter(r=>r[key]);
      return {count:available.length,total:available.reduce((s,r)=>s+r[key].total,0),used:available.reduce((s,r)=>s+r[key].used,0),free:available.reduce((s,r)=>s+r[key].free,0)};
    };
    const vpn=rows.filter(r=>r.node.role!=='panel'&&r.state!=='disabled');
    return {count:rows.length,online:rows.filter(r=>!['offline','unknown','disabled'].includes(r.state)).length,
      vpnCount:vpn.length,vpnAvailable:vpn.filter(r=>r.access.state==='healthy').length,vpnFailed:vpn.filter(r=>r.access.state==='offline').length,
      vpnUnknown:vpn.filter(r=>r.access.state==='unknown').length,
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
  const api={describe,summarize,sort,capacity,bucket,access,chartScale};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.RimeMonitor=api;
})(typeof window!=='undefined'?window:globalThis);
