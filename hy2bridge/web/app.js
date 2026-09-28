"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const state = {token:null,overview:null,traffic:null,events:[],busy:false,plan:null,draft:null,jobTimer:null,revision:0};
  const titles={overview:"Обзор",traffic:"Трафик",events:"События",nodes:"Ноды",deploy:"Добавить ноду",users:"Пользователи",monitoring:"Мониторинг",node:"Нода"};
  const statusNames={healthy:"В работе",offline:"Нет связи",degraded:"Есть ошибки",unknown:"Нет данных"};
  const protocolNames={hysteria2:"Hysteria2",xray:"VLESS / Xray",vless:"VLESS"};
  const bytes=n=>n==null?"—":new Intl.NumberFormat("ru-RU",{maximumFractionDigits:2}).format(n/1024**(n>=1024**4?4:n>=1024**3?3:n>=1024**2?2:n>=1024?1:0))+" "+(n>=1024**4?"TiB":n>=1024**3?"GiB":n>=1024**2?"MiB":n>=1024?"KiB":"B");
  const stamp=n=>n==null?"Нет данных":new Date(typeof n==="number"?n*1000:n).toLocaleString("ru-RU",{timeZone:"UTC",day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"})+" UTC";
  const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!=null)n.textContent=String(text);if(cls)n.className=cls;return n;};
  function empty(target,text="Данных за выбранный период пока нет."){target.replaceChildren(el("p",text,"empty"));}
  function showError(message){$("global-error").textContent=message;$("global-error").hidden=!message;}
  async function api(path,options={}){
    const abort=new AbortController();const timer=setTimeout(()=>abort.abort(),20000);
    try{
      const headers={...options.headers};if(state.token)headers.Authorization="Bearer "+state.token;
      if(options.json){headers["Content-Type"]="application/json";options.body=JSON.stringify(options.json);delete options.json;}
      const response=await fetch(path,{...options,headers,signal:abort.signal,credentials:"same-origin",cache:"no-store"});
      if(!response.ok){let detail;try{detail=(await response.json()).detail;}catch{}
        if(response.status===401&&state.token){logout();throw new Error("Сессия завершена. Войдите снова.");}
        throw new Error(typeof detail==="string"?detail:`Запрос не выполнен (${response.status}). Проверьте поля и повторите.`);
      }
      return options.raw?response:response.status===204?null:response.json();
    }catch(error){if(error.name==="AbortError")throw new Error("Сервер не ответил вовремя. Данные не обновлены.");throw error;}finally{clearTimeout(timer);}
  }
  function badge(status){return el("span",statusNames[status]||status,"badge "+status);}
  function table(target,headers,rows){
    if(!rows.length){empty(target);return;}
    const t=el("table"),thead=el("thead"),tr=el("tr");
    headers.forEach(h=>{const th=el("th",h);th.scope="col";tr.append(th);});thead.append(tr);t.append(thead);
    const body=el("tbody");for(const row of rows){const tr=el("tr");for(const value of row){const td=el("td");if(value instanceof Node)td.append(value);else td.textContent=value==null?"—":String(value);tr.append(td);}body.append(tr);}t.append(body);target.replaceChildren(t);
  }
  function chart(target,series){
    if(!series.length){empty(target);return;}
    const ns="http://www.w3.org/2000/svg",svg=document.createElementNS(ns,"svg");svg.setAttribute("viewBox","0 0 700 225");svg.setAttribute("role","img");
    const title=document.createElementNS(ns,"title");title.textContent="Объём трафика Hysteria2 и VLESS/Xray по часам. Точные значения доступны в таблице отчёта.";svg.append(title);
    const valid=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0;
    const max=Math.max(...series.flatMap(x=>[x.hysteria2,x.xray].filter(valid)),1);
    for(let i=0;i<4;i++){const y=25+i*49,line=document.createElementNS(ns,"line");Object.entries({x1:58,x2:686,y1:y,y2:y,stroke:"#263449","stroke-dasharray":"3 5"}).forEach(([k,v])=>line.setAttribute(k,v));svg.append(line);const text=document.createElementNS(ns,"text");text.setAttribute("x","0");text.setAttribute("y",y+3);text.textContent=bytes(max*(3-i)/3);svg.append(text);}
    ["hysteria2","xray"].forEach((key,index)=>{let segment=[];const color=index?"#67bfff":"#6ee7b7";const draw=()=>{if(!segment.length)return;const item=document.createElementNS(ns,segment.length===1?"circle":"polyline"),attrs=segment.length===1?{cx:segment[0][0],cy:segment[0][1],r:4,fill:color}:{points:segment.map(p=>p.join(',')).join(' '),fill:'none',stroke:color,'stroke-width':2.5,'stroke-linejoin':'round'};Object.entries(attrs).forEach(([k,v])=>item.setAttribute(k,v));svg.append(item);segment=[];};series.forEach((x,i)=>{if(!valid(x[key])){draw();return;}segment.push([58+i*628/Math.max(series.length-1,1),172-147*x[key]/max]);});draw();});
    [...new Set([0,Math.floor((series.length-1)/2),series.length-1])].forEach(i=>{const text=document.createElementNS(ns,"text");text.setAttribute("x",58+i*628/Math.max(series.length-1,1));text.setAttribute("y","205");text.setAttribute("text-anchor",i===0?"start":i===series.length-1?"end":"middle");text.textContent=series[i].hour.slice(5,16).replace(" "," · ");svg.append(text);});target.replaceChildren(svg);
  }
  function eventList(target,events){
    if(!events.length){empty(target,"Открытых ошибок нет.");return;}
    target.replaceChildren();for(const item of events.slice(0,5)){const row=el("div",null,"event"),icon=el("span",item.resolved_at?"✓":"!","event-icon"),body=el("div");body.append(el("p",item.message),el("time",item.node+" · "+stamp(item.last_at)));row.append(icon,body);target.append(row);}
  }
  function nodeName(node){const d=el("div");d.append(el("strong",node.name),el("span",node.address||node.id,"small muted"));return d;}
  function renderNodes(nodes){
    table($("overview-nodes"),["Нода","Протокол","Состояние","TCP / экземпляры Hy2","Свободно на диске","Последний сигнал"],nodes.map(n=>[nodeName(n),protocolNames[n.protocol]||n.protocol,badge(n.state),window.RimeConsole?.connectionLink(n)??n.metrics.online_connections,bytes(n.metrics.disk_free_bytes),n.status_source==="marzban"?"Управляется Rime":stamp(n.seen_at)]));
    const grid=$("nodes-grid");grid.replaceChildren();if(!nodes.length){empty(grid,"Нод пока нет. Добавьте первый сервер.");return;}
    for(const n of nodes){const card=el("article",null,"card node-card"),header=el("header"),name=el("div");name.append(el("h2",n.name),el("p",protocolNames[n.protocol]||n.protocol,"small muted"));header.append(name,badge(n.state));card.append(header,el("p",n.address||n.id,"address"));const dl=el("dl");for(const [label,value] of [[window.RimeConsole?.connectionLabel(n)||"Подключения",window.RimeConsole?.connectionLink(n)??n.metrics.online_connections??"—"],["Загрузка ОС",n.metrics.cpu_load1==null?"—":n.metrics.cpu_load1.toFixed(2)],["Доступно RAM",bytes(n.metrics.mem_available_bytes)],["Свободно на диске",bytes(n.metrics.disk_free_bytes)]]){const d=el("div");const valueCell=el("dd");if(value instanceof Node)valueCell.append(value);else valueCell.textContent=value;d.append(el("dt",label),valueCell);dl.append(d);}card.append(dl,el("footer",n.status_source==="marzban"?"Состояние из Rime · ресурсы ОС: "+stamp(n.seen_at):`Сигнал: ${stamp(n.seen_at)} · ${n.monitoring_only?"Мониторинг ОС · прежний Hy2-мост":n.metrics.accounting_durable?"Долговечный учёт":"Обычные счётчики"}`));grid.append(card);}
    const selected=$("filter-node").value,select=$("filter-node");select.replaceChildren(new Option("Все ноды",""));for(const n of nodes)select.add(new Option(n.name,n.id));if(!nodes.some(n=>n.id==='xray:local'))select.add(new Option("Сервер панели","xray:local"));select.value=selected;window.RimeConsole?.nodeLinks();
  }
  function renderEvents(){if(window.RimeConsole){window.RimeConsole.events();return;}const events=state.events.filter(x=>!$("events-open").checked||!x.resolved_at);table($("events-table"),["Время UTC","Нода","Событие","Состояние","Повторов"],events.map(x=>[stamp(x.last_at),x.node,x.message,badge(x.resolved_at?"healthy":"degraded"),x.occurrences]));}
  function renderOverview(data,traffic){
    const online=data.nodes.filter(n=>n.protocol==='hysteria2'&&n.state!=="unknown"&&n.state!=="offline"&&n.metrics.online_connections!=null);
    $("metric-nodes").textContent=`${data.summary.healthy} / ${data.nodes.length}`;$("metric-nodes-detail").textContent=`Нет связи: ${data.summary.offline} · Нет данных: ${data.summary.unknown}`;
    $("metric-online").textContent=online.length?online.reduce((s,n)=>s+n.metrics.online_connections,0):"—";
    const open=data.events.filter(e=>!e.resolved_at);$("metric-errors").textContent=open.length;$("event-badge").textContent=open.length;$("event-badge").hidden=!open.length;
    eventList($("overview-events"),open);renderNodes(data.nodes);
    if(traffic){$("metric-traffic").textContent=bytes(traffic.total);chart($("overview-chart"),traffic.series);}
  }
  function reportParams(){const q=new URLSearchParams();const start=$("filter-start").value,end=$("filter-end").value;if(start)q.set("start",start+"T00:00:00Z");if(end){const d=new Date(end+"T00:00:00Z");d.setUTCDate(d.getUTCDate()+1);q.set("end",d.toISOString());}for(const key of ["protocol","node","user","tag"]){const value=$("filter-"+key).value.trim();if(value)q.set(key==="user"?"username":key,value);}return q;}
  async function loadTraffic(){
    $("traffic-status").textContent="Загрузка отчёта…";
    try{const data=await api("/api/fleet/traffic?"+reportParams());state.traffic=data;window.RimeConsole?.report(data);$("traffic-total").textContent=bytes(data.total)+" за период";chart($("traffic-chart"),data.series);
      table($("traffic-users"),["Пользователь","Hysteria2","VLESS / Xray","Всего"],data.users.map(r=>[r.username,bytes(r.hysteria2),bytes(r.xray),bytes(r.hysteria2+r.xray)]));
      table($("traffic-rows"),["Час UTC","Нода","Пользователь","Протокол","Отдача","Загрузка","Всего"],data.rows.map(r=>[r.hour,r.node,r.username,protocolNames[r.protocol],bytes(r.tx),bytes(r.rx),bytes(r.total)]));
      $("traffic-status").textContent=`Строк: ${data.rows.length}. Обновлено ${stamp(Date.now()/1000)}.`;
    }catch(e){$("traffic-status").textContent=e.message;}
  }
  async function refresh(){
    if(!state.token||state.busy)return;state.busy=true;const revision=state.revision;$("refresh").disabled=true;
    try{const results=await Promise.allSettled([api("/api/fleet/overview"),api("/api/fleet/traffic"),api("/api/fleet/events")]);
      if(revision!==state.revision)return;
      const errors=results.filter(r=>r.status==="rejected").map(r=>r.reason.message);showError(errors.join(" "));
      if(results[0].status==="fulfilled"){state.overview=results[0].value;renderOverview(state.overview,results[1].status==="fulfilled"?results[1].value:null);}
      if(results[2].status==="fulfilled"){state.events=results[2].value;renderEvents();}
      $("freshness").textContent=errors.length?"Часть данных не обновлена":"Обновлено "+new Date().toLocaleTimeString("ru-RU");
      if(location.hash==="#traffic")await loadTraffic();await window.RimeConsole?.refresh();
    }finally{state.busy=false;$("refresh").disabled=false;if(revision!==state.revision&&state.token)refresh();}
  }
  function resetWizard(){state.plan=null;state.draft=null;$("deploy-form").reset();$("deploy-form").hidden=false;for(const id of ["plan-card","job-card","host-key-card"])$(id).hidden=true;$("job-done").hidden=true;$("deploy-confirm").disabled=false;$("step-2").classList.remove("active");$("step-3").classList.remove("active");}
  function navigate(){const page=(location.hash.slice(1)||"overview").split("/")[0];const selected=titles[page]?page:"overview";document.querySelectorAll(".page").forEach(n=>n.hidden=n.id!=="page-"+selected);document.querySelectorAll("nav a").forEach(a=>{if(a.dataset.page===selected||(selected==="deploy"&&a.dataset.page==="nodes"))a.setAttribute("aria-current","page");else a.removeAttribute("aria-current");});$("breadcrumb").textContent=titles[selected];if(selected==="deploy"&&!$("job-done").hidden)resetWizard();if(selected==="traffic"&&state.token)loadTraffic();window.RimeConsole?.navigate(selected);$("main").focus({preventScroll:true});}
  function logout(){document.querySelectorAll("dialog[open]").forEach(d=>d.close());state.token=null;state.draft=null;state.plan=null;clearTimeout(state.jobTimer);resetWizard();$("app").hidden=true;$("login").hidden=false;$("login-password").value="";$("login-user").focus();}
  $("login-form").addEventListener("submit",async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;$("login-error").textContent="";try{const username=$("login-user").value;const form=new URLSearchParams({username,password:$("login-password").value});const result=await api("/api/admin/token",{method:"POST",body:form,headers:{"Content-Type":"application/x-www-form-urlencoded"}});state.token=result.access_token;await api("/api/fleet/overview");$("avatar").textContent=username.slice(0,1).toUpperCase();$("login-password").value="";$("login").hidden=true;$("app").hidden=false;navigate();await refresh();}catch(err){state.token=null;$("login-error").textContent=err.message;}finally{button.disabled=false;}});
  $("logout-mobile").addEventListener("click",logout);$("logout").addEventListener("click",logout);$("refresh").addEventListener("click",refresh);$("filters").addEventListener("submit",e=>{e.preventDefault();loadTraffic();});$("events-open").addEventListener("change",renderEvents);window.addEventListener("hashchange",navigate);
  $("export").addEventListener("click",async e=>{e.currentTarget.disabled=true;try{const r=await api("/api/fleet/traffic.csv?"+reportParams(),{raw:true});const url=URL.createObjectURL(await r.blob());const a=el("a");a.href=url;a.download="traffic.csv";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(err){showError(err.message);}finally{$("export").disabled=false;}});
  $("deploy-form").addEventListener("submit",async e=>{e.preventDefault();$("deploy-error").textContent="";$("preflight").disabled=true;try{const data=Object.fromEntries(new FormData(e.currentTarget));data.ssh_port=Number(data.ssh_port);data.vpn_port=Number(data.vpn_port);if(!data.private_key.trim()&&!data.password)throw new Error("Укажите SSH-ключ или пароль.");state.draft=data;const scan=await api("/api/fleet/provision/host-key",{method:"POST",json:{host:data.host,ssh_port:data.ssh_port}});state.draft.fingerprint=scan.fingerprint;$("host-key").textContent=scan.fingerprint;$("trust-host").checked=false;$("verify-host").disabled=true;$("host-key-card").hidden=false;$("host-key-card").scrollIntoView({block:"center"});}catch(err){$("deploy-error").textContent=err.message;}finally{$("preflight").disabled=false;}});
  $("trust-host").addEventListener("change",()=>$("verify-host").disabled=!$("trust-host").checked);
  $("verify-host").addEventListener("click",async()=>{$("verify-host").disabled=true;try{const plan=await api("/api/fleet/provision/preflight",{method:"POST",json:state.draft});state.plan=plan;const list=el("dl");for(const [key,value] of Object.entries(plan.summary||{})){list.append(el("dt",key,"muted"),el("dd",value));}const checks=el("ul");for(const c of plan.checks||[])checks.append(el("li",(c.passed?"✓ ":"! ")+c.message));$("plan-details").replaceChildren(list,checks);$("plan-card").hidden=false;$("host-key-card").hidden=true;$("deploy-form").hidden=true;$("step-2").classList.add("active");$("deploy-confirm").disabled=!plan.ready;$("plan-card").scrollIntoView({block:"start"});}catch(err){$("deploy-error").textContent=err.message;$("deploy-error").scrollIntoView({block:"center"});}finally{$("verify-host").disabled=false;}});
  $("plan-cancel").addEventListener("click",()=>{$("plan-card").hidden=true;$("deploy-form").hidden=false;state.plan=null;});
  async function pollJob(id){try{const job=await api("/api/fleet/provision/jobs/"+encodeURIComponent(id));$("job-state").textContent=job.message||job.state;$("job-steps").replaceChildren(...(job.steps||[]).map(s=>el("li",s.message)));if(["succeeded","failed","rolled_back"].includes(job.state)){$("job-done").hidden=false;refresh();}else state.jobTimer=setTimeout(()=>pollJob(id),1500);}catch(err){$("job-state").textContent=err.message;}}
  $("deploy-confirm").addEventListener("click",async()=>{$("deploy-confirm").disabled=true;try{const job=await api("/api/fleet/provision/deploy",{method:"POST",json:{plan_id:state.plan.id}});state.draft=null;$("deploy-form").reset();$("plan-card").hidden=true;$("job-card").hidden=false;$("step-3").classList.add("active");pollJob(job.id);}catch(err){showError(err.message);$("deploy-confirm").disabled=false;}});
  const now=new Date(),start=new Date(now);start.setUTCDate(start.getUTCDate()-6);$("filter-start").value=start.toISOString().slice(0,10);$("filter-end").value=now.toISOString().slice(0,10);
  function invalidateNodes(aliases){state.revision++;state.traffic=null;state.events=state.events.filter(e=>!aliases.includes(e.node));if(state.overview){state.overview.nodes=state.overview.nodes.filter(n=>!aliases.includes(n.id));state.overview.events=state.events;state.overview.summary=Object.fromEntries(['healthy','offline','degraded','unknown'].map(s=>[s,state.overview.nodes.filter(n=>n.state===s).length]));renderOverview(state.overview,null);}$("overview-chart").replaceChildren();$("metric-traffic").textContent='…';for(const id of ['traffic-users','traffic-rows','traffic-by-node','traffic-chart','edit-nodes'])$(id)?.replaceChildren();}
  window.Rime={api,el,table,chart,bytes,stamp,state,badge,refresh,showError,loadTraffic,invalidateNodes};
  setInterval(()=>{if(!document.hidden)refresh();},10000);
})();
