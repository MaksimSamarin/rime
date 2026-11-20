"use strict";
(() => {
  const $ = id => document.getElementById(id);
  let storage;try{storage=window.sessionStorage;}catch{}
  const session=window.RimeSession.createSession({storage});
  const state = {overview:null,traffic:null,events:[],busy:false,plan:null,draft:null,jobTimer:null,planTimer:null,currentJob:null,jobFailures:0,revision:0};
  Object.defineProperty(state,"token",{get:()=>session.token});
  let refreshOwner=null,trafficRequest=0,overviewTraffic=null,overviewTrafficAt=0,trafficAt=0,lastInteraction=0;
  const pageName=()=>{const page=(location.hash.slice(1)||"overview").split("/")[0];return titles[page]?page:"overview";};
  function canAutoRefresh(){
    const active=document.activeElement,selected=window.getSelection?.();
    return pageName()!=='docs'&&!!state.token&&!document.hidden&&!document.querySelector('dialog[open]')&&
      !['INPUT','TEXTAREA','SELECT'].includes(active?.tagName)&&!selected?.toString()&&Date.now()-lastInteraction>1500;
  }
  for(const event of ['pointerdown','keydown'])document.addEventListener(event,()=>{lastInteraction=Date.now();},{passive:true});
  const titles={overview:"Обзор",traffic:"VPN-трафик",events:"События",nodes:"Ноды",deploy:"Добавить ноду",users:"Пользователи",monitoring:"Мониторинг",node:"Нода",relays:"Туннели",docs:"Документация"};
  const statusNames={healthy:"Служба работает",offline:"Нет связи",degraded:"Есть ошибки",unknown:"Нет данных"};
  const protocolNames={hysteria2:"Hysteria2",xray:"VLESS / Xray",vless:"VLESS"};
  const byteFormat=new Intl.NumberFormat("ru-RU",{maximumFractionDigits:2});
  const timeFormat=new Intl.DateTimeFormat("ru-RU",{timeZone:"UTC",day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"});
  const bytes=n=>n==null?"—":byteFormat.format(n/1024**(n>=1024**4?4:n>=1024**3?3:n>=1024**2?2:n>=1024?1:0))+" "+(n>=1024**4?"TiB":n>=1024**3?"GiB":n>=1024**2?"MiB":n>=1024?"KiB":"B");
  const stamp=n=>n==null?"Нет данных":timeFormat.format(new Date(typeof n==="number"?n*1000:n))+" UTC";
  const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!=null)n.textContent=String(text);if(cls)n.className=cls;return n;};
  function empty(target,text="Данных за выбранный период пока нет."){target.replaceChildren(el("p",text,"empty"));}
  function showError(message){$("global-error").textContent=message;$("global-error").hidden=!message;}
  const baseApi=window.RimeSession.createApi({session,fetch:(...args)=>fetch(...args),onUnauthorized:()=>logout("Сессия завершена. Войдите снова.")});
  async function api(path,options={}){
    const finish=window.RimeProgress?.activity(path,options.method)||(()=>{});
    try{const value=await baseApi(path,options);finish(true);return value;}
    catch(error){finish(false);throw error;}
  }
  api.abortAll=baseApi.abortAll;
  function badge(status){return el("span",statusNames[status]||status,"badge "+status);}
  function nodeBadge(node){
    if(window.RimeMonitor){const access=window.RimeMonitor.access(node,Date.now()/1000),sample=node.tunnel_access?.active?node.tunnel_access:node.client_access,item=el('span',access.label,'badge '+access.state);item.title=access.detail+(sample?.checked_at?' · '+stamp(sample.checked_at):'');return item;}
    if(node.role==='panel')return badge(node.state);
    if(node.enabled===0||node.native_status==='disabled')return el('span','Отключена','badge unknown');
    const a=node.client_access;
    if(!a||a.state==='unknown'||!a.checked_at||Date.now()/1000-a.checked_at>180)return el('span','VPN не проверен','badge unknown');
    const item=el('span',a.state==='available'?'Проба VPN: ОК':'Проба VPN: сбой','badge '+(a.state==='available'?'healthy':'offline'));
    item.title=(a.origin||'Источник не указан')+' · '+stamp(a.checked_at)+' · '+(a.target_ip||'');return item;
  }
  function table(target,headers,rows){
    if(!rows.length){empty(target);return;}
    const t=el("table"),thead=el("thead"),tr=el("tr");
    headers.forEach(h=>{const th=el("th",h);th.scope="col";tr.append(th);});thead.append(tr);t.append(thead);
    const body=el("tbody");t.append(body);let offset=0;
    const more=el('button','Показать ещё 100 строк','button secondary');more.type='button';
    const render=()=>{const end=Math.min(offset+100,rows.length),fragment=document.createDocumentFragment();for(;offset<end;offset++){const tr=el('tr');for(const value of rows[offset]){const td=el('td');if(value instanceof Node)td.append(value);else td.textContent=value==null?'—':String(value);tr.append(td);}fragment.append(tr);}body.append(fragment);more.hidden=offset>=rows.length;more.textContent=`Показать ещё · ${offset} из ${rows.length}`;};
    more.addEventListener('click',render);render();target.replaceChildren(t,more);
  }
  const chartStates=new WeakMap();
  const chartTime=new Intl.DateTimeFormat('ru-RU',{timeZone:'UTC',day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
  const protocolGroups=[{key:'hysteria2',label:'Hysteria2',color:'hy'},{key:'xray',label:'VLESS / Xray',color:'xr'}];
  function chart(target,series,groups=protocolGroups){
    let entry=chartStates.get(target);
    if(!entry){
      entry={series:[],width:0,selected:null,userSelected:false};chartStates.set(target,entry);
      if(window.ResizeObserver){entry.observer=new ResizeObserver(()=>{if(target.clientWidth>0&&Math.abs(target.clientWidth-entry.width)>4)requestAnimationFrame(()=>drawTrafficChart(target,entry));});entry.observer.observe(target);}
    }
    entry.series=Array.isArray(series)?series:[];entry.groups=groups.map((group,index)=>({...group,color:group.color||'series-'+index}));drawTrafficChart(target,entry);
  }
  function drawTrafficChart(target,entry){
    if(chartStates.get(target)!==entry)return;
    const series=entry.series,groups=entry.groups,valid=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0;
    if(!series.length){empty(target,'За выбранный период нет измерений.');return;}
    const width=Math.max(300,Math.floor(target.clientWidth||900)),height=width<550?240:target.id==='traffic-chart'?300:235;
    entry.width=width;
    const left=58,right=18,top=32,bottom=height-42,plotWidth=width-left-right,plotHeight=bottom-top;
    const values=series.flatMap(row=>groups.map(group=>row[group.key]));
    const scale=window.RimeMonitor?.chartScale(values)||{upper:Math.max(1,...values.filter(valid)),unitBytes:1,unit:'B'};
    const times=series.map(row=>Date.parse(row.hour.replace(' ','T')+(row.hour.endsWith('Z')?'':'Z')));
    const timed=times.every(Number.isFinite)&&times[times.length-1]>times[0];
    const x=index=>left+(timed?(times[index]-times[0])/(times[times.length-1]-times[0]):index/Math.max(1,series.length-1))*plotWidth;
    const y=value=>bottom-value/scale.upper*plotHeight;
    const label=index=>Number.isFinite(times[index])?chartTime.format(times[index]):series[index].hour;
    const make=(tag,attrs={},text)=>{const node=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value] of Object.entries(attrs))node.setAttribute(key,value);if(text!=null)node.textContent=text;return node;};
    const svg=make('svg',{viewBox:`0 0 ${width} ${height}`,width,height,role:'img',tabindex:'0',class:'dashboard-chart','aria-label':'Трафик по часам. Для выбора замера используйте стрелки влево и вправо.'});
    svg.append(make('title',{},`Учтённый трафик. Шкала от 0 до ${bytes(scale.upper)} за час.`));
    svg.append(make('text',{x:left,y:16,class:'chart-unit'},scale.unit+' за час · UTC'));
    for(let index=0;index<=4;index++){
      const tickY=top+plotHeight*index/4;
      svg.append(make('line',{x1:left,x2:width-right,y1:tickY,y2:tickY,class:index===4?'chart-baseline':'chart-gridline'}));
      svg.append(make('text',{x:left-10,y:tickY+4,'text-anchor':'end'},byteFormat.format(scale.upper*(1-index/4)/scale.unitBytes)));
    }
    for(const {key,color} of groups){
      let segment=[];
      const finish=()=>{if(!segment.length)return;svg.append(segment.length===1?make('circle',{cx:segment[0][0],cy:segment[0][1],r:3,class:'chart-point '+color}):make('polyline',{points:segment.map(point=>point.join(',')).join(' '),class:'chart-line '+color}));segment=[];};
      series.forEach((row,index)=>{if(!valid(row[key])){finish();return;}if(index&&timed&&times[index]-times[index-1]>5400000)finish();segment.push([x(index),y(row[key])]);});finish();
    }
    const tickCount=width<550?2:width<900?3:5;
    for(const index of [...new Set(Array.from({length:tickCount},(_,i)=>Math.round((series.length-1)*i/(tickCount-1))))]){
      svg.append(make('text',{x:x(index),y:height-12,'text-anchor':index===0?'start':index===series.length-1?'end':'middle'},label(index)));
    }
    const cursor=make('g',{'aria-hidden':'true'}),cursorLine=make('line',{y1:top,y2:bottom,class:'chart-cursor'}),dots=groups.map(group=>make('circle',{r:4,class:'chart-point '+group.color}));
    cursor.append(cursorLine,...dots);svg.append(cursor);
    const readout=el('div',null,'chart-readout');readout.setAttribute('role','status');readout.setAttribute('aria-live','off');
    const select=index=>{
      entry.selected=Math.max(0,Math.min(series.length-1,index));const row=series[entry.selected];
      cursorLine.setAttribute('x1',x(entry.selected));cursorLine.setAttribute('x2',x(entry.selected));
      groups.forEach(({key},i)=>{dots[i].hidden=!valid(row[key]);dots[i].setAttribute('visibility',valid(row[key])?'visible':'hidden');if(valid(row[key])){dots[i].setAttribute('cx',x(entry.selected));dots[i].setAttribute('cy',y(row[key]));}});
      readout.replaceChildren(el('time',label(entry.selected)+' UTC'),...groups.map(({key,label,color})=>el('span',label+' '+(valid(row[key])?bytes(row[key]):'нет данных'),color+'-value')));
    };
    let pointerFrame=null;
    const pointer=event=>{const rect=svg.getBoundingClientRect(),position=(event.clientX-rect.left)*width/rect.width;let closest=0;for(let i=1;i<series.length;i++)if(Math.abs(x(i)-position)<Math.abs(x(closest)-position))closest=i;entry.userSelected=true;cancelAnimationFrame(pointerFrame);if(closest!==entry.selected)pointerFrame=requestAnimationFrame(()=>select(closest));};
    svg.addEventListener('pointermove',pointer);svg.addEventListener('pointerdown',pointer);
    svg.addEventListener('keydown',event=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();entry.userSelected=true;readout.setAttribute('aria-live','polite');select(event.key==='Home'?0:event.key==='End'?series.length-1:(entry.selected??0)+(event.key==='ArrowRight'?1:-1));});
    let selected=entry.userSelected&&entry.selected!=null?Math.min(entry.selected,series.length-1):series.length-1;
    if(!entry.userSelected)while(selected>0&&!groups.some(group=>valid(series[selected][group.key])))selected--;
    target.replaceChildren(svg,readout);select(selected);
  }
  function eventList(target,events){
    if(!events.length){empty(target,"Открытых ошибок нет.");return;}
    target.replaceChildren();for(const item of events.slice(0,5)){const row=el("div",null,"event"),icon=el("span",item.resolved_at?"✓":"!","event-icon"),body=el("div");body.append(el("p",item.message),el("time",item.node+" · "+stamp(item.last_at)));row.append(icon,body);target.append(row);}
  }
  function nodeName(node){const d=el("div");d.append(el("strong",node.name),el("span",node.address||node.id,"small muted"));return d;}
  function renderNodes(nodes){
    table($("overview-nodes"),["Нода","Протокол","Состояние","TCP / экземпляры Hy2","Свободно на диске","Последний сигнал"],nodes.map(n=>[nodeName(n),protocolNames[n.protocol]||n.protocol,nodeBadge(n),window.RimeConsole?.connectionLink(n)??n.metrics.online_connections,bytes(n.metrics.disk_free_bytes),n.status_source==="marzban"?"Управляется Rime":stamp(n.seen_at)]));
    const grid=$("nodes-grid");grid.replaceChildren();if(!nodes.length){empty(grid,"Нод пока нет. Добавьте первый сервер.");return;}
    for(const n of nodes){const card=el("article",null,"card node-card"),header=el("header"),name=el("div");name.append(el("h2",n.name),el("p",protocolNames[n.protocol]||n.protocol,"small muted"));header.append(name,nodeBadge(n));card.append(header,el("p",n.address||n.id,"address"));const dl=el("dl");for(const [label,value] of [[window.RimeConsole?.connectionLabel(n)||"Подключения",window.RimeConsole?.connectionLink(n)??n.metrics.online_connections??"—"],["Загрузка ОС",n.metrics.cpu_load1==null?"—":n.metrics.cpu_load1.toFixed(2)],["Доступно RAM",bytes(n.metrics.mem_available_bytes)],["Свободно на диске",bytes(n.metrics.disk_free_bytes)]]){const d=el("div");const valueCell=el("dd");if(value instanceof Node)valueCell.append(value);else valueCell.textContent=value;d.append(el("dt",label),valueCell);dl.append(d);}card.append(dl,el("footer",n.status_source==="marzban"?"Состояние из Rime · ресурсы ОС: "+stamp(n.seen_at):`Сигнал: ${stamp(n.seen_at)} · ${n.monitoring_only?"Мониторинг ОС · прежний Hy2-мост":n.metrics.accounting_durable?"Долговечный учёт":"Обычные счётчики"}`));grid.append(card);}
    window.RimeConsole?.nodeLinks();
  }
  let nodeOptionsKey='';
  function syncNodeOptions(nodes){
    const key=JSON.stringify(nodes.map(n=>[n.id,n.name]));if(key===nodeOptionsKey)return;nodeOptionsKey=key;
    const select=$("filter-node"),selected=select.value;select.replaceChildren(new Option("Все ноды",""));
    for(const n of nodes)select.add(new Option(n.name,n.id));
    if(!nodes.some(n=>n.id==='xray:local'))select.add(new Option("Сервер панели","xray:local"));
    select.value=selected;
  }
  function renderEvents(){if(window.RimeConsole){window.RimeConsole.events();return;}const events=state.events.filter(x=>!$("events-open").checked||!x.resolved_at);table($("events-table"),["Время UTC","Нода","Событие","Состояние","Повторов"],events.map(x=>[stamp(x.last_at),x.node,x.message,badge(x.resolved_at?"healthy":"degraded"),x.occurrences]));}
  function renderOverview(data,traffic){
    const rows=window.RimeMonitor?data.nodes.map(node=>window.RimeMonitor.describe(node,Date.now()/1000)):[];
    const gateway=rows.filter(row=>row.node.role!=='panel'&&row.state!=='disabled'),available=gateway.filter(row=>row.access.state==='healthy').length;
    const failed=gateway.filter(row=>row.access.state==='offline'),unknown=gateway.filter(row=>row.access.state==='unknown');
    $('overview-status').textContent=failed.length?failed.slice(0,2).map(row=>row.node.name).join(', ')+(failed.length>2?' и ещё '+(failed.length-2):'')+' — клиентский трафик не прошёл.':unknown.length?'Нужна свежая проверка трафика для '+unknown.length+' нод.':gateway.length?'Все выходные ноды проходят клиентскую пробу.':'Добавьте первую выходную ноду и проверьте передачу трафика.';
    const online=rows.filter(row=>row.node.protocol==='hysteria2'&&row.fresh&&row.state!=='disabled'&&row.node.metrics.online_connections!=null).map(row=>row.node);
    $("metric-nodes").textContent=gateway.length?`${available} / ${gateway.length}`:'—';$("metric-nodes-detail").textContent=gateway.length?`Сбой: ${gateway.filter(row=>row.access.state==='offline').length} · Без свежей пробы: ${gateway.filter(row=>row.access.state==='unknown').length}`:'Выходных нод нет';
    $("metric-online").textContent=online.length?online.reduce((s,n)=>s+n.metrics.online_connections,0):"—";
    const open=data.events.filter(e=>!e.resolved_at);$("metric-errors").textContent=rows.filter(row=>row.attention).length;$("event-badge").textContent=open.length;$("event-badge").hidden=!open.length;
    syncNodeOptions(data.nodes);
    if(pageName()==='overview'||pageName()==='nodes')renderNodes(data.nodes);
    if(pageName()==='overview')eventList($("overview-events"),open);
    if(traffic&&pageName()==='overview'){$("metric-traffic").textContent=bytes(traffic.total);chart($("overview-chart"),traffic.series);}
  }
  function reportParams(){const q=new URLSearchParams();const start=$("filter-start").value,end=$("filter-end").value;if(start)q.set("start",start+"T00:00:00Z");if(end){const d=new Date(end+"T00:00:00Z");d.setUTCDate(d.getUTCDate()+1);q.set("end",d.toISOString());}for(const key of ["protocol","node","user","tag"]){const value=$("filter-"+key).value.trim();if(value)q.set(key==="user"?"username":key,value);}q.set("group_by",$("traffic-group").value||"protocol");return q;}
  function clearTrafficReport(){
    state.traffic=null;
    const target=$('traffic-chart');
    chartStates.get(target)?.observer?.disconnect();chartStates.delete(target);
    for(const id of ['report-summary','traffic-chart','traffic-users','traffic-by-node'])$(id).replaceChildren();
    for(const id of ['traffic-coverage','traffic-user-count'])$(id).textContent='';
    $('traffic-quality').textContent='Нет отчёта';
    target.setAttribute('aria-busy','false');
  }
  async function loadTraffic({background=false}={}){
    if(background&&!canAutoRefresh())return;
    const request=++trafficRequest;
    if(!updateTrafficContext()){
      clearTrafficReport();
      return;
    }
    if($("filter-start").value>$("filter-end").value){$("traffic-status").textContent='Дата начала должна быть раньше даты окончания.';$("traffic-status").classList.add('error');$("filter-end").setAttribute('aria-invalid','true');if(!background)$("filter-end").focus();return;}
    $("filter-end").removeAttribute('aria-invalid');
    const params=reportParams().toString(),version=session.version;
    if(!background)$("traffic-status").textContent="Загрузка отчёта…";$("traffic-chart").setAttribute('aria-busy','true');
    try{const data=await api("/api/fleet/traffic?detail=false&"+params);if(request!==trafficRequest||version!==session.version||params!==reportParams().toString()||background&&!canAutoRefresh())return;trafficAt=Date.now();state.traffic=data;window.RimeConsole?.report(data);$("traffic-total").textContent="Трафик по часам";const groups=data.chart_groups||protocolGroups;
      chart($("traffic-chart"),data.chart_series||data.series,groups);
      $("traffic-legend").replaceChildren(...groups.map((group,index)=>{const span=el('span'),mark=el('i',null,group.color||'series-'+index);span.append(mark,document.createTextNode(group.label));return span;}));
      $("traffic-group-note").textContent=data.chart_note||'';
      if(!window.RimeConsole?.report)table($("traffic-users"),["Пользователь","Всего","Hysteria2","VLESS / Xray"],data.users.map(r=>[r.username,bytes(r.hysteria2+r.xray),bytes(r.hysteria2),bytes(r.xray)]));
      loadTraffic.appliedParams=params;$("traffic-status").classList.remove('error');$("traffic-status").textContent=`Сформировано ${stamp(Date.now()/1000)}.`;
    }catch(e){if(request===trafficRequest&&version===session.version&&e.name!=="SessionChangedError"){$("traffic-status").classList.add('error');$("traffic-status").textContent=e.message+(loadTraffic.appliedParams===params?' Показан последний успешный отчёт.':'');if(loadTraffic.appliedParams!==params){state.traffic=null;for(const id of ['report-summary','traffic-users','traffic-by-node','traffic-chart'])$(id).replaceChildren();$("traffic-total").textContent='Отчёт не загружен';$("traffic-coverage").textContent='';$("traffic-quality").className='badge unknown';$("traffic-quality").textContent='Нет отчёта';$("traffic-user-count").textContent='';$("traffic-users-more").hidden=true;}}}
    finally{if(request===trafficRequest)$("traffic-chart").removeAttribute('aria-busy');}
  }
  function refresh({background=false,pageLoad=false}={}){
    if(!state.token||pageName()==='docs'||background&&!canAutoRefresh())return Promise.resolve();
    if(refreshOwner?.version===session.version)return refreshOwner.promise;
    const owner={version:session.version,revision:state.revision,route:location.hash};refreshOwner=owner;
    state.busy=true;$("refresh").disabled=true;
    owner.promise=(async()=>{
      const requests=[api("/api/fleet/overview")];
      const wantTraffic=pageName()==="overview"&&(!overviewTraffic||Date.now()-overviewTrafficAt>30000);
      if(wantTraffic)requests.push(api("/api/fleet/traffic?detail=false"));
      const results=await Promise.allSettled(requests);
      if(owner.version!==session.version||owner.revision!==state.revision||!state.token||background&&!canAutoRefresh())return;
      const errors=results.filter(r=>r.status==="rejected"&&r.reason.name!=="SessionChangedError").map(r=>r.reason.message);
      showError(errors.join(" "));
      if(wantTraffic&&results[1]?.status==="fulfilled"){overviewTraffic=results[1].value;overviewTrafficAt=Date.now();}
      if(results[0].status==="fulfilled"){state.overview=results[0].value;renderOverview(state.overview,overviewTraffic);}
      if(results[0].status==="fulfilled"){state.events=results[0].value.events; if(pageName()==='events')renderEvents();}
      $("freshness").textContent=errors.length?"Часть данных не обновлена":"Обновлено "+new Date().toLocaleTimeString("ru-RU");
      if(owner.route!==location.hash)return;
      if(pageName()==="traffic"&&(!background||Date.now()-trafficAt>30000))await loadTraffic({background});
      if(pageLoad)await window.RimeConsole?.navigate(pageName());else await window.RimeConsole?.refresh({background});
    })().catch(error=>{if(owner.version===session.version&&error.name!=="SessionChangedError")showError(error.message);}).finally(()=>{
      if(refreshOwner===owner){refreshOwner=null;state.busy=false;$("refresh").disabled=false;}
    });
    return owner.promise;
  }
  let deployRequest=0;
  function invalidateDeployVerification(){
    deployRequest++;state.draft=null;state.plan=null;clearTimeout(state.planTimer);
    $("host-key-card").hidden=true;$("plan-card").hidden=true;$("host-key").textContent="";
    $("trust-host").checked=false;$("verify-host").disabled=true;$("deploy-confirm").disabled=true;
    $("preflight").disabled=false;$("step-2").classList.remove("active");
  }
  function syncDeployAuth(clear=false){
    const useKey=$("deploy-auth-method").value==="key",form=$("deploy-form");
    const password=form.elements.namedItem("password"),key=form.elements.namedItem("private_key"),passphrase=form.elements.namedItem("key_passphrase");
    $("deploy-password-fields").hidden=useKey;$("deploy-key-fields").hidden=!useKey;
    password.disabled=useKey;password.required=!useKey;key.disabled=!useKey;key.required=useKey;passphrase.disabled=!useKey;
    if(clear)for(const field of [password,key,passphrase])field.value="";
  }
  function resetWizard(){
    clearTimeout(state.jobTimer);clearTimeout(state.planTimer);
    invalidateDeployVerification();state.currentJob=null;state.jobFailures=0;
    try{storage?.removeItem("rime.provision.job");}catch{}
    $("deploy-form").reset();syncDeployAuth();$("deploy-form").hidden=false;$("deploy-error").textContent="";
    const form=$("deploy-form");form.elements.namedItem('move_node').value='';form.elements.namedItem('protocol').disabled=false;
    for(const option of form.elements.namedItem('protocol').options||[])if(option.value==='vless')option.textContent='VLESS · gRPC + TLS';
    for(const name of ['name','domain','vpn_port'])form.elements.namedItem(name).readOnly=false;
    $('transfer-notice').hidden=true;$('deploy-title').textContent='Добавить ноду';$('deploy-description').textContent='Укажите доступ. Панель проверит сервер и подготовит установку.';
    $('deploy-confirm').textContent='Развернуть ноду';
    for(const id of ["plan-card","job-card","host-key-card","job-retry","job-new","job-done"])$(id).hidden=true;
    $("step-2").classList.remove("active");$("step-3").classList.remove("active");
  }
  async function prepareTransfer(node){
    const route=location.hash;
    const saved=await api('/api/fleet/nodes/'+encodeURIComponent(node)+'/recovery');
    if(location.hash!==route)return;
    if(!saved.available&&window.RimeRecovery){
      const identity=state.overview?.nodes.find(item=>item.id===node);
      if(identity){await window.RimeRecovery.open(identity);return;}
    }
    const source=await api('/api/fleet/provision/transfer/'+encodeURIComponent(node));
    if(location.hash!==route)return;
    resetWizard();location.hash='#deploy';
    const form=$('deploy-form');
    for(const name of ['name','protocol','domain','vpn_port'])form.elements.namedItem(name).value=source[name];
    form.elements.namedItem('move_node').value=node;form.elements.namedItem('protocol').disabled=true;
    for(const option of form.elements.namedItem('protocol').options||[])if(option.value==='vless')option.textContent='VLESS · сохранённые входы';
    for(const name of ['name','domain','vpn_port'])form.elements.namedItem(name).readOnly=true;
    $('deploy-title').textContent='Перенести ноду '+source.name;$('breadcrumb').textContent='Перенос ноды';document.title='Перенос ноды · Rime';
    $('deploy-description').textContent='Укажите прямой доступ к новому серверу.';
    $('deploy-confirm').textContent='Перенести ноду';
    $('transfer-notice').textContent=source.instructions+' Прежний сервер — '+source.old_address+'.';$('transfer-notice').hidden=false;
    if(source.services?.length){const list=el('ul');for(const service of source.services)list.append(el('li',service));$('transfer-notice').append(list);}
    if(source.retry_job){const retry=el('button','Открыть незавершённую попытку · '+source.retry_job.host,'secondary');retry.type='button';retry.addEventListener('click',()=>resumeJob(source.retry_job.id));$('transfer-notice').append(retry);}
    form.elements.namedItem('host').focus();
  }
  function restoreJob(){
    if(state.currentJob)return;
    let id;try{id=storage?.getItem("rime.provision.job");}catch{}
    if(!/^[a-f0-9]{32}$/.test(id||""))return;
    state.currentJob={id};showJob(id);
  }
  function resumeJob(id){resetWizard();location.hash='#deploy';state.currentJob={id};showJob(id);}
  function showJob(id){
    try{storage?.setItem("rime.provision.job",id);}catch{}
    $("deploy-form").hidden=true;$("plan-card").hidden=true;$("host-key-card").hidden=true;
    $("job-card").hidden=false;$("step-3").classList.add("active");pollJob(id);
  }
  let lastRoute=null,appliedTrafficContext=null;
  function updateTrafficContext(){
    const parts=location.hash.slice(1).split('/');
    const back=$('traffic-back');
    if(parts[0]!=='traffic'||!parts[1]){back.hidden=true;appliedTrafficContext=null;return true;}
    let identity;
    try{identity=decodeURIComponent(parts.slice(1).join('/'));}
    catch{back.hidden=false;back.href='#nodes';back.textContent='← Все ноды';$('traffic-status').textContent='Некорректная ссылка на отчёт ноды.';return false;}
    const node=state.overview?.nodes.find(item=>item.id===identity);
    back.hidden=false;
    back.href=node?'#node/'+encodeURIComponent(identity):'#nodes';
    back.textContent=node?'← К ноде '+node.name:'← Все ноды';
    if(!state.overview)return false;
    if(!node){$('traffic-status').textContent='Нода из ссылки недоступна. Выберите её в списке нод.';return false;}
    if(appliedTrafficContext!==identity){
      $('filter-node').value=identity;
      for(const field of ['filter-user','filter-tag','filter-protocol'])$(field).value='';
      appliedTrafficContext=identity;
    }
    return true;
  }
  function navigate({load=true}={}){
    const route=location.hash.slice(1)||'overview',page=route.split('/')[0];
    const selected=titles[page]?page:'overview';
    if(lastRoute!==route){
      lastRoute=route;appliedTrafficContext=null;window.scrollTo(0,0);
      if(selected==='traffic')clearTrafficReport();
    }
    document.querySelectorAll('.page').forEach(item=>item.hidden=item.id!=='page-'+selected);
    document.querySelectorAll('nav a').forEach(link=>{
      if(link.dataset.page===selected||(['deploy','node'].includes(selected)&&link.dataset.page==='nodes'))link.setAttribute('aria-current','page');
      else link.removeAttribute('aria-current');
    });
    const title=selected==='deploy'&&$('deploy-form').elements.namedItem('move_node').value?'Перенос ноды':titles[selected];
    $('breadcrumb').textContent=title;
    document.title=title+' · Rime';
    if(selected==='deploy'&&!$('job-done').hidden)resetWizard();
    if(state.overview&&selected==='nodes')renderNodes(state.overview.nodes);
    if(state.overview&&selected==='overview')renderOverview(state.overview,overviewTraffic);
    if(selected==='events')renderEvents();
    if(selected==='docs')window.RimeHelp?.navigate();
    if(selected==='relays')window.RimeRelays?.navigate();
    $('refresh').hidden=selected==='docs';$('freshness').hidden=selected==='docs';
    if(load&&selected!=='docs'&&state.token&&!state.overview)refresh({pageLoad:true});
    else{
      if(load&&selected==='traffic'&&state.token)loadTraffic();
      if(load&&selected==='overview'&&state.token&&!overviewTraffic)refresh();
      if(load)window.RimeConsole?.navigate(selected);
    }
    $('main').focus({preventScroll:true});
  }
  function showApp(username){$("avatar").textContent=(username||"A").slice(0,1).toUpperCase();$("login").hidden=true;$("app").hidden=false;$("login-error").textContent="";document.dispatchEvent(new Event("rime:session-ready"));if(pageName()==="deploy")restoreJob();}
  function logout(message=""){
    session.clear();api.abortAll();state.revision++;trafficRequest++;overviewTraffic=null;overviewTrafficAt=0;trafficAt=0;
    lastRoute=null;appliedTrafficContext=null;$('traffic-back').hidden=true;$('traffic-back').href='#nodes';$('traffic-back').textContent='← Все ноды';
    document.querySelectorAll("dialog[open]").forEach(d=>d.close());window.RimeConsole?.resetSession();window.RimeProxy?.reset();window.RimeRecovery?.reset();
    nodeOptionsKey="";state.overview=null;state.traffic=null;state.events=[];state.draft=null;state.plan=null;clearTimeout(state.jobTimer);resetWizard();
    for(const id of ['overview-chart','traffic-chart','node-traffic-chart']){const target=$(id),entry=chartStates.get(target);entry?.observer?.disconnect();chartStates.delete(target);}
    for(const id of ['user-table','nodes-grid','overview-nodes','overview-events','events-table','traffic-users','traffic-by-node','report-summary','overview-chart','traffic-chart','node-traffic-chart','monitor-table','monitor-summary','monitor-history','panel-host-resources','panel-host-info','node-metrics','node-config','node-edit-fields','node-hosts','node-checks','node-events','node-resource-charts','node-resource-history','node-history','node-client-access','node-quota-summary','hub-runtime','hub-vpn-hosts','connections-summary','connections-groups','event-details','user-suggestions'])$(id)?.replaceChildren();
    for(const id of ['metric-nodes','metric-traffic','metric-online','metric-errors'])$(id).textContent='—';
    for(const id of ['metric-nodes-detail','traffic-status','traffic-user-count','traffic-coverage','monitor-status','monitor-coverage','node-title','node-subtitle','node-check-status','node-traffic-status','node-save-status','quota-save-status','panel-host-address','panel-host-status','hub-xray-status','hub-vpn-traffic','connections-description','connections-note','user-picker-status','user-count','users-page'])$(id).textContent='';
    $('traffic-users-more').hidden=true;$('traffic-quality').textContent='Нет отчёта';loadTraffic.appliedParams=null;
    $('filter-node').replaceChildren(new Option('Все ноды',''));for(const id of ['filter-tag','user-tag'])$(id).replaceChildren(new Option('Все теги',''));$('filter-user').value='';
    $("app").hidden=true;$("login").hidden=false;$("login-password").value="";$("login-error").textContent=message;$("login-user").focus();
  }
  $("login-form").addEventListener("submit",async e=>{
    e.preventDefault();const button=e.submitter;button.disabled=true;$("login-error").textContent="";
    try{
      const username=$("login-user").value,form=new URLSearchParams({username,password:$("login-password").value});
      const result=await api("/api/admin/token",{method:"POST",body:form,headers:{"Content-Type":"application/x-www-form-urlencoded"}});
      session.set(result.access_token,username);$("login-password").value="";showApp(username);navigate({load:false});await refresh({pageLoad:true});
    }catch(error){if(error.name!=="SessionChangedError")$("login-error").textContent=error.message;}
    finally{button.disabled=false;}
  });
  $("logout-mobile").addEventListener("click",()=>logout());$("logout").addEventListener("click",()=>logout());$("refresh").addEventListener("click",refresh);$("filters").addEventListener("submit",e=>{e.preventDefault();loadTraffic();});$("traffic-group").addEventListener("change",()=>loadTraffic());$("events-open").addEventListener("change",renderEvents);window.addEventListener("hashchange",navigate);
  $("export").addEventListener("click",async e=>{e.currentTarget.disabled=true;try{const r=await api("/api/fleet/traffic.csv?"+reportParams(),{raw:true});const url=URL.createObjectURL(await r.blob());const a=el("a");a.href=url;a.download="traffic.csv";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(err){showError(err.message+(err.status===422?' Сузьте период или выберите ноду, тег или пользователя.':''));}finally{$("export").disabled=false;}});
  $("deploy-auth-method").addEventListener("change",()=>{invalidateDeployVerification();syncDeployAuth(true);});
  $("deploy-form").addEventListener("input",invalidateDeployVerification);
  syncDeployAuth();
  $("deploy-form").addEventListener("submit",async e=>{
    e.preventDefault();invalidateDeployVerification();const request=deployRequest;$("deploy-error").textContent="";$("preflight").disabled=true;
    try{
      const data=Object.fromEntries(new FormData(e.currentTarget));
      for(const key of ["name","host","domain","username"])data[key]=data[key].trim();
      data.ssh_port=Number(data.ssh_port);data.vpn_port=Number(data.vpn_port);
      if(data.move_node)data.protocol=$('deploy-form').elements.namedItem('protocol').value;
      else delete data.move_node;
      const useKey=$("deploy-auth-method").value==="key";
      data.password=useKey?"":data.password||"";data.private_key=useKey?data.private_key||"":"";data.key_passphrase=useKey?data.key_passphrase||"":"";
      if(!data.cleanup_job)delete data.cleanup_job;
      if(useKey&&!data.private_key.trim())throw new Error("Укажите приватный SSH-ключ для входа.");
      if(!useKey&&!data.password)throw new Error("Введите пароль пользователя сервера.");
      const options=await api("/api/fleet/provision/options");
      if(request!==deployRequest)return;
      if(!options.enabled||!options.protocols[data.protocol])throw new Error("Установка выбранного протокола не настроена на панели.");
      if(!options.automatic_tls&&!data.certificate&&!data.certificate_key)throw new Error("Укажите свой TLS-сертификат и ключ в дополнительных настройках.");
      state.draft=data;
      const scan=await api("/api/fleet/provision/host-key",{method:"POST",timeoutMs:45000,json:{host:data.host,ssh_port:data.ssh_port}});
      if(request!==deployRequest||state.draft!==data)return;
      data.fingerprint=scan.fingerprint;data.address=scan.address;
      $("host-key").textContent=scan.fingerprint;$("trust-host").checked=false;$("verify-host").disabled=true;
      $("host-key-card").hidden=false;$("host-key-card").scrollIntoView({block:"center"});
    }catch(err){if(request===deployRequest)$("deploy-error").textContent=err.message;}
    finally{if(request===deployRequest)$("preflight").disabled=false;}
  });
  $("trust-host").addEventListener("change",()=>$("verify-host").disabled=!$("trust-host").checked);
  $("verify-host").addEventListener("click",async()=>{
    const request=deployRequest,draft=state.draft;if(!draft||!$("trust-host").checked)return;
    $("verify-host").disabled=true;
    try{
      const plan=await api("/api/fleet/provision/preflight",{method:"POST",timeoutMs:90000,json:draft});
      if(request!==deployRequest||state.draft!==draft)return;
      state.plan=plan;clearTimeout(state.planTimer);state.planTimer=setTimeout(async()=>{if(state.plan?.id===plan.id){const moving=state.draft?.move_node;try{if(moving)await prepareTransfer(moving);else resetWizard();$("deploy-error").textContent="План истёк. Введите доступ и повторите проверку.";}catch(error){resetWizard();showError(error.message);}}},Math.max(0,plan.expires_at*1000-Date.now()));
      const list=el("dl");for(const [key,value] of Object.entries(plan.summary||{})){list.append(el("dt",key,"muted"),el("dd",value));}
      const checks=el("ul");for(const c of plan.checks||[])checks.append(el("li",(c.passed?"✓ ":"! ")+c.message));
      $("plan-details").replaceChildren(list,checks);$("plan-card").hidden=false;$("host-key-card").hidden=true;$("deploy-form").hidden=true;$("step-2").classList.add("active");$("deploy-confirm").disabled=!plan.ready;$("plan-card").scrollIntoView({block:"start"});
    }catch(err){if(request===deployRequest){$("deploy-error").textContent=err.message;$("deploy-error").scrollIntoView({block:"center"});}}
    finally{if(request===deployRequest)$("verify-host").disabled=!$("trust-host").checked;}
  });
  $("plan-cancel").addEventListener("click",()=>{$("plan-card").hidden=true;$("deploy-form").hidden=false;state.plan=null;});
  window.addEventListener("hashchange",()=>{if(pageName()==="deploy"&&state.token)restoreJob();});
  async function pollJob(id){
    clearTimeout(state.jobTimer);
    try{
      const job=await api("/api/fleet/provision/jobs/"+encodeURIComponent(id));
      state.currentJob=job;state.jobFailures=0;$("job-state").textContent=job.message||job.state;
      let progress=$('job-progress');
      if(!progress){progress=el('div');progress.id='job-progress';$('job-state').after(progress);}
      window.RimeProgress?.mount(progress).update(window.RimeProgress.job(job));
      if(job.context?.move_node){$('deploy-title').textContent='Перенос ноды '+job.context.name;$('breadcrumb').textContent='Перенос ноды';document.title='Перенос ноды · Rime';}
      $("job-steps").replaceChildren(...(job.steps||[]).map(step=>el("li",step.message)));
      if(["succeeded","failed","rolled_back"].includes(job.state)){
        $("job-done").hidden=false;$("job-new").hidden=false;
        $("job-retry").hidden=job.state==="succeeded"||!job.context?.host;refresh();
      }else state.jobTimer=setTimeout(()=>pollJob(id),1500);
    }catch(error){
      if(error.name==="SessionChangedError"||error.name==="UnauthorizedError")return;
      $("job-state").textContent=error.message;state.jobFailures++;
      if(error.status===404&&state.jobFailures>2){$("job-new").hidden=false;return;}
      state.jobTimer=setTimeout(()=>pollJob(id),Math.min(10000,1500*state.jobFailures));
    }
  }
  $("deploy-confirm").addEventListener("click",async()=>{
    $("deploy-confirm").disabled=true;const id=state.plan.id;
    try{
      const job=await api("/api/fleet/provision/deploy",{method:"POST",json:{plan_id:id}});
      clearTimeout(state.planTimer);state.plan=null;state.draft=null;$("deploy-form").reset();syncDeployAuth();
      state.currentJob={id:job.id};showJob(job.id);
    }catch(error){
      if(error.status&&error.status<500){showError(error.message);$("deploy-confirm").disabled=false;return;}
      clearTimeout(state.planTimer);state.plan=null;state.draft=null;$("deploy-form").reset();syncDeployAuth();
      state.currentJob={id};showJob(id);
    }
  });
  $("job-new").addEventListener("click",resetWizard);
  $("job-retry").addEventListener("click",async()=>{
    const previous=state.currentJob;
    try{if(previous.context.move_node)await prepareTransfer(previous.context.move_node);else resetWizard();}
    catch(error){showError(error.message);return;}
    for(const key of previous.context.move_node?["host","ssh_port","username"]:["host","ssh_port","username","name","protocol","domain","vpn_port"]){
      const field=$("deploy-form").elements.namedItem(key);
      if(field&&previous.context[key]!=null)field.value=previous.context[key];
    }
    if(previous.state==="failed")$("deploy-form").elements.namedItem("cleanup_job").value=previous.id;
    $("deploy-error").textContent="Введите SSH-пароль или ключ заново. Перед установкой панель проверит остатки предыдущей попытки.";
    $("deploy-form").elements.namedItem("password").focus();
  });
  const now=new Date(),start=new Date(now);start.setUTCDate(start.getUTCDate()-6);$("filter-start").value=start.toISOString().slice(0,10);$("filter-end").value=now.toISOString().slice(0,10);
  function invalidateNodes(aliases){state.revision++;state.traffic=null;state.events=state.events.filter(e=>!aliases.includes(e.node));if(state.overview){state.overview.nodes=state.overview.nodes.filter(n=>!aliases.includes(n.id));state.overview.events=state.events;state.overview.summary=Object.fromEntries(['healthy','offline','degraded','unknown'].map(s=>[s,state.overview.nodes.filter(n=>n.state===s).length]));renderOverview(state.overview,null);}$("overview-chart").replaceChildren();$("metric-traffic").textContent='…';for(const id of ['traffic-users','traffic-by-node','traffic-chart','edit-nodes'])$(id)?.replaceChildren();}
  window.Rime={api,el,table,chart,bytes,stamp,state,badge,nodeBadge,refresh,showError,loadTraffic,invalidateNodes,canAutoRefresh,prepareTransfer,resumeJob};
  async function poll(){
    try{
      if(canAutoRefresh())await refresh({background:true});
      else if(state.token&&!document.hidden&&!state.busy)$("freshness").textContent="Автообновление на паузе во время ввода";
    }finally{setTimeout(poll,10000);}
  }
  function boot(){
    if(session.token){showApp(session.username);navigate({load:false});refresh({pageLoad:true});}
    setTimeout(poll,10000);
  }
  if(document.readyState==="complete")boot();else document.addEventListener("DOMContentLoaded",boot,{once:true});
  document.addEventListener("visibilitychange",()=>{if(canAutoRefresh())refresh({background:true});});
})();
