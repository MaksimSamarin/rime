"use strict";
(() => {
  const {api,el,table,chart,bytes,stamp,state,badge,showError,loadTraffic}=window.Rime;
  const $=id=>document.getElementById(id), names={active:"Активен",disabled:"Отключён",limited:"Лимит исчерпан",expired:"Срок истёк",on_hold:"Ожидает подключения"};
  let offset=0,total=0,editing=null,activeNode=null,activeEvent=null,userRequest=0,pickerRequest=0,checkTimer=null;
  const debounce=fn=>{let timer;return ()=>{clearTimeout(timer);timer=setTimeout(fn,250);};};
  const run=fn=>(...args)=>Promise.resolve(fn(...args)).catch(e=>showError(e.message));
  const link=(text,href)=>{const a=el('a',text,'text-link');a.href=href;return a;};
  const button=(text,callback)=>{const b=el('button',text,'quiet');b.type='button';b.addEventListener('click',run(callback));return b;};
  let connectionNode=null;
  const connectionLabel=n=>n.protocol==='hysteria2'?'Экземпляры Hy2':'TCP на VPN-порту';
  function connectionLink(n){
    const count=n.metrics?.online_connections;
    if(count==null)return el('span',n.metrics?.connection_metric_state==='not_configured'?'API статистики не включён':'Нет данных','muted');
    const b=button(String(count)+' · подробнее',()=>connections(n.id));b.setAttribute('aria-label',connectionLabel(n)+': '+count+'. Показать состав');return b;
  }
  async function connections(node){
    connectionNode=node;const data=await api('/api/fleet/nodes/'+encodeURIComponent(node)+'/connections'),d=data.details;
    $('connections-title').textContent=data.name+' · подключения';if(!$('connections-dialog').open)$('connections-dialog').showModal();
    $('connections-description').textContent=d?.kind==='tcp_established'?'Текущие TCP-соединения ESTABLISHED на порту '+d.local_port+'. Это транспортные соединения, включая ещё не авторизованные; не число людей или устройств.':d?.kind==='hy2_client_instances'?'Активные экземпляры клиента Hysteria по API ядра. Несколько проксируемых потоков одного экземпляра считаются одной клиентской сессией.':'Подробный срез ещё не поступил от сборщика.';
    const stampText='Получено панелью: '+stamp(data.received_at)+(data.received_at&&Date.now()/1000-data.received_at>30?' · срез устарел':'');
    const rows=[['В срезе',data.count??'Нет данных',stampText]];
    if(d?.kind==='tcp_established')rows.push(['IP-источников',d.unique_source_ips,'Не равно числу пользователей'],['Сокеты Xray',d.confirmed_core_sockets,'Владелец подтверждён ОС'],['Владелец не подтверждён',d.unverified_owner_sockets,'Не приписываем другому сервису']);
    if(d?.kind==='hy2_client_instances')rows.push(['Учётных записей',d.authenticated_users,'По идентификаторам авторизации ядра']);
    metrics($('connections-summary'),rows);
    if(d?.groups?.length)table($('connections-groups'),[d.kind==='tcp_established'?'Анонимный IP-источник':'Анонимная учётная запись','Тип','Соединений'],d.groups.map(g=>[g.key,g.family,g.count]));
    else $('connections-groups').replaceChildren(el('p',data.count===0?'В этом срезе подключений нет.':'Состав недоступен.','muted'));
    $('connections-note').textContent='Пароли, UUID, токены и назначения трафика не передаются в этот отчёт. '+(d?.kind==='tcp_established'?'За одним IP могут быть несколько устройств, а одно устройство может открыть несколько TCP-соединений. ':'Одна учётная запись может использовать несколько экземпляров клиента. ')+(d?.other_connections?'За пределами первых 50 групп: '+d.other_connections+' соединений.':'');
  }
  $('connections-refresh').addEventListener('click',run(()=>connections(connectionNode)));
  let deletePlan=null;
  async function previewDelete(){
    if(!activeNode||activeNode.id==='xray:local')return;
    const p=await api('/api/fleet/nodes/'+encodeURIComponent(activeNode.id)+'/delete-preview');deletePlan=p;
    $('delete-node-target').textContent=p.name+' · '+p.address+' · '+p.node;
    $('delete-node-effects').replaceChildren(...p.effects.map(text=>el('li',text)));
    $('delete-node-retained').replaceChildren(...p.retained.map(text=>el('li',text)));
    $('delete-node-counts').textContent='Адресов подписки: '+(p.host_ids.length+p.external_endpoints)+'. Связей в выборе пользователей: '+p.restricted_user_links+'. Пользователи не удаляются.';
    $('delete-node-name').value='';$('delete-node-ack').checked=false;$('delete-node-confirm').disabled=true;$('delete-node-error').textContent='';$('delete-node-dialog').showModal();
  }
  const deletionReady=()=>{$('delete-node-confirm').disabled=!deletePlan||$('delete-node-name').value!==deletePlan.name||!$('delete-node-ack').checked;};
  $('delete-node-name').addEventListener('input',deletionReady);$('delete-node-ack').addEventListener('change',deletionReady);
  $('delete-node-form').addEventListener('submit',async event=>{event.preventDefault();if(!deletePlan)return;const p=deletePlan;$('delete-node-confirm').disabled=true;
    try{await api('/api/fleet/nodes/'+encodeURIComponent(p.node),{method:'DELETE',json:{name:$('delete-node-name').value,confirmation:p.confirmation,acknowledge_remote_retained:$('delete-node-ack').checked}});
      window.Rime.invalidateNodes(p.aliases);activeNode=null;editing=null;deletePlan=null;connectionNode=null;$('delete-node-dialog').close();$('delete-node-target').textContent='';$('delete-node-effects').replaceChildren();$('delete-node-retained').replaceChildren();$('delete-node-name').value='';$('delete-node-ack').checked=false;location.hash='#nodes';await window.Rime.refresh();
    }catch(error){$('delete-node-error').textContent=error.message;deletionReady();}});
  const nodeName=id=>state.overview?.nodes.find(n=>n.id===id)?.name||id;
  const quotaBytes=n=>n==null?'—':new Intl.NumberFormat('ru-RU',{maximumFractionDigits:2}).format(n/(n>=1e12?1e12:n>=1e9?1e9:n>=1e6?1e6:n>=1e3?1e3:1))+' '+(n>=1e12?'ТБ':n>=1e9?'ГБ':n>=1e6?'МБ':n>=1e3?'КБ':'Б');
  function quotaCell(q){
    const root=el('div',null,'resource-cell');
    if(!q?.enabled){root.append(el('span','Без лимита','muted'));if(q?.transition_pending)root.append(el('small','Восстановление VPN-доступа…','muted'));return root;}
    root.append(el('strong',quotaBytes(q.used_bytes)+' / '+quotaBytes(q.limit_bytes)),el('small','Осталось '+quotaBytes(q.remaining_bytes),q.stage==='exceeded'?'resource-critical':'muted'));
    root.append(el('small',q.transition_pending?'Применяется изменение VPN-доступа…':q.blocked?'VPN-доступ ограничен квотой':q.stage==='exceeded'?'Лимит исчерпан · только предупреждение':q.percent>=80?`Израсходовано ${pct(q.percent)}`:'Лимит действует',q.percent>=95?'resource-critical':q.percent>=80?'resource-warning':'muted'));
    return root;
  }
  function metrics(target,items){target.replaceChildren(...items.map(([label,value,help])=>{const c=el('article',null,'metric');c.append(el('p',label),el('strong',value),el('span',help||'','small muted'));return c;}));}
  function options(select,items,all){const old=select.value;select.replaceChildren(new Option(all,''),...items.map(x=>new Option(x.tag+' ('+x.users+')',x.tag)));select.value=old;}
  async function tags(){const values=await api('/api/fleet/tags');options($('user-tag'),values,'Все теги');options($('filter-tag'),values,'Все теги');}
  async function users(){
    const request=++userRequest,q=new URLSearchParams({q:$('user-query').value,tag:$('user-tag').value,offset,limit:30});
    const data=await api('/api/fleet/users?'+q);if(request!==userRequest)return;
    total=data.total;if(offset>=total&&offset>0){offset=0;return users();}
    $('user-count').textContent=`Найдено: ${total}`;
    table($('user-table'),['Пользователь','Статус','Теги','Доступ к нодам','Расход / лимит','Срок'],data.users.map(u=>[
      button(u.username,()=>openUser(u.username)),el('span',names[u.status]||u.status,'badge '+(u.status==='active'?'healthy':u.status==='disabled'?'unknown':'degraded')),
      u.tags.join(', ')||'Без тегов',u.nodes===null?'Все ноды':u.nodes.map(nodeName).join(', '),
      bytes(u.used_traffic)+' / '+(u.data_limit?bytes(u.data_limit):'Без лимита'),u.expire?stamp(u.expire):'Без срока']));
    $('users-page').textContent=total?`${offset+1}–${Math.min(offset+30,total)} из ${total}`:'0';
    $('users-prev').disabled=offset===0;$('users-next').disabled=offset+30>=total;
  }
  async function picker(){
    const request=++pickerRequest,query=$('filter-user').value.trim();
    const data=await api('/api/fleet/users?'+new URLSearchParams({q:query,tag:$('filter-tag').value,limit:100}));
    if(request!==pickerRequest)return;
    $('user-suggestions').replaceChildren(...data.users.map(u=>{const option=new Option('',u.username);option.label=u.username+(u.tags.length?' · '+u.tags.join(', '):'');return option;}));
    $('user-picker-status').textContent=query?`Найдено: ${data.total}`:`Доступно пользователей: ${data.total}`;
  }
  function nodeChoices(selected){
    const nodes=state.overview?.nodes||[];
    const choices=nodes.some(n=>n.id==='xray:local')?nodes:[...nodes,{id:'xray:local',name:'Локальный Xray'}];
    $('edit-nodes').replaceChildren(...choices.map(n=>{const label=el('label',null,'check'),input=el('input');input.type='checkbox';input.value=n.id;input.checked=selected?.includes(n.id)||false;label.append(input,document.createTextNode(n.name));return label;}));
    $('edit-nodes').hidden=$('edit-all-nodes').checked;
  }
  async function openUser(username){
    editing=username?await api('/api/fleet/users/'+encodeURIComponent(username)):null;
    $('user-form').reset();$('user-form-error').textContent='';
    $('user-dialog-title').textContent=editing?'Пользователь '+username:'Новый пользователь';
    $('edit-username').value=username||'';$('edit-username').disabled=!!editing;
    $('edit-status').replaceChildren(new Option('Активен','active'),new Option('Отключён','disabled'));
    if(editing&&!['active','disabled'].includes(editing.status))$('edit-status').add(new Option(names[editing.status],editing.status));
    $('edit-status').value=editing?.status||'active';
    $('edit-limit').value=editing?.data_limit?editing.data_limit/1024**3:'';
    $('edit-expire').value=editing?.expire?new Date(editing.expire*1000).toISOString().slice(0,10):'';
    $('edit-tags').value=editing?.tags.join(', ')||'';$('edit-note').value=editing?.note||'';
    $('edit-all-nodes').checked=editing?.nodes==null;nodeChoices(editing?.nodes);
    $('user-subscription').hidden=!editing;
    if(editing)$('subscription-url').value=new URL(editing.subscription_url,location.origin).href;
    $('user-dialog').showModal();
  }
  $('user-form').addEventListener('submit',async e=>{
    e.preventDefault();$('user-save').disabled=true;$('user-form-error').textContent='';
    try{
      const data={tags:$('edit-tags').value.split(',').map(t=>t.trim()).filter(Boolean),nodes:$('edit-all-nodes').checked?null:[...document.querySelectorAll('#edit-nodes input:checked')].map(n=>n.value),
        status:$('edit-status').value,data_limit:Math.round(Number($('edit-limit').value)*1024**3),
        expire:$('edit-expire').value?Math.floor(new Date($('edit-expire').value+'T23:59:59Z').getTime()/1000):0,note:$('edit-note').value};
      if(editing){
        if($('edit-expire').value===(editing.expire?new Date(editing.expire*1000).toISOString().slice(0,10):''))data.expire=editing.expire||0;
        await api('/api/fleet/users/'+encodeURIComponent(editing.username),{method:'PUT',json:data});
      }else{data.username=$('edit-username').value;await api('/api/fleet/users',{method:'POST',json:data});}
      $('user-dialog').close();await Promise.all([users(),tags(),picker()]);
    }catch(error){$('user-form-error').textContent=error.message;}finally{$('user-save').disabled=false;}
  });
  $('copy-subscription').addEventListener('click',run(async()=>{
    const input=$('subscription-url');input.select();
    if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(input.value);
    else if(!document.execCommand('copy'))throw new Error('Выделенная ссылка готова к копированию: нажмите Ctrl+C');
    $('copy-subscription').textContent='Скопировано';setTimeout(()=>$('copy-subscription').textContent='Скопировать',1500);
  }));
  $('edit-all-nodes').addEventListener('change',()=>$('edit-nodes').hidden=$('edit-all-nodes').checked);
  $('user-create').addEventListener('click',run(()=>openUser(null)));
  $('user-filters').addEventListener('submit',e=>{e.preventDefault();offset=0;run(users)();});
  $('user-query').addEventListener('input',debounce(run(()=>{offset=0;return users();})));
  $('user-tag').addEventListener('change',run(()=>{offset=0;return users();}));
  $('users-prev').addEventListener('click',run(()=>{offset=Math.max(0,offset-30);return users();}));
  $('users-next').addEventListener('click',run(()=>{offset+=30;return users();}));
  $('filter-user').addEventListener('input',debounce(run(picker)));
  $('filter-tag').addEventListener('change',run(async()=>{await picker();await loadTraffic();}));
  $('filter-user').addEventListener('change',loadTraffic);
  document.querySelectorAll('.dialog-close').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));

  const guides={
    node_quota_80:['Нода использовала не менее 80% своей квоты.','Откройте ноду: проверьте остаток и дату сброса. При необходимости увеличьте лимит. Лимиты пользователей не сбрасываются.'],
    node_quota_95:['Нода использовала не менее 95% своей квоты.','Проверьте выбранное действие при исчерпании. Увеличьте лимит или подготовьте другую ноду до остановки VPN-доступа.'],
    node_quota_exceeded:['Квота ноды исчерпана. Действует выбранный режим: предупреждение или остановка VPN-доступа.','Откройте лимит в карточке ноды. Увеличьте объём, смените режим на предупреждение или начните новый период. В дату автосброса квота обновится автоматически.'],
    native_unavailable:['Панель потеряла связь с ядром Xray.','Проверьте службу Marzban-node, адрес и API-порт ноды, сертификат панели и сетевой маршрут. После восстановления соединения событие закроется автоматически при следующем замере.'],
    heartbeat_stale:['Панель не получает подтверждение связи. Последние значения могли устареть.','Проверьте доступность сервера и состояние агента. Затем проверьте маршрут от ноды до панели, TLS и токен. Для нативной VLESS-ноды проверьте службу Marzban-node и её API-порт. После восстановления дождитесь нового сигнала.'],
    stats_unavailable:['Агент не может прочитать счётчики VPN-ядра. Отчётность может задерживаться.','Проверьте, что Hysteria запущена, локальный API статистики доступен и его адрес/секрет совпадает с конфигурацией агента. Не обнуляйте счётчики. После исправления дождитесь успешного опроса.'],
    accounting_failed:['Не удалось передать расход. До подтверждения панели агент должен сохранять его в журнале.','Проверьте связь с панелью, TLS, токен ноды и журнал агента. При HTTP 409 сверьте идентификатор журнала и последовательность пакетов. Не удаляйте spool и не сбрасывайте расход.'],
    ledger_failed:['Агент не может надёжно сохранить учёт трафика.','Проверьте свободное место, права на каталог журнала и ошибки диска. Сначала восстановите запись на диск; не удаляйте журнал для устранения ошибки.'],
    control_expired:['Срок действия последней политики доступа истёк.','Проверьте связь ноды с панелью, сертификат, токен и часы сервера. Дождитесь получения новой политики; не отключайте проверку TLS.'],
    counter_reset:['Счётчик ядра уменьшился без смены журнала. Учёт требует проверки.','Сохраните журнал и конфигурацию. Сверьте версии ядра и агента, историю перезапусков и последний подтверждённый пакет. Не сбрасывайте расход повторно.'],
    provision_failed:['Развёртывание завершилось ошибкой.','Проверьте журнал задачи установки и состояние созданных служб. Исправьте причину перед новой попыткой.'],
    provision_rolled_back:['Установка не завершилась, выполнен откат.','Проверьте причину в сообщении задачи. После исправления выполните предварительную проверку заново.'],
    traffic_failed:['Контрольный клиент не смог передать и получить одинаковый payload через VPN. Одной доступности порта для этой проверки недостаточно.','Проверьте VPN-службу, контрольную учётную запись, локальный контрольный туннель и маршрут до тестового echo-сервиса. После исправления нажмите «Проверить ноду сейчас»: успешная проба закроет событие автоматически.']
  };
  function incidentState(e){return e.resolved_at?'Восстановлено':e.action?.acknowledged?'В работе':'Новое';}
  function events(){
    const values=state.events.filter(e=>!$('events-open').checked||!e.resolved_at);
    table($('events-table'),['Впервые / последнее','Нода','Событие','Разбор','Подтверждений','Действие'],values.map(e=>[
      stamp(e.first_at)+' / '+stamp(e.last_at),link(nodeName(e.node),'#node/'+encodeURIComponent(e.node)),e.message,
      el('span',incidentState(e),'badge '+(e.resolved_at?'healthy':'degraded')),e.occurrences,button('Разобрать',()=>openEvent(e))]));
  }
  async function openEvent(event){
    activeEvent=event;$('event-title').textContent=event.message;
    const guide=guides[event.code]||['Сбой требует проверки конфигурации.','Проверьте журнал соответствующей службы и последнее изменение настроек.'];
    const body=$('event-details');body.replaceChildren(el('p',incidentState(event)+' · '+nodeName(event.node),'muted'),el('h3','Что произошло'),el('p',guide[0]),el('h3','Порядок проверки'),el('p',guide[1]),
      el('p','Первый сигнал: '+stamp(event.first_at)+' · Последний: '+stamp(event.last_at),'small muted'));
    if(state.overview?.nodes.some(n=>n.id===event.node))body.append(link('Открыть мониторинг ноды →','#node/'+encodeURIComponent(event.node)));
    body.querySelector('a')?.addEventListener('click',()=>$('event-dialog').close());
    if(event.action)body.append(el('p','Комментарий: '+event.action.actor+' · '+stamp(event.action.updated_at),'small muted'));
    if(state.overview?.nodes.some(n=>n.id===event.node)){
      const detail=await api('/api/fleet/nodes/'+encodeURIComponent(event.node)),last=detail.checks[0];
      if(last)body.append(el('h3','Последняя проверка'),el('p',`${last.state==='passed'?'Успешно':last.state==='failed'?'Ошибка':'Выполняется'} · ${stamp(last.completed_at||last.requested_at)} · этап: ${last.result.stage||'ожидание'} · ${last.result.error||((last.result.bytes||0)+' Б, '+(last.result.latency_ms??'—')+' мс')}`));
    }
    $('event-note').value=event.action?.note||'';$('event-action-status').textContent='';
    $('event-check').hidden=event.code.startsWith('node_quota_')||!state.overview?.nodes.some(n=>n.id===event.node);
    $('event-action').hidden=!!event.resolved_at;
    $('event-dialog').showModal();
  }
  $('event-action').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{
    await api('/api/fleet/events/'+encodeURIComponent(activeEvent.id)+'/action',{method:'PUT',json:{acknowledged:true,note:$('event-note').value}});
    $('event-action-status').textContent='Сохранено. Событие остаётся нерешённым до восстановления ноды.';
    state.events=await api('/api/fleet/events');events();
  }catch(err){$('event-action-status').textContent=err.message;}finally{b.disabled=false;}});
  async function requestCheck(node,target){
    target.textContent='Проверка поставлена в очередь…';
    const check=await api('/api/fleet/nodes/'+encodeURIComponent(node)+'/checks',{method:'POST'});
    target.textContent='Проверка выполняется. Агент устанавливает VPN-сессию и передаёт контрольные данные…';
    clearTimeout(checkTimer);const started=Date.now();
    const poll=async()=>{const detail=await api('/api/fleet/nodes/'+encodeURIComponent(node));const current=detail.checks.find(x=>x.id===check.id);
      if(current&&['passed','failed'].includes(current.state)){
        const result=current.result||{};target.textContent=current.state==='passed'?`Успешно: через VPN передано ${result.bytes||0} Б, задержка ${result.latency_ms??'—'} мс.`:`Ошибка на этапе «${result.stage||'проверка'}»: ${result.error||'трафик не прошёл'}`;
        activeNode=detail;if(location.hash.startsWith('#node/'))await nodeDetail(true);state.events=await api('/api/fleet/events');events();return;
      }
      if(Date.now()-started>30000){target.textContent='Агент не вернул результат за 30 секунд. Проверьте его связь с панелью.';return;}
      checkTimer=setTimeout(()=>run(poll)(),1000);
    };checkTimer=setTimeout(()=>run(poll)(),600);
  }
  $('event-check').addEventListener('click',run(()=>requestCheck(activeEvent.node,$('event-action-status'))));

  function nodeLinks(){
    const nodes=state.overview?.nodes||[];
    document.querySelectorAll('#nodes-grid .node-card').forEach((card,i)=>{if(nodes[i])card.append(link('Открыть ноду →','#node/'+encodeURIComponent(nodes[i].id)));});
    document.querySelectorAll('#overview-nodes tbody tr').forEach((row,i)=>{if(nodes[i])row.cells[0].replaceChildren(link(nodes[i].name,'#node/'+encodeURIComponent(nodes[i].id)));});
  }
  function timeline(target,nodes,history,hours=24){
    target.replaceChildren();
    if(!history.length){target.append(el('p','История ещё собирается. Первый замер появится в течение минуты.','empty'));return;}
    const end=Date.now()/1000,start=end-hours*3600,buckets=48;
    for(const n of nodes){
      const samples=history.filter(h=>h.node===n.id),row=el('div',null,'timeline-row');row.append(link(n.name,'#node/'+encodeURIComponent(n.id)));
      const bar=el('div',null,'timeline');bar.setAttribute('aria-label','История состояния '+n.name);
      for(let i=0;i<buckets;i++){
        const from=start+(end-start)*i/buckets,to=start+(end-start)*(i+1)/buckets,part=samples.filter(h=>h.minute>=from&&h.minute<to);
        const summary=window.RimeMonitor.bucket(part),status=summary.state;
        const cell=el('span',null,status);cell.title=stamp(from)+' — '+stamp(to)+': '+(summary.last==='healthy'&&summary.failures?'Связь восстановлена; сбойных замеров: '+summary.failures:({healthy:'В работе',offline:'Нет связи',degraded:'Ошибка',unknown:'Нет данных'}[status]))+' · замеров: '+summary.count;bar.append(cell);
      }
      const healthy=samples.filter(h=>h.state==='healthy').length;
      row.append(bar,el('span',`${healthy}/${samples.length} исправных замеров`,'small muted'));target.append(row);
    }
    target.append(el('p','Слева — начало периода, справа — сейчас. Зелёный: в работе; оранжевый: ошибка или связь восстановилась внутри интервала; красный: последний замер без связи; серый: нет данных. Наведите на интервал для подробностей.','small muted'));
  }
  let monitorData=null,monitorRequest=0,monitorFailed=false,monitorReceived=0;
  const pct=value=>new Intl.NumberFormat('ru-RU',{maximumFractionDigits:1}).format(value)+'%';
  function resourceCell(row,key){
    const root=el('div',null,'resource-cell'),cap=row[key],value=key==='cpu'?cap:cap?.percent;
    if(value==null){
      root.append(el('strong',row.age!==null&&!row.fresh?'Замер устарел':'Нет данных','muted'));
      const free=row.node.metrics?.[key==='ram'?'mem_available_bytes':'disk_free_bytes'];
      root.append(el('small',!row.fresh?'Нет актуальной телеметрии':key!=='cpu'&&typeof free==='number'?`Свободно ${bytes(free)} · общий объём неизвестен`:'Агент не передал метрику','muted'));
      return root;
    }
    const critical=key==='disk'?90:95,level=value>=critical?'critical':value>=80?'warning':'normal';root.classList.add(level);
    const head=el('div',null,'resource-value');head.append(el('strong',pct(value)),el('span',level==='critical'?'Критично':level==='warning'?'Внимание':'','small'));root.append(head);
    const meter=el('meter');meter.min=0;meter.max=100;meter.low=80;meter.high=critical;meter.optimum=0;meter.value=value;meter.setAttribute('aria-label',`${row.node.name}: ${key==='ram'?'RAM':key==='disk'?'диск':'CPU'} ${pct(value)}`);root.append(meter);
    if(key==='cpu')root.append(el('small','Загрузка процессора','muted'));
    else root.append(el('small',`${bytes(cap.used)} / ${bytes(cap.total)} занято`),el('small',`Свободно ${bytes(cap.free)}`,'muted'));
    return root;
  }
  function duration(seconds){
    if(typeof seconds!=='number')return 'Нет данных';
    const minutes=Math.floor(seconds/60),hours=Math.floor(minutes/60),days=Math.floor(hours/24);
    return days?`${days} д ${hours%24} ч`:hours?`${hours} ч ${minutes%60} мин`:`${minutes} мин`;
  }
  function renderPanelHost(rows){
    const row=rows.find(r=>r.node.role==='panel'||r.node.id==='xray:local');
    $('panel-host').hidden=!row;if(!row)return;
    const n=row.node,p=n.panel||{},m=n.metrics||{},live=row.fresh&&!monitorFailed;
    $('panel-host-address').textContent=location.host+' · текущая панель';
    $('panel-host-status').textContent=live?'Панель отвечает':'Нет свежего ответа панели';
    $('panel-host-status').className='badge '+(live?'healthy':'unknown');
    $('panel-host-resources').replaceChildren(...['cpu','ram','disk'].map(key=>{const block=el('section');block.append(el('h3',key==='cpu'?'CPU сервера':key==='ram'?'RAM сервера':'Диск с данными'),resourceCell(row,key));return block;}));
    const pairs=[['Версия Rime',p.version||'Нет данных'],['Панель без перезапуска',duration(p.uptime_seconds)],['ОС без перезапуска',duration(p.host_uptime_seconds)],['Память процесса панели',row.fresh?bytes(p.process_memory_bytes):'Нет свежего замера'],['Локальный Xray',row.fresh?(m.service_healthy?'Работает':'Остановлен'):'Нет свежего замера'],['Имя среды выполнения',p.hostname||'Нет данных']];
    $('panel-host-info').replaceChildren(...pairs.map(([name,value])=>{const block=el('div');block.append(el('dt',name),el('dd',value));return block;}));
  }
  function renderMonitoring(){
    if(!monitorData)return;
    const elapsed=(performance.now()-monitorReceived)/1000,now=monitorData.generated_at+elapsed;
    const all=monitorData.nodes.map(n=>window.RimeMonitor.describe(n,now));
    renderPanelHost(all);
    const summary=window.RimeMonitor.summarize(all),coverage=n=>`Свежие метрики: ${n} из ${all.length} нод`;
    metrics($('monitor-summary'),[
      ['На связи',`${summary.online} / ${summary.count}`,`Требуют внимания: ${summary.attention}`],
      ['Максимальная загрузка CPU',summary.cpuMax===null?'Нет данных':pct(summary.cpuMax),coverage(summary.cpuCount)],
      ['Занято RAM',summary.ram.count?bytes(summary.ram.used):'Нет данных',summary.ram.count?`из ${bytes(summary.ram.total)} · ${coverage(summary.ram.count)}`:coverage(0)],
      ['Свободно на дисках',summary.disk.count?bytes(summary.disk.free):'Нет данных',summary.disk.count?`из ${bytes(summary.disk.total)} · ${coverage(summary.disk.count)}`:coverage(0)]
    ]);
    const query=$('monitor-query').value.trim().toLocaleLowerCase(),filter=$('monitor-filter').value;
    let rows=all.filter(r=>(r.node.name+' '+r.node.address).toLocaleLowerCase().includes(query));
    if(filter==='attention')rows=rows.filter(r=>r.attention);
    if(filter==='offline')rows=rows.filter(r=>r.state==='offline');
    if(filter==='missing')rows=rows.filter(r=>r.unavailable);
    rows=window.RimeMonitor.sort(rows,$('monitor-sort').value);
    $('monitor-coverage').textContent=`Показано ${rows.length} из ${all.length} · Без полных метрик: ${summary.missing}. Сводка сверху — по всей сети.`;
    const headers=['Нода','Состояние','CPU','RAM','Диск','Трафик / лимит','Связь / VPN'];
    table($('monitor-table'),headers,rows.map(r=>{
      const n=r.node,m=n.metrics||{},identity=el('div',null,'resource-identity');identity.append(link(n.name,'#node/'+encodeURIComponent(n.id)),el('small',n.address||n.id,'muted'),el('small',n.role==='panel'?'Этот сервер · панель + Xray':n.protocol==='hysteria2'?'Hysteria2':'VLESS / Xray','muted'));
      const status=el('div',null,'resource-status');status.append(r.state==='disabled'?el('span','Отключена','badge'):badge(r.state));
      for(const alert of r.alerts)status.append(el('small',alert.text,alert.level===2?'resource-critical':'resource-warning'));
      if(r.unavailable)status.append(el('small',r.age!==null&&!r.fresh?'Телеметрия устарела':'Метрики неполные','muted'));
      const service=el('div',null,'resource-service');
      service.append(el('small',r.age===null?'Нет замера ресурсов':`Замер ${Math.floor(r.age)} с назад`));
      service.append(el('small',r.fresh?(m.service_healthy==null?'VPN-служба: нет данных':m.service_healthy?'VPN-служба работает':'Ошибка VPN-службы'):'VPN-служба: нет свежих данных','muted'));
      if(r.fresh&&m.online_connections!=null){service.append(el('small',connectionLabel(r.node),'muted'));service.append(connectionLink(r.node));}
      service.append(el('small',m.traffic_checked_at?`Проба: ${m.traffic_healthy?'успешно':'ошибка'} · ${stamp(m.traffic_checked_at)}`:'VPN-трафик: нет результата пробы','muted'));
      if(n.quota?.blocked)status.append(el('small','Лимит VPN исчерпан','resource-critical'));
      return [identity,status,resourceCell(r,'cpu'),resourceCell(r,'ram'),resourceCell(r,'disk'),quotaCell(n.quota),service];
    }));
    $('monitor-table').querySelectorAll('tbody tr').forEach((tr,i)=>{tr.dataset.node=rows[i].node.id;for(let c=0;c<tr.cells.length;c++)tr.cells[c].dataset.label=headers[c];});
    if(!rows.length)$('monitor-table').replaceChildren(el('p','По выбранному фильтру нод нет. Измените поиск или состояние.','empty'));
    $('monitor-status').classList.toggle('error',monitorFailed);
    $('monitor-status').textContent=monitorFailed?'Не удалось обновить ресурсы. Показан последний ответ; старые замеры исключаются автоматически.':`Последний ответ: ${stamp(monitorData.generated_at)} · ${Math.floor(elapsed)} с назад. Автообновление работает, пока вкладка открыта.`;
  }
  async function monitoring(){
    const request=++monitorRequest,hours=Number($('monitor-hours').value);$('monitor-refresh').disabled=true;
    try{
      const data=await api('/api/fleet/monitoring?hours='+hours);
      if(request!==monitorRequest||location.hash!=='#monitoring')return;
      monitorData=data;monitorReceived=performance.now();monitorFailed=false;renderMonitoring();
      timeline($('monitor-history'),data.nodes,data.history,hours);
    }catch(error){
      if(request!==monitorRequest)return;
      monitorFailed=true;if(monitorData)renderMonitoring();else $('monitor-status').textContent='Не удалось загрузить ресурсы. '+error.message;
    }finally{if(request===monitorRequest)$('monitor-refresh').disabled=false;}
  }
  $('monitor-filters').addEventListener('submit',e=>{e.preventDefault();renderMonitoring();});
  $('monitor-query').addEventListener('input',renderMonitoring);
  for(const id of ['monitor-sort','monitor-filter'])$(id).addEventListener('change',renderMonitoring);
  $('monitor-refresh').addEventListener('click',monitoring);
  setInterval(()=>{if(!document.hidden&&state.token&&location.hash==='#monitoring')renderMonitoring();},5000);
  $('monitor-hours').addEventListener('change',run(monitoring));
  function resourceCharts(history,isHub=false,latest={}){
    const root=$('node-resource-charts');root.replaceChildren();
    const specs=isHub?[['cpu_percent','CPU сервера, %',pct],['mem_available_bytes','Свободная RAM',bytes],['disk_free_bytes','Свободное место на диске',bytes]]:[['cpu_load1','Загрузка ОС · load average',n=>n.toFixed(2)],['mem_available_bytes','Доступная память ОС',bytes],['online_connections',activeNode?connectionLabel(activeNode):'Соединения',n=>String(n)]];
    for(const [key,title,format] of specs){
      const card=el('section');card.append(el('h3',title));root.append(card);
      const valid=r=>typeof r.metrics[key]==='number'&&Number.isFinite(r.metrics[key])&&r.metrics[key]>=0&&(isHub||!['offline','unknown'].includes(r.state));
      const values=history.filter(valid);
      if(!values.length){card.append(el('p','Нет данных за период','empty'));continue;}
      const observedMax=Math.max(...values.map(r=>r.metrics[key])),observedMin=Math.min(...values.map(r=>r.metrics[key]));
      const nice=value=>{if(value<=0)return 1;const power=10**Math.floor(Math.log10(value)),factor=value/power;return (factor<=1?1:factor<=2?2:factor<=5?5:10)*power;};
      const capacityKey=key==='mem_available_bytes'?'mem_total_bytes':key==='disk_free_bytes'?'disk_total_bytes':null;
      const capacities=capacityKey?[latest[capacityKey],...history.map(r=>r.metrics[capacityKey])].filter(n=>typeof n==='number'&&Number.isFinite(n)&&n>0):[];
      const upper=key==='cpu_percent'?100:capacities.length?Math.max(observedMax,...capacities):(key==='online_connections'||capacityKey)?Math.max(2,nice(observedMax)):Math.max(.01,nice(observedMax));
      const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 300 140');svg.setAttribute('preserveAspectRatio','none');svg.setAttribute('role','img');svg.setAttribute('aria-label',`${title} за 24 часа. Шкала от ${format(0)} до ${format(upper)}. Минимум ${format(observedMin)}, максимум ${format(observedMax)}.`);
      const first=history[0].minute,last=history[history.length-1].minute;
      const plot=el('div',null,'resource-plot'),axis=el('div',null,'resource-axis');axis.setAttribute('aria-label','Границы шкалы');
      for(const [value,y] of [[upper,8],[upper/2,70],[0,132]]){
        axis.append(el('span',format(value)));
        const grid=document.createElementNS(ns,'line');for(const [k,v] of Object.entries({x1:2,x2:298,y1:y,y2:y,'class':'resource-gridline'}))grid.setAttribute(k,v);svg.append(grid);
      }
      let points=[];
      function line(){if(!points.length)return;const p=document.createElementNS(ns,'polyline');p.setAttribute('points',points.join(' '));p.setAttribute('fill','none');p.setAttribute('stroke','var(--accent)');p.setAttribute('stroke-width','2');p.setAttribute('vector-effect','non-scaling-stroke');svg.append(p);points=[];}
      let previous=null;
      for(const r of history){if(!valid(r)){line();previous=null;continue;}if(previous!==null&&r.minute-previous>120)line();
        const x=2+(r.minute-first)*296/Math.max(1,last-first),y=132-124*r.metrics[key]/upper;points.push(x+','+y);previous=r.minute;
        const dot=document.createElementNS(ns,'circle');dot.setAttribute('cx',x);dot.setAttribute('cy',y);dot.setAttribute('r','2');dot.setAttribute('fill','var(--accent)');const t=document.createElementNS(ns,'title');t.textContent=stamp(r.minute)+': '+format(r.metrics[key]);dot.append(t);svg.append(dot);
      }line();plot.append(axis,svg);card.append(plot);
      const times=el('div',null,'resource-times'),timeFormat=n=>new Date(n*1000).toLocaleString('ru-RU',{timeZone:'UTC',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
      times.append(el('span',timeFormat(first)),el('span',timeFormat(last)));card.append(times,el('p','Время UTC','resource-timezone'));
      const stats=el('dl',null,'resource-statistics');
      for(const [name,value] of [['Последний',values[values.length-1].metrics[key]],['Минимум',observedMin],['Максимум',observedMax]]){const group=el('div');group.append(el('dt',name),el('dd',format(value)));stats.append(group);}card.append(stats);
    }
  }
  function nodeRole(isHub){
    for(const id of ['node-check','node-check-status','node-report','node-delete','node-settings-card','node-checks','node-traffic-card','node-history','node-quota-card'])$(id).hidden=isHub;
    for(const id of ['hub-details','hub-refresh','hub-monitor-link','hub-local-vpn'])$(id).hidden=!isHub;
    $('node-settings-layout').classList.toggle('hub-layout',isHub);
    $('node-role').textContent=isHub?'ХАБ УПРАВЛЕНИЯ':'ВЫХОДНАЯ VPN-НОДА';
    $('node-events-heading').textContent=isHub?'События сервера':'Проверки и события';
  }
  async function nodeDetail(preserveCheckStatus=false){
    const id=decodeURIComponent(location.hash.slice(6));
    activeNode=null;$('quota-save').disabled=true;$('quota-new-period').disabled=true;
    nodeRole(id==='xray:local');$('hub-refresh').disabled=true;
    $('node-check').disabled=true;if(!preserveCheckStatus)$('node-check-status').textContent='Загрузка данных ноды…';
    const [n,h]=await Promise.all([api('/api/fleet/nodes/'+encodeURIComponent(id)),api('/api/fleet/monitoring?node='+encodeURIComponent(id)+'&hours=24')]);
    if(location.hash!=='#node/'+encodeURIComponent(id)&&location.hash!=='#node/'+id)return;
    const isHub=n.role==='panel'||n.id==='xray:local';nodeRole(isHub);
    quotaForm(n.quota||{});
    activeNode=n;$('quota-save').disabled=false;$('node-title').textContent=n.name;$('node-subtitle').textContent=isHub?location.host+' · панель управления Rime':(n.address||n.id)+' · '+n.protocol;$('node-check').disabled=false;$('hub-refresh').disabled=false;if(!preserveCheckStatus)$('node-check-status').textContent='Проверка создаёт реальное подключение через контрольный VPN-клиент и сверяет отправленный payload.';
    if(n.metrics.resource_observer){$('node-check').disabled=true;$('node-check-status').textContent='Сборщик проверяет ресурсы, процесс и порт VPN. Контрольный VPN-клиент для проверки из панели ещё не подключён.';}
    if(n.monitoring_only){$('quota-save').disabled=true;$('quota-fields').disabled=true;$('quota-enabled').disabled=true;$('quota-new-period').disabled=true;$('node-subtitle').textContent+=' · мониторинг подключён, управление VPN — прежний мост';}else{$('quota-enabled').disabled=false;}
    if(isHub){
      const p=n.panel||{},row=window.RimeMonitor.describe(n,h.generated_at);
      metrics($('node-metrics'),[['Панель','Отвечает',stamp(n.seen_at)],['CPU',row.cpu===null?'Нет данных':pct(row.cpu),'Загрузка сервера'],['Свободно RAM',row.ram?bytes(row.ram.free):'Нет данных',row.ram?'из '+bytes(row.ram.total):''],['Свободно на диске',row.disk?bytes(row.disk.free):'Нет данных',row.disk?'из '+bytes(row.disk.total):'']]);
      const fields=[['Роль сервера','Хаб управления'],['Версия Rime',p.version||'Нет данных'],['Адрес панели',location.origin],['Панель без перезапуска',duration(p.uptime_seconds)],['ОС без перезапуска',duration(p.host_uptime_seconds)],['Память процесса панели',bytes(p.process_memory_bytes)],['Среда выполнения',p.hostname||'Нет данных']];
      $('hub-runtime').replaceChildren(...fields.map(([name,value])=>{const block=el('div');block.append(el('dt',name),el('dd',value));return block;}));
      $('hub-xray-status').textContent='Локальный Xray: '+(n.metrics.service_healthy?'работает':'остановлен')+' · версия '+(n.metrics.core_version||'неизвестна');
      const hosts=n.local_vpn_hosts||[];
      if(hosts.length)table($('hub-vpn-hosts'),['Существующий адрес','Подпись'],hosts.map(host=>[host.address,host.remark]));
      else $('hub-vpn-hosts').replaceChildren(el('p','Локальные адреса подписок не привязаны.','muted'));
      $('hub-vpn-traffic').textContent='Расход локального VPN за 7 дней: '+bytes(n.traffic.total);
    }else metrics($('node-metrics'),[['Связь',({healthy:'В работе',offline:'Нет связи',degraded:'Ошибка',unknown:'Нет данных'})[n.state],stamp(n.seen_at)],['VPN-трафик',n.metrics.traffic_healthy==null?'Не проверялся':n.metrics.traffic_healthy?'Проходит':'Не проходит',stamp(n.metrics.traffic_checked_at)],['CPU',n.metrics.cpu_percent==null?'Нет данных':n.metrics.cpu_percent.toFixed(1)+'%','Последний замер'],['Трафик пользователей',bytes(n.traffic.total),'За 7 дней']]);
    timeline($('node-history'),[n],h.history);
    resourceCharts(h.history,isHub,n.metrics);
    if(isHub)table($('node-resource-history'),['Время','CPU','Свободно RAM','Свободно на диске'],h.history.slice(-30).reverse().map(r=>[stamp(r.minute),r.metrics.cpu_percent==null?'Нет данных':pct(r.metrics.cpu_percent),bytes(r.metrics.mem_available_bytes),bytes(r.metrics.disk_free_bytes)]));
    else table($('node-resource-history'),['Время','Состояние','Load average','Доступно RAM','Свободно на диске','Сессии'],h.history.slice(-30).reverse().map(r=>[stamp(r.minute),badge(r.state),r.metrics.cpu_load1??'Нет данных',bytes(r.metrics.mem_available_bytes),bytes(r.metrics.disk_free_bytes),r.metrics.online_connections??'Нет данных']));
    $('node-save-status').textContent='';
    const fields=$('node-edit-fields');fields.replaceChildren();
    const add=(id,label,value,type='text',attrs={})=>{const l=el('label',label),input=el('input');input.id=id;input.type=type;input.value=value??'';for(const [k,v] of Object.entries(attrs))input[k]=v;l.append(input);fields.append(l);return input;};
    add('node-name','Название',n.name,'text',{required:true,maxLength:64});
    if(n.id!=='xray:local')add('node-address',n.protocol==='hysteria2'?'Домен / адрес подключения':'Адрес агента',n.settings.domain||n.address,'text',{required:true,maxLength:253});
    if(n.protocol==='hysteria2'&&n.settings.vpn_port!=null)add('node-vpn-port','VPN-порт',n.settings.vpn_port,'number',{required:true,min:1,max:65535});
    if(n.protocol==='xray'&&n.id!=='xray:local'){
      add('node-port','Порт службы',n.settings.port,'number',{required:true,min:1,max:65535});add('node-api-port','API-порт',n.settings.api_port,'number',{required:true,min:1,max:65535});add('node-coefficient','Коэффициент учёта',n.settings.usage_coefficient,'number',{required:true,min:.01,max:100,step:.01});
    }
    if(n.id!=='xray:local'){const enabled=add('node-enabled','Нода включена','', 'checkbox');enabled.checked=n.settings.active!==0&&n.enabled!==0;}
    if(n.monitoring_only){for(const input of fields.querySelectorAll('input'))if(input.id!=='node-name')input.disabled=true;$('node-save-status').textContent='Параметры действующего Hy2 сохраняются на сервере. Здесь можно изменить только подпись.';}
    const labels={domain:'Домен / SNI',vpn_port:'VPN-порт',port:'Порт службы',api_port:'API-порт',usage_coefficient:'Коэффициент учёта',status:'Статус службы',active:'Добавлена в подписку'};
    $('node-config').replaceChildren(...Object.entries({Адрес:n.address,Протокол:n.protocol,Версия:n.metrics.core_version||'Нет данных',...n.settings}).filter(([k])=>!['id','native_id','host_id'].includes(k)).flatMap(([k,v])=>[el('dt',labels[k]||k),el('dd',k==='active'?(v?'Да':'Нет'):v)]));
    const hostBox=$('node-hosts');hostBox.replaceChildren();
    if(!isHub&&n.hosts.length){hostBox.append(el('h3','Адреса этой ноды в подписках'),el('p','Свяжите адреса подключения с этой выходной нодой. Они используются при выборе доступных пользователю нод.','small muted'));
      for(const host of n.hosts){const label=el('label',null,'check'),input=el('input');input.type='checkbox';input.value=host.id;input.checked=host.node===n.id||host.id===n.settings.host_id;input.disabled=!!host.node&&host.node!==n.id;label.append(input,document.createTextNode(host.remark+' · '+host.address+(input.disabled?' (другая нода)':'')));hostBox.append(label);}
    }
    $('node-events').replaceChildren(...n.events.slice(0,12).map(e=>button(incidentState(e)+' · '+e.message,()=>openEvent(e))));
    if(!n.events.length)$('node-events').append(el('p','Событий нет.','muted'));
    const checks=$('node-checks');checks.replaceChildren(el('h3','Последние проверки VPN-трафика'));
    if(!n.checks.length)checks.append(el('p','Проверок ещё не было.','muted'));
    else table(checks,['Время','Результат','Этап','Задержка'],n.checks.slice(0,5).map(c=>[stamp(c.completed_at||c.requested_at),c.state==='passed'?'Успешно':c.state==='failed'?'Ошибка':'Выполняется',c.result.stage||'—',c.result.latency_ms==null?'—':c.result.latency_ms+' мс']));
    chart($('node-traffic-chart'),n.traffic.series);
    $('node-traffic-status').textContent=n.meter?'VPN-данные с '+stamp(n.meter.history_started_at)+'. Загрузка: '+bytes(n.meter.upload_bytes)+' · скачивание: '+bytes(n.meter.download_bytes)+'. '+(n.meter.average_bytes_per_second==null?'Скорость ещё не рассчитана.':'Средняя скорость: '+bytes(n.meter.average_bytes_per_second)+'/с за '+Math.round(n.meter.interval_seconds)+' с.')+(n.meter.state!=='active'?' Учёт не обновляется — проверьте событие агента.':'')+(n.meter.possible_loss_intervals?' Есть интервалы после перезапуска ядра с возможным недоучётом.':''):'Показаны зарегистрированные байты за период. Отсутствующая история не заменяется нулями.';
    table($('node-traffic-users'),['Пользователь','Hysteria2','VLESS / Xray'],n.traffic.users.map(u=>[button(u.username,()=>openUser(u.username)),bytes(u.hysteria2),bytes(u.xray)]));
  }
  $('node-settings').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{
    if(activeNode?.id==='xray:local')throw new Error('В карточке хаба нет настроек выходной ноды.');
    const value=id=>$(id)?.value||null,number=id=>$(id)?Number($(id).value):null;
    const data={name:value('node-name'),host_ids:activeNode.hosts.length?[...document.querySelectorAll('#node-hosts input:checked')].map(x=>Number(x.value)):null,address:value('node-address'),port:number('node-port'),api_port:number('node-api-port'),vpn_port:number('node-vpn-port'),usage_coefficient:number('node-coefficient'),enabled:$('node-enabled')?.checked??null,active:$('node-enabled')?.checked??null};
    const result=await api('/api/fleet/nodes/'+encodeURIComponent(activeNode.id),{method:'PUT',json:activeNode.monitoring_only?{name:data.name}:data});
    $('node-save-status').textContent=result.reconnect_scheduled?'Сохранено. Переподключение ноды запущено.':'Настройки сохранены и применены.';await window.Rime.refresh();
  }catch(err){$('node-save-status').textContent=err.message;}finally{b.disabled=false;}});
  $('node-check').addEventListener('click',run(()=>requestCheck(decodeURIComponent(location.hash.slice(6)),$('node-check-status'))));
  $('hub-refresh').addEventListener('click',async()=>{try{await nodeDetail();}catch(error){showError(error.message);}finally{$('hub-refresh').disabled=false;}});
  function quotaToggle(){
    $('quota-fields').disabled=!$('quota-enabled').checked;
    $('quota-reset-date').disabled=$('quota-period').value==='none';
    $('quota-reset-date').required=$('quota-period').value!=='none';
  }
  function quotaSummary(q){
    $('node-quota-summary').replaceChildren(quotaCell(q));
    if(q.enabled)$('node-quota-summary').append(el('p',(q.direction==='outgoing'?'Исходящий к VPN-клиентам':'Входящий + исходящий')+' · Начало: '+stamp(q.period_start)+' · Следующий сброс: '+(q.next_reset?stamp(q.next_reset):'вручную'),'small muted'));
  }
  function quotaForm(q){
    $('quota-enabled').checked=!!q.enabled;
    const unit=q.limit_bytes&&q.limit_bytes<1e12?1e9:1e12;
    $('quota-unit').value=String(unit);$('quota-volume').value=q.limit_bytes?q.limit_bytes/unit:5;
    $('quota-period').value=q.period||'monthly';$('quota-direction').value=q.direction||'total';$('quota-action').value=q.action||'warn';
    const next=new Date();next.setUTCMonth(next.getUTCMonth()+1,1);
    $('quota-reset-date').value=q.next_reset?new Date(q.next_reset*1000).toISOString().slice(0,10):next.toISOString().slice(0,10);
    $('quota-new-period').disabled=!q.node;$('quota-reset-confirm').hidden=true;$('quota-save-status').textContent='';quotaToggle();quotaSummary(q);
  }
  $('quota-enabled').addEventListener('change',quotaToggle);$('quota-period').addEventListener('change',quotaToggle);
  $('node-quota-form').addEventListener('submit',async e=>{
    e.preventDefault();const button=e.submitter;button.disabled=true;$('quota-save-status').textContent='Сохранение…';
    try{
      const target=activeNode?.id;
      if(!target||target!==decodeURIComponent(location.hash.slice(6)))throw new Error('Дождитесь загрузки выбранной ноды');
      const enabled=$('quota-enabled').checked;
      const data={limit_bytes:enabled?Math.round(Number($('quota-volume').value)*Number($('quota-unit').value)):0,
        period:$('quota-period').value,direction:$('quota-direction').value,action:$('quota-action').value,
        reset_date:$('quota-period').value==='none'?null:$('quota-reset-date').value};
      if(enabled&&data.limit_bytes<=0)throw new Error('Укажите объём больше нуля');
      const q=await api('/api/fleet/nodes/'+encodeURIComponent(target)+'/quota',{method:'PUT',json:data});
      if(activeNode?.id!==target)return;
      activeNode.quota=q;quotaForm(q);$('quota-save-status').textContent=q.blocked?'Сохранено. Применяется ограничение VPN-доступа.':'Лимит сохранён. Расход пользователей не изменён.';
      await window.Rime.refresh();
    }catch(err){$('quota-save-status').textContent=err.message;}finally{button.disabled=false;}
  });
  $('quota-new-period').addEventListener('click',()=>{$('quota-reset-confirm').hidden=false;});
  $('quota-reset-cancel').addEventListener('click',()=>{$('quota-reset-confirm').hidden=true;});
  $('quota-reset-apply').addEventListener('click',async()=>{
    $('quota-reset-apply').disabled=true;
    try{const target=activeNode?.id;if(!target||target!==decodeURIComponent(location.hash.slice(6)))throw new Error('Дождитесь загрузки выбранной ноды');const q=await api('/api/fleet/nodes/'+encodeURIComponent(target)+'/quota/reset',{method:'POST'});if(activeNode?.id!==target)return;activeNode.quota=q;quotaForm(q);$('quota-save-status').textContent='Новый период начат. Если квота блокировала VPN, доступ восстанавливается.';await window.Rime.refresh();}
    catch(error){$('quota-save-status').textContent=error.message;}finally{$('quota-reset-apply').disabled=false;}
  });
  $('node-report').addEventListener('click',()=>{$('filter-node').value=activeNode.id;$('filter-user').value='';$('filter-tag').value='';});
  $('node-delete').addEventListener('click',run(previewDelete));
  function report(data){
    metrics($('report-summary'),[['Всего',bytes(data.total),'Выбранный период'],['Hysteria2',bytes(data.totals.hysteria2),'Загрузка + отдача'],['VLESS / Xray',bytes(data.totals.xray),'Объединённый расход'],['Пользователей',data.users.length,'С трафиком за период']]);
    const grouped=new Map();for(const r of data.rows)grouped.set(r.node,(grouped.get(r.node)||0)+r.total);
    table($('traffic-by-node'),['Нода','Трафик','Доля'],[...grouped].sort((a,b)=>b[1]-a[1]).map(([node,total])=>[link(nodeName(node),'#node/'+encodeURIComponent(node)),bytes(total),data.total?(100*total/data.total).toFixed(1)+'%':'—']));
    $('traffic-coverage').textContent=(data.hy2_first_sample_hour?'Hysteria2: достоверные выборки с '+data.hy2_first_sample_hour+' UTC. ':'Hysteria2: в этом периоде нет подтверждённых выборок. ')+(data.gaps?.length?'Отмечено интервалов задержки или смены процесса: '+data.gaps.length+'. ':'')+'Передано пользователями: '+bytes(data.hy2_upload_bytes)+'; скачано: '+bytes(data.hy2_download_bytes)+'. Пропуски сбора показаны разрывами линии.';
  }
  window.RimeConsole={events,nodeLinks,report,connectionLink,connectionLabel,
    navigate(page){if(!state.token)return;run(async()=>{
      if(page==='users'){await tags();await users();}
      if(page==='traffic'){await tags();await picker();}
      if(page==='monitoring')await monitoring();
      if(page==='node')await nodeDetail();
    })();},
    async refresh(){
      if(location.hash==='#monitoring')await monitoring();
      if(location.hash==='#users'&&!$('user-dialog').open)await users();
      if(location.hash.startsWith('#node/')&&decodeURIComponent(location.hash.slice(6))==='xray:local')await nodeDetail();
      else if(location.hash.startsWith('#node/')&&activeNode){const live=state.overview?.nodes.find(n=>n.id===activeNode.id);if(live?.quota)quotaSummary(live.quota);}
      // Do not overwrite a node settings form while the administrator edits it.
    }
  };
})();
