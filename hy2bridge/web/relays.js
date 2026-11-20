"use strict";
(() => {
  let catalog, dialog, kind, draft, plan, removingEntry, switchingRoute, pendingNode, deploying = false;
  let version = 0, formVersion=0, navigationVersion=0, timer;
  const api = (...args) => window.Rime.api(...args);
  const el = (...args) => window.Rime.el(...args);
  const find = id => document.getElementById("relay-" + id);
  const button = (label, action, className = "secondary") => {
    const value = el("button",label,className); value.type = "button"; value.addEventListener("click",action); return value;
  };
  const savedKey = "rime.relay.job";
  function rememberJob(identity) {
    try { sessionStorage.setItem(savedKey,identity); } catch {}
  }
  function forgetJob(identity) {
    try {
      if (!identity || sessionStorage.getItem(savedKey) === identity) sessionStorage.removeItem(savedKey);
    } catch {}
  }
  function savedJob() {
    try {
      const identity = sessionStorage.getItem(savedKey);
      if (/^[a-f0-9]{32}$/.test(identity || "")) return identity;
      if (identity) sessionStorage.removeItem(savedKey);
    } catch {}
    return null;
  }
  function switchEntries(route) {
    return catalog.entries.filter(entry => entry.id !== route.entry && entry.state === "active" && entry.fresh);
  }
  function serviceLabel(service) {
    if (service.kind === "proxy") return {http:"HTTP-прокси",https:"HTTPS-прокси"}[service.mode] || "HTTP/HTTPS-прокси";
    return {vpn:"VPN",management:"Управление VLESS",ssh:"SSH через вход"}[service.kind] || service.kind;
  }
  function error(message) { find("error").textContent = message || ""; find("error").hidden = !message; }
  function checkLabel(route,service){
    if(service.kind==='management')return 'Связь контроллера';
    const check=route.result?.services?.find(value=>value.kind===service.kind&&value.origin_port===service.origin_port);
    if(!check)return 'Нет результата';
    if(!route.checked_at||Date.now()/1000-route.checked_at>180)return 'Проба устарела';
    if(check.passed)return 'Пройдена';
    const stages={payload:'Передача данных',proxy_connect:'Подключение к прокси',authorization:'Авторизация',credentials:'Доступы',ssh:'SSH',connect:'Подключение',client:'Запуск клиента',configuration:'Настройки',route:'Адрес'};
    return 'Ошибка · '+(stages[check.stage]||'Проверка');
  }

  async function navigate() {
    if (!location.hash.startsWith("#relays") || !window.Rime.state.token) return;
    const owner=++navigationVersion;
    try {
      const [value,overview] = await Promise.all([api("/api/fleet/relays"),window.Rime.state.overview ? Promise.resolve(null) : api("/api/fleet/overview")]);
      if(owner!==navigationVersion||!location.hash.startsWith('#relays'))return;
      catalog = value;
      if(overview)window.Rime.state.overview=overview;
      error(""); render();
      const saved = savedJob();
      if (saved && !dialog?.open) resume(saved);
      if(pendingNode){
        const node=pendingNode;pendingNode=null;
        const route=catalog.tunnels.find(value=>value.node===node.id);
        if(route){const card=Array.from(find('route-list').children).find(value=>value.dataset.routeId===route.id);card?.scrollIntoView({block:'center'});card?.focus();}
        else open('route',node.id);
      }
    } catch (failure) {
      if(owner!==navigationVersion||!location.hash.startsWith('#relays'))return;
      error(failure.status === 404 ? "Туннелирование ещё не включено в этой установке. Его можно проверить в демонстрационном контуре." : failure.message);
      find("add-route").disabled = true; find("add-entry").disabled = true;
    }
  }

  function render() {
    find("add-entry").disabled = !catalog.runtime_available;
    find("add-route").disabled = !catalog.entries.some(value => value.state === "active");
    const cards = catalog.entries.filter(value => value.state !== "deleted").map(entry => {
      const card = el("article",null,"card relay-entry"), health = entry.health || {};
      card.append(el("h2",entry.name),el("p",entry.domain,"muted"),el("span",entry.fresh ? "Свежая телеметрия" : "Нет свежих метрик","badge " + (entry.fresh ? "healthy" : "unknown")));
      const resources = el("div",null,"resource-row");
      for (const [name,value] of [["CPU",health.cpu_percent == null ? "—" : health.cpu_percent + "%"],
        ["Свободно RAM",window.Rime.bytes(health.mem_available_bytes)],["Свободно на диске",window.Rime.bytes(health.disk_free_bytes)]]) {
        const item = el("div"); item.append(el("p",name,"small muted"),el("strong",value)); resources.append(item);
      }
      const count = catalog.tunnels.filter(value => value.entry === entry.id && value.state === "active").length;
      const actions=el("div",null,"form-actions"),removeButton=button("Удалить вход",()=>open("entry-remove",entry.id),"quiet danger");
      removeButton.disabled=catalog.tunnels.some(value=>value.entry===entry.id) || entry.pending_cleanup_count > 0;
      if(removeButton.disabled)removeButton.title=entry.pending_cleanup_count > 0 ? "Дождитесь очистки прежних правил этого входа" : "Сначала удалите маршруты этого входа";
      const forget=button("Забыть вход",()=>forgetEntry(entry),"quiet danger");
      forget.disabled=catalog.tunnels.some(value=>value.entry===entry.id);
      if(forget.disabled)forget.title="Сначала верните маршруты на прямые адреса или смените их вход";
      actions.append(button("Проверить",async()=>{
        try{const job=await api('/api/fleet/relays/entry/'+encodeURIComponent(entry.id)+'/check',{method:'POST'});rememberJob(job.id);resume(job.id);}
        catch(failure){error(failure.message);}
      },"quiet"),removeButton,forget);
      if(health.quarantined_packets)card.append(el("p",`Пакетов телеметрии в карантине · ${health.quarantined_packets}. Свежие метрики продолжают поступать.`,"relay-cleanup-note"));
      card.append(resources,el("p",`Выходных нод · ${count}`,"small muted"),actions); return card;
    });
    find("entry-list").replaceChildren(...(cards.length ? cards : [el("p","Добавьте сервер, через который будут подключаться клиенты.","card muted")]));
    const routes = catalog.tunnels.map(route => {
      const item = el("section",null,"relay-route"), heading = el("div",null,"relay-route-header");
      item.dataset.routeId=route.id;item.tabIndex=-1;
      const node = window.Rime.state.overview?.nodes.find(value => value.id === route.node);
      const title = el("a",(node?.name || route.node) + " через " + route.entry_name,"relay-route-title"); title.href = "#node/" + encodeURIComponent(route.node);
      const actions=el('div',null,'form-actions');
      actions.append(button('Проверить маршрут',async()=>{
        try{const job=await api('/api/fleet/relays/routes/'+encodeURIComponent(route.id)+'/check',{method:'POST',timeoutMs:120000});rememberJob(job.id);resume(job.id);}
        catch(failure){error(failure.message);}
      }),button("Сменить вход",() => open("route-switch",route.id)),button("Удалить маршрут",() => remove(route),"quiet danger"),
      button("Вернуть прямой адрес",()=>detachRoute(route),"quiet danger"));
      heading.append(title,actions);
      const direct = node?.client_access;
      item.append(heading,el("p","Вход " + route.entry_domain + " → выход " + route.origin,"muted"),
        el("p",route.state === "active" && route.result?.passed && Date.now()/1000-route.checked_at<=180 ? "Через вход · трафик проверен " + window.Rime.stamp(route.checked_at) : "Маршрут требует свежей проверки","badge " + (route.state === "active" && route.result?.passed && Date.now()/1000-route.checked_at<=180 ? "healthy" : "degraded")),
        el("p","Прямая проверка из РФ · " + (direct?.state === "available" ? "доступна" : direct?.state === "unavailable" ? "трафик не прошёл" : "нет свежего результата"),"small muted"));
      if(route.grace_until>Date.now()/1000){
        item.append(el("p","Прежний вход сохранён до "+window.Rime.stamp(route.grace_until)+" для обновления подписок. Затем удалятся только его прежние правила.","relay-cleanup-note"));
      } else if (route.old_cleanup_pending || route.switch?.old_cleanup_pending) {
        item.append(el("p","Новый вход работает. Очистка прежних правил ожидает связи или сверки конфигурации старого входа.","relay-cleanup-note"));
      } else if (route.switch?.phase === "rollback_pending") {
        item.append(el("p","Прежний маршрут сохранён. Очистка правил попытки ожидает связи или сверки конфигурации нового входа.","relay-cleanup-note"));
      }
      const target = el("div",null,"table-wrap"); item.append(target);
      window.Rime.table(target,["Служба","Входной порт","Порт выхода","Проверка","К клиентам / от клиентов"],route.services.filter(value => value.state === "active").map(value => [
        serviceLabel(value),
        value.public_port + "/" + value.protocol.toUpperCase(),value.origin_port,
        checkLabel(route,value),
        window.Rime.bytes(value.traffic.rx) + " / " + window.Rime.bytes(value.traffic.tx)]));
      return item;
    });
    find("route-list").replaceChildren(...(routes.length ? routes : [el("p","Маршруты пока не созданы.","empty")]));
  }

  function ensure() {
    if (dialog) return;
    dialog = document.createElement("dialog"); dialog.className = "relay-dialog"; dialog.setAttribute("aria-labelledby","relay-dialog-title");
    dialog.innerHTML = `<header class="update-heading"><h2 id="relay-dialog-title"></h2><button type="button" id="relay-close" class="quiet" aria-label="Закрыть">×</button></header><div id="relay-dialog-body"></div><p id="relay-dialog-error" class="error" role="alert"></p>`;
    document.body.append(dialog); find("close").addEventListener("click",() => dialog.close());
    dialog.addEventListener("close",() => {version++;clearTimeout(timer);draft=null;plan=null;deploying=false;find("dialog-body").replaceChildren();});
  }

  function open(selected, nodeId) {
    ensure(); kind = selected; plan = null; draft = null; removingEntry=null; switchingRoute=null; deploying=false; version++; clearTimeout(timer);
    find("dialog-error").textContent = "";
    find("dialog-title").textContent = selected === "entry" ? "Добавить входной сервер" : selected==='entry-remove'?'Удалить входной сервер':selected==='route-switch'?"Сменить входной сервер":"Подключить ноду через вход";
    const body = find("dialog-body");
    if (selected === "route-switch") {
      switchingRoute = catalog.tunnels.find(route => route.id === nodeId);
      if (!switchingRoute) {
        body.replaceChildren(el("p","Маршрут изменился. Обновите список туннелей.","muted"),button("Закрыть",() => dialog.close()));
        if (!dialog.open) dialog.showModal();
        return;
      }
      const node = window.Rime.state.overview?.nodes.find(value => value.id === switchingRoute.node);
      const current = catalog.entries.find(entry => entry.id === switchingRoute.entry);
      const available = switchEntries(switchingRoute);
      body.replaceChildren(el("p",(node?.name || switchingRoute.node) + " · текущий вход " + switchingRoute.entry_name,"relay-path"));
      if (!current?.fresh) body.append(el("p","Нет свежей связи с текущим входом. Можно переключиться на другой доступный сервер.","relay-cleanup-note"));
      if (!available.length) {
        body.append(el("p","Других готовых входных серверов со свежей связью пока нет. Подготовьте ещё один вход и повторите смену.","muted"),button("Закрыть",() => dialog.close()));
        if (!dialog.open) dialog.showModal();
        return;
      }
      const content = el("div");
      content.innerHTML = `<form id="relay-form"><label>Новый входной сервер<select name="entry" required></select></label><label>Сохранить прежний вход для обновления подписок<select name="grace_hours"><option value="24">24 часа</option><option value="48">48 часов</option><option value="72">72 часа</option><option value="0">Удалить прежние правила сразу</option></select></label><p class="muted">Новый маршрут будет подготовлен и проверен перед переключением. После смены обновите существующую подписку в клиенте. Для недоступного прежнего входа льготный период не применяется.</p><button class="primary">Проверить новый вход</button></form>`;
      body.append(content);
      for (const entry of available) {
        const option = el("option",entry.name + " · " + entry.domain);
        option.value = entry.id; find("form").elements.entry.append(option);
      }
    } else if (selected !== "route") {
      body.innerHTML = `<p class="muted">Укажите прямой SSH-доступ. На сервере появится отдельная служба TCP/UDP и сборщик метрик.</p><form id="relay-form"><div class="form-grid"><label>Название<input name="name" required maxlength="64" placeholder="Например, Zurich"></label><label>Домен входа<input name="domain" required placeholder="entry.example.com"></label><label>SSH-адрес<input name="host" required placeholder="203.0.113.10"></label><label>SSH-порт<input name="ssh_port" type="number" value="22" required min="1" max="65535"></label><label>SSH-пользователь<input name="username" value="root" required></label><label>SSH-пароль<input name="password" type="password" required autocomplete="off"></label></div><details><summary>Вход по SSH-ключу и служебные порты</summary><label>Приватный SSH-ключ<textarea name="private_key" autocomplete="off"></textarea></label><label>Пароль ключа<input name="key_passphrase" type="password" autocomplete="off"></label><div class="form-grid"><label>Защищённое управление<input name="control_port" type="number" value="62080" min="1024" max="65535" required></label><label>Локальные метрики<input name="metrics_port" type="number" value="62081" min="1024" max="65535" required></label><label>Локальный API<input name="api_port" type="number" value="62082" min="1024" max="65535" required></label></div></details><button class="primary">Проверить сервер</button></form>`;
      const form = find("form"); form.elements.private_key.addEventListener("input",() => {form.elements.password.required = !form.elements.private_key.value.trim();});
      if(selected==='entry-remove'){
        removingEntry=catalog.entries.find(value=>value.id===nodeId);
        body.querySelector('p').textContent='Удаляется выбранная служба входа и её сборщик. Укажите свежий прямой SSH-доступ.';
        for(const name of ['name','domain','host','ssh_port','username']){form.elements[name].value=removingEntry[name];form.elements[name].readOnly=true;}
        form.querySelector('button').textContent='Проверить удаление';
      }
    } else {
      body.innerHTML = `<form id="relay-form"><label>Выходная нода<select name="node" required></select></label><label>Входной сервер<select name="entry" required></select></label><label>IP выхода для связи из входного сервера<input name="origin" placeholder="Из настроек ноды"><span class="small muted">Этот адрес сохраняется отдельно от публичного имени подключения.</span></label><label class="check"><input name="include_proxies" type="checkbox" checked> Включить HTTP/HTTPS-прокси ноды</label><label class="check"><input name="management" type="checkbox" checked> Подключать управление VLESS через выбранный вход</label><label class="check"><input name="ssh_enabled" type="checkbox" checked> SSH-доступ через выбранный вход</label><label>SSH-порт выходной ноды<input name="ssh_port" type="number" value="22" min="1" max="65535"><span class="small muted">Для изменения и удаления прокси с прежними SSH-доступами выходной ноды.</span></label><p class="muted">Все пользовательские ключи и URL подписок сохранятся. Для получения входного адреса понадобится обновить подписку в клиенте.</p><button class="primary">Проверить маршрут</button></form>`;
      for (const node of window.Rime.state.overview?.nodes || []) if (node.role !== "panel") {
        if(catalog.tunnels.some(route=>route.node===node.id))continue;
        const option = el("option",node.name); option.value = node.id; find("form").elements.node.append(option);
      }
      if (nodeId) find("form").elements.node.value = nodeId;
      for (const entry of catalog.entries.filter(value => value.state === "active")) {
        const option = el("option",entry.name + " · " + entry.domain); option.value = entry.id; find("form").elements.entry.append(option);
      }
    }
    const form=find('form');
    if(selected==='route'){
      const toggle=()=>{form.elements.ssh_port.disabled=!form.elements.ssh_enabled.checked;form.elements.ssh_port.required=form.elements.ssh_enabled.checked;};
      form.elements.ssh_enabled.addEventListener('change',toggle);toggle();
    }
    form.addEventListener('input',()=>{formVersion++;draft=null;plan=null;form.querySelector('button').disabled=false;});
    form.addEventListener("submit",prepare); if (!dialog.open) dialog.showModal();
  }

  async function prepare(event) {
    event.preventDefault(); find("dialog-error").textContent = "";
    const form = find("form"), submit = form.querySelector("button"); submit.disabled = true;
    const owner=version,epoch=formVersion;
    const values = Object.fromEntries(new FormData(form));
    try {
      if (kind === "route-switch") {
        draft = {entry:values.entry,grace_seconds:Number(values.grace_hours)*3600};
        await requestPlan();
      } else if (kind !== "route") {
        draft = {...values,ssh_port:Number(values.ssh_port),control_port:Number(values.control_port),metrics_port:Number(values.metrics_port),api_port:Number(values.api_port)};
        const identity = await api("/api/fleet/provision/host-key",{method:"POST",json:{host:draft.host,ssh_port:draft.ssh_port}});
        if(owner!==version||epoch!==formVersion||!dialog.open)return;
        Object.assign(draft,identity); form.hidden = true;
        const trust = el("section"); trust.append(el("h3","Проверка подлинности входного сервера"),el("p","Сверьте отпечаток с данными провайдера или доверенного подключения.","muted"),el("code",identity.fingerprint));
        const label = el("label",null,"check"), check = el("input"); check.type = "checkbox"; label.append(check,document.createTextNode("Отпечаток проверен"));
        const next = button("Продолжить проверку",() => requestPlan()); next.disabled = true; check.addEventListener("change",() => {next.disabled = !check.checked;});
        trust.append(label,next); find("dialog-body").append(trust);
      } else {
        draft = {...values,include_proxies:form.elements.include_proxies.checked,management:form.elements.management.checked,ssh_port:form.elements.ssh_enabled.checked ? Number(values.ssh_port) : null};
        await requestPlan();
      }
    } catch (failure) {if(owner===version&&epoch===formVersion&&dialog.open){find("dialog-error").textContent = failure.message;submit.disabled = false;}}
  }

  async function requestPlan() {
    if(!draft)return;
    const owner=version,epoch=formVersion;
    find("dialog-error").textContent = "";
    try {
      const path=kind==='entry-remove'?'entry/'+encodeURIComponent(removingEntry.id)+'/remove':kind==='route-switch'?'routes/'+encodeURIComponent(switchingRoute.id)+'/switch':kind;
      const received = await api("/api/fleet/relays/" + path + "/plan",{method:"POST",json:draft,timeoutMs:60000});
      if(owner!==version||epoch!==formVersion||!dialog.open)return;
      plan=received;
      const body = find("dialog-body");
      body.replaceChildren(...(kind === "route-switch" ? [] : [el("p",plan.message,"muted")]));
      if (kind === "route-switch") {
        const from = plan.from_entry?.name || switchingRoute.entry_name;
        const to = plan.to_entry?.name || catalog.entries.find(entry => entry.id === draft.entry)?.name;
        body.append(el("div",from + " → " + to,"relay-path"));
        const table = el("div",null,"table-wrap"); body.append(table);
        window.Rime.table(table,["Служба","Новый входной порт","Порт выхода"],plan.services.map(value => [
          serviceLabel(value),
          value.public_port + "/" + value.protocol.toUpperCase(),value.origin_port]));
        body.append(el("p",plan.message || "Адрес подписки и пользовательские ключи сохранятся. Для получения нового входа обновите подписку в клиенте.","muted"));
      } else if (kind === "route") {
        body.append(el("div",plan.entry_name + " → " + plan.name + " · " + plan.origin,"relay-path"));
        const table = el("div",null,"table-wrap"); body.append(table);
        window.Rime.table(table,["Служба","Вход","Выход"],plan.services.map(value => [value.kind,value.public_port + "/" + value.protocol,value.origin_port]));
      } else body.append(el("p",plan.domain + " · " + plan.address,"relay-path"));
      body.append(button(kind === "entry" ? "Установить входной сервер" : kind==='entry-remove'?'Удалить входной сервер':kind==='route-switch'?"Сменить вход":"Включить туннель",deploy,"primary"));
    } catch (failure) {if(owner===version&&epoch===formVersion&&dialog.open){find("dialog-error").textContent = failure.message;find("form")?.querySelector("button")?.removeAttribute("disabled");}}
  }

  async function deploy() {
    if(!plan || deploying)return;
    deploying = true;
    const owner=version,selected=plan;
    const buttons=Array.from(find("dialog-body").querySelectorAll("button"));
    for (const control of buttons) control.disabled = true;
    rememberJob(selected.id);
    try {
      const job = await api("/api/fleet/relays/deploy",{method:"POST",json:{plan_id:selected.id}});
      if(owner!==version||!dialog.open)return;
      draft = null; rememberJob(job.id); resume(job.id);
    } catch (failure) {
      try{await api('/api/fleet/relays/jobs/'+encodeURIComponent(selected.id));if(owner===version&&dialog.open)resume(selected.id);}
      catch{
        forgetJob(selected.id);
        if(owner===version&&dialog.open){
          deploying=false;
          for (const control of buttons) control.disabled = false;
          find('dialog-error').textContent=failure.message;
        }
      }
    }
  }

  function resume(id) {
    ensure(); if (!dialog.open) dialog.showModal(); version++; clearTimeout(timer);
    find("dialog-title").textContent = kind === "route-switch" ? "Смена входного сервера" : "Изменение туннеля"; find("dialog-error").textContent = "";
    find("dialog-body").innerHTML = `<div id="relay-progress"></div><p id="relay-job-message" role="status"></p><p id="relay-job-note" class="relay-cleanup-note" hidden></p><ol id="relay-job-log" class="relay-job-log"></ol>`;
    poll(id,version);
  }

  async function poll(id, owner) {
    try {
      const job = await api("/api/fleet/relays/jobs/" + encodeURIComponent(id));
      if (owner !== version || !dialog.open) return;
      find("dialog-error").textContent = "";
      if (job.context?.operation === "route-switch") find("dialog-title").textContent = "Смена входного сервера";
      window.RimeProgress.mount(find("progress")).update(window.RimeProgress.job(job));
      find("job-message").textContent = job.message;
      find("job-log").replaceChildren(...job.steps.map(value => el("li",typeof value === "string" ? value : value.message)));
      const grace=job.context?.grace_until>Date.now()/1000;
      const pendingCleanup = job.state === "succeeded" && (job.context?.old_cleanup_pending || job.context?.cleanup_pending || grace);
      find("job-note").hidden = !pendingCleanup;
      find("job-note").textContent = grace ? "Прежний вход сохранён до "+window.Rime.stamp(job.context.grace_until)+" для обновления подписок." : pendingCleanup ? (job.context?.operation==='route-switch'?"Новый вход работает.":"Подписка возвращена на прямые адреса.")+" Очистка прежних правил ожидает связи или сверки конфигурации входа." : "";
      if (["succeeded","failed","rolled_back"].includes(job.state)) {
        deploying=false; forgetJob(id); await navigate();
        if (owner !== version || !dialog.open) return;
        if (job.state === "succeeded" && job.context?.operation === "route-switch") {
          find("dialog-body").append(el("p","Обновите существующую подписку в клиенте, чтобы получить адрес нового входа.","muted"));
        }
        find("dialog-body").append(button("Закрыть",() => dialog.close()));
      } else timer = setTimeout(() => poll(id,owner),1500);
    } catch (failure) {
      if (owner !== version || !dialog.open) return;
      find("dialog-error").textContent = failure.status === 404 ? "Задание не найдено. Обновите список туннелей и проверьте состояние маршрута." : "Не удалось получить состояние операции. Повторяем проверку связи с панелью.";
      if(failure.status===404){forgetJob(id);find("dialog-body").append(button("Закрыть",() => dialog.close()));return;}
      timer = setTimeout(() => poll(id,owner),3000);
    }
  }

  async function remove(route) {
    ensure(); version++; find("dialog-title").textContent = "Удалить туннель";
    find("dialog-body").replaceChildren(el("p","Будут удалены только правила этого маршрута. VPN и прокси выходной ноды сохранятся. Подписка вернётся к прямым адресам.","muted"),
      button("Удалить маршрут",async () => {
        try {
          const job = await api("/api/fleet/relays/routes/" + encodeURIComponent(route.id),{method:"DELETE"});
          rememberJob(job.id); resume(job.id);
        } catch (failure) {find("dialog-error").textContent = failure.message;}
      },"primary danger"));
    find("dialog-error").textContent = ""; dialog.showModal();
  }

  function explicit(title,message,expected,typed,action) {
    ensure();version++;clearTimeout(timer);deploying=false;find('dialog-title').textContent=title;find('dialog-error').textContent='';
    const owner=version,label=el('label'),input=el('input'),submit=button(title,async()=>{
      if(submit.disabled)return;submit.disabled=true;
      try{await action();}catch(failure){if(owner===version&&dialog.open){find('dialog-error').textContent=failure.message;submit.disabled=false;}}
    },'primary danger');
    input.type=typed?'text':'checkbox';input.name='confirmation';input.autocomplete='off';submit.disabled=true;
    label.append(input,document.createTextNode(typed?'Введите точный домен: '+expected:'Подтверждаю возврат выбранной ноды на прямые адреса'));
    input.addEventListener(typed?'input':'change',()=>{submit.disabled=typed?input.value!==expected:!input.checked;});
    find('dialog-body').replaceChildren(el('p',message,'muted'),label,submit);if(!dialog.open)dialog.showModal();
  }

  function detachRoute(route) {
    explicit('Вернуть прямой адрес','Подписка выбранной ноды вернётся к прямым адресам, даже если вход недоступен. Незавершённые изменения маршрута после прерывания будут отменены; выполняющиеся операции блокируют возврат. VPN-ключи и прокси выхода сохраняются. Очистка прежних правил будет отложена до восстановления связи.',route.id,false,async()=>{
      const job=await api('/api/fleet/relays/routes/'+encodeURIComponent(route.id)+'/detach',{method:'POST',json:{confirmation:route.id}});
      rememberJob(job.id);resume(job.id);
    });
  }

  function forgetEntry(entry) {
    explicit('Забыть вход','Из панели удалятся регистрация входа и его токен. Отложенная очистка будет прекращена. Службы на недоступном сервере не удаляются; при его возвращении их нужно убрать вручную.',entry.domain,true,async()=>{
      await api('/api/fleet/relays/entry/'+encodeURIComponent(entry.id)+'/forget',{method:'POST',json:{confirmation:entry.domain}});
      dialog.close();await navigate();
    });
  }
  find("add-entry").addEventListener("click",() => open("entry"));
  find("add-route").addEventListener("click",() => open("route"));
  addEventListener('hashchange',()=>{if(!location.hash.startsWith('#relays')){navigationVersion++;pendingNode=null;}});
  window.RimeRelays = {navigate,openNode:node => {pendingNode=node;if(location.hash==='#relays')navigate();else location.hash='#relays';}};
})();
