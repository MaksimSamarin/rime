"use strict";
(() => {
  const fields=["host","ssh_port","username","domain","proxy_username","http_port","https_port"];
  let dialog,api,node,plan,draft,currentJob,pollTimer,planTimer,checking,editingService=null,reconciling=false,revision=0,formVersion=0,connectionEpoch=0,checkingRequest=0;
  let registeredServices=new Map(),accessMetadata=null;
  const connectionViews=new Map();
  const $=id=>dialog.querySelector("#proxy-"+id);
  const message=text=>{$("error").textContent=text||"";};
  const storageKey=()=>"rime.proxy.job."+node.id;
  const saveJob=id=>{try{sessionStorage.setItem(storageKey(),id);}catch{}};
  const forgetJob=()=>{try{sessionStorage.removeItem(storageKey());}catch{}};

  function element(tag,text,className){
    const value=document.createElement(tag);
    if(text!=null)value.textContent=text;
    if(className)value.className=className;
    return value;
  }
  function randomPassword(){
    const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
  }
  function modes(){
    const legacy=$("replace-legacy").checked||reconciling;
    $("http-port").disabled=legacy||!$("http-enabled").checked;
    $("https-port").disabled=legacy||!$("https-enabled").checked;
    $("domain").required=$("https-enabled").checked;
  }
  function invalidateForm(){
    formVersion++;clearTimeout(planTimer);plan=null;draft=null;
    $("fingerprint-card").hidden=true;$("plan").hidden=true;$("fingerprint").textContent="";
    $("trust").checked=false;$("verify").disabled=true;$("deploy").disabled=true;$("preflight").disabled=false;
  }
  function authMode(clear=false){
    const useKey=$("auth-method").value==='key',form=$("form");
    const password=form.elements.namedItem('password'),key=form.elements.namedItem('private_key'),passphrase=form.elements.namedItem('key_passphrase');
    $("password-fields").hidden=useKey;$("key-fields").hidden=!useKey;
    password.disabled=useKey;password.required=!useKey;key.disabled=!useKey;key.required=useKey;passphrase.disabled=!useKey;
    if(clear)for(const field of [password,key,passphrase])field.value='';
  }
  function nodeDomain(){
    const endpoint=(node.hosts||[]).find(host=>host.node===node.id&&/^[A-Za-z0-9.-]+\.[A-Za-z]+$/.test(host.address||""));
    return node.settings?.domain||node.domain||endpoint?.address||(/[A-Za-z]/.test(node.address||"")?node.address:"");
  }
  function legacyMode(clear=false){
    const legacy=$("replace-legacy").checked,user=$("form").elements.namedItem('proxy_username');
    const edit=!!editingService;
    $("access-fields").hidden=reconciling;$("reconcile-fields").hidden=!reconciling;$("reconcile-password").disabled=!reconciling;
    for(const name of ['domain','http_port','https_port','proxy_username','proxy_password','certificate','certificate_key'])$("form").elements.namedItem(name).disabled=reconciling;
    $("legacy-section").hidden=edit;$("replace-legacy").disabled=edit;$("edit-cancel").hidden=!edit;
    $("form-title").textContent=reconciling?'Сверить установку прокси':edit?'Изменить действующий прокси':legacy?'Перевести существующий Squid':'Добавить прокси';
    $("form-help").textContent=reconciling?'Сверка подтвердит управляемый контейнер либо вернёт предыдущую рабочую установку. Нужен свежий SSH-доступ.':edit?'Текущие параметры заполнены ниже. Изменения применяются после SSH-проверки и подтверждения плана.':legacy?'Введите действующий пароль. Логин и адреса будут считаны и сверены на сервере.':'Параметры новой установки и новой учётной записи прокси.';
    $("user-label").textContent=edit?'Логин прокси':legacy?'Действующий логин прокси':'Новый логин прокси';
    $("password-label").textContent=edit?'Новый пароль, если требуется изменить':legacy?'Действующий пароль прокси':'Новый пароль прокси';
    user.disabled=legacy||reconciling;user.required=!legacy&&!reconciling;user.placeholder=legacy?'Определится на сервере':'Например, rime_proxy';
    $("proxy-password").minLength=legacy?1:12;$("proxy-password").required=!edit;$("proxy-password").placeholder=edit?'Оставить текущий':'';
    $("domain").readOnly=legacy||edit&&editingService.locked_domain!==false;
    $("domain-help").textContent=edit&&$("domain").readOnly?'Для этого прокси используется сохранённый TLS-домен.':'DNS должен указывать на выбранную ноду. TLS-сертификат проверяется при подготовке установки.';
    $("http-enabled").disabled=legacy||reconciling;$("https-enabled").disabled=legacy||reconciling;
    $("generate").hidden=legacy;
    $("secret-help").textContent=edit?'Пустое поле пароля сохраняет действующий пароль, уже сохранённый в панели. После применения готовые адреса доступны в карточке.':legacy?'Используйте пароль действующего прокси. После успешного перевода доступы можно копировать из карточки.':'Укажите новый пароль или сгенерируйте его. После успешной установки доступы сохранятся в панели для копирования.';
    $("deploy").textContent=edit?'Применить изменения':legacy?'Перевести Squid':'Установить прокси';
    $("verify").textContent=reconciling?'Сверить и восстановить':'Продолжить проверку';
    if(clear){
      user.value='';$("proxy-password").value='';
      $("http-enabled").checked=true;$("https-enabled").checked=true;
      $("http-port").value='3128';$("https-port").value=legacy||node.protocol==='hysteria2'?'443':'8443';
      if(legacy)$("domain").value=nodeDomain();
    }
    modes();
  }
  function clearSensitive(){
    draft=null;checkingRequest++;
    for(const name of ["password","private_key","key_passphrase","proxy_password","certificate_key"]){
      const field=$("form").elements.namedItem(name);if(field)field.value="";
    }
    $("check-password").value="";
    $("reconcile-password").value="";
    $("remember").checked=false;
  }
  function maskedUrl(service,scheme){
    const endpoint=service.endpoints?.[scheme],address=endpoint?.host||service.domain;
    const host=address.includes(':')&&!address.startsWith('[')?'['+address+']':address;
    return scheme+'://'+encodeURIComponent(service.username)+':••••••••@'+host+':'+(endpoint?.port||service[scheme+'_port']);
  }
  const credentialsSaved=service=>service.credentials_available??service.credentials_saved;
  async function checkSaved(service,button){
    const version=revision,request=++checkingRequest;
    const current=()=>version===revision&&request===checkingRequest&&dialog.open;
    clearConnections(false);button.disabled=true;message('Проверка с сохранёнными доступами…');
    try{
      const result=await api('/api/fleet/proxy/'+encodeURIComponent(service.id)+'/check',{method:'POST',timeoutMs:120000,json:{proxy_password:'',remember:false}});
      if(!current())return;
      await loadServices();
      if(current())message(result.passed?'Проверка пройдена.':'Проверка завершилась сбоем. Результат показан в карточке.');
    }catch(error){if(current())message(error.message);}
    finally{if(current())button.disabled=false;}
  }
  function maskConnection(view,empty=false){
    view.revealed=false;
    for(const [scheme,input]of view.inputs){input.value=empty?'':maskedUrl(view.service,scheme);view.labels.get(scheme).textContent=scheme.toUpperCase()+' URL · пароль скрыт';}
    view.toggle.textContent='Показать пароль';view.toggle.setAttribute('aria-pressed','false');
  }
  function clearConnections(remove=true){
    connectionEpoch++;
    for(const view of connectionViews.values()){
      maskConnection(view,remove);
      view.status.textContent='';
      for(const button of view.buttons)button.disabled=remove||view.blocked;
    }
    if(remove)connectionViews.clear();
  }
  function changeContext(){revision++;clearConnections(false);}
  async function connectionAction(view,scheme){
    const version=revision,epoch=connectionEpoch;
    const current=()=>version===revision&&epoch===connectionEpoch&&dialog.open&&connectionViews.get(view.service.id)===view;
    if(!current()||view.blocked)return;
    if(!scheme&&view.revealed){
      maskConnection(view);view.status.textContent='';return;
    }
    for(const button of view.buttons)button.disabled=true;
    view.status.textContent='Получение сохранённых доступов…';let connection=null;
    try{
      connection=await api('/api/fleet/proxy/'+encodeURIComponent(view.service.id)+'/connection');
      if(!current())return;
      if(connection.id!==view.service.id||connection.node!==node.id)throw new Error('Сведения прокси изменились. Откройте карточку заново.');
      if(connection.deployment_state&&connection.deployment_state!=='succeeded')throw new Error('Установка требует сверки. Дождитесь завершения задачи.');
      if(!connection.credentials_available||connection.needs_password)throw new Error('Сначала проверьте действующий пароль с сохранением в панели.');
      const urls=connection.urls||{};
      if(scheme){
        if(typeof urls[scheme]!=='string'||!urls[scheme].startsWith(scheme+'://'))throw new Error('Этот режим прокси отключён. Откройте карточку заново.');
        await navigator.clipboard.writeText(urls[scheme]);
        if(current())view.status.textContent=scheme.toUpperCase()+'-адрес скопирован с логином и паролем.';
      }else{
        for(const mode of view.inputs.keys()){
          if(typeof urls[mode]!=='string'||!urls[mode].startsWith(mode+'://'))throw new Error('Режимы прокси изменились. Откройте карточку заново.');
        }
        for(const [mode,input]of view.inputs){input.value=urls[mode];view.labels.get(mode).textContent=mode.toUpperCase()+' URL · пароль показан';}
        view.revealed=true;view.toggle.textContent='Скрыть пароль';view.toggle.setAttribute('aria-pressed','true');view.status.textContent='Показаны действующие доступы.';
      }
    }catch(error){if(current()){maskConnection(view);view.status.textContent=error.message;}}
    finally{connection=null;if(current())for(const button of view.buttons)button.disabled=view.blocked;}
  }
  function configureEdit(service){
    editingService=service;
    $("form").elements.namedItem('replace_service').value=service.id;
    $("form").elements.namedItem('domain').value=service.domain;
    $("form").elements.namedItem('proxy_username').value=service.username||'';
    $("http-enabled").checked=service.http_port!=null;$("https-enabled").checked=service.https_port!=null;
    $("http-port").value=service.http_port??3128;$("https-port").value=service.https_port??(node.protocol==='hysteria2'?443:8443);
    $("replace-legacy").checked=false;$("proxy-password").value='';legacyMode();
  }
  function editService(service){
    changeContext();forgetJob();resetForm();configureEdit(service);$("form").scrollIntoView({block:'start'});
  }
  function reconcileService(service){
    editService(service);reconciling=true;legacyMode();
  }
  function connectionFields(service,blocked){
    const root=element('section'),controls=element('div',null,'form-grid'),toggle=element('button','Показать пароль','secondary'),status=element('p','','small muted');
    toggle.type='button';toggle.setAttribute('aria-pressed','false');
    const view={service,inputs:new Map(),labels:new Map(),buttons:[],toggle,status,revealed:false,blocked:blocked||credentialsSaved(service)===false};
    for(const scheme of ['http','https'])if(service[scheme+'_port']!=null){
      const label=element('label'),caption=element('span',scheme.toUpperCase()+' URL · пароль скрыт'),input=element('input');
      input.type='text';input.readOnly=true;input.autocomplete='off';input.spellcheck=false;input.value=maskedUrl(service,scheme);
      input.setAttribute('aria-label',scheme.toUpperCase()+' адрес прокси');label.append(caption,input);root.append(label);
      const copy=element('button','Копировать '+scheme.toUpperCase(),'secondary');copy.type='button';copy.disabled=view.blocked;
      copy.addEventListener('click',()=>connectionAction(view,scheme));controls.append(copy);view.buttons.push(copy);view.inputs.set(scheme,input);view.labels.set(scheme,caption);
    }
    toggle.disabled=view.blocked;toggle.addEventListener('click',()=>connectionAction(view));view.buttons.push(toggle);controls.append(toggle);
    root.append(element('p',credentialsSaved(service)===false?'Для копирования и изменений сначала проверьте текущий пароль с сохранением в панели.':'Кнопка копирования получает полный действующий адрес с логином и паролем.','small muted'),controls,status);
    connectionViews.set(service.id,view);return root;
  }
  function resetForm(){
    formVersion++;checkingRequest++;clearTimeout(pollTimer);clearTimeout(planTimer);plan=null;draft=null;currentJob=null;checking=null;editingService=null;reconciling=false;
    $("form").reset();$("form").hidden=false;$("plan").hidden=true;$("fingerprint-card").hidden=true;
    $("job").hidden=true;$("retry").hidden=true;$("new").hidden=true;$("check-form").hidden=true;
    for(const id of ["preflight","verify","deploy"])$(id).disabled=false;
    $("check-form").querySelector('button[type="submit"],button:not([type])').disabled=false;
    $("remember").checked=false;
    $("reconcile-password").value='';
    $("verify").disabled=true;
    $("form").elements.namedItem("node").value=node.id;
    $("form").elements.namedItem("host").value=node.address||"";
    if(accessMetadata)for(const name of ['host','ssh_port','username'])$("form").elements.namedItem(name).value=accessMetadata[name];
    $('access-route').textContent=accessMetadata?.via_entry?'SSH через '+accessMetadata.entry_name+' к выходной ноде':'Прямой SSH-доступ к ноде';
    $("form").elements.namedItem("domain").value=nodeDomain();
    $("https-port").value=node.protocol==='hysteria2'?'443':'8443';
    authMode();legacyMode();$("add").disabled=false;$("add").hidden=true;message("");
  }
  function ensureDialog(){
    if(dialog)return;
    dialog=document.createElement("dialog");dialog.id="proxy-dialog";dialog.className="proxy-dialog";
    dialog.setAttribute("aria-labelledby","proxy-title");
    dialog.innerHTML=`
      <header class="card-heading"><h2 id="proxy-title">HTTP/HTTPS-прокси</h2><button type="button" class="quiet" id="proxy-close" aria-label="Закрыть">×</button></header>
      <p class="muted">Отдельный прокси с логином и паролем. HTTPS включает TLS между клиентом и прокси.</p>
      <details><summary>Учёт трафика прокси</summary><p class="small muted">Прокси использует отдельную авторизацию. Квоты VPN-подписок к нему не применяются. Сетевые метрики ОС показывают общий трафик сервера.</p></details>
      <section id="proxy-services" aria-label="Установленные прокси"><h3>Установленные прокси</h3><p id="proxy-services-empty" class="small muted">Загрузка сведений…</p><div id="proxy-services-list"></div></section>
      <div class="form-actions"><button id="proxy-add" type="button" class="secondary" hidden>Добавить ещё прокси</button></div>
      <form id="proxy-check-form" hidden><label>Действующий пароль для проверки<input id="proxy-check-password" type="password" autocomplete="off" required></label><label class="check"><input id="proxy-remember" type="checkbox"> Сохранить пароль в панели после успешной проверки</label><p class="small muted">Сохранённые доступы можно получить и скопировать из карточки прокси.</p><div class="form-actions"><button type="button" class="quiet" id="proxy-check-cancel">Отмена проверки</button><button class="secondary">Проверить подключение</button></div></form>
      <form id="proxy-form">
        <input name="node" type="hidden"><input name="cleanup_job" type="hidden"><input name="replace_service" type="hidden">
        <h3 id="proxy-form-title">Добавить прокси</h3><p id="proxy-form-help" class="small muted">Параметры новой установки и новой учётной записи прокси.</p>
        <div id="proxy-legacy-section"><label class="check"><input id="proxy-replace-legacy" type="checkbox"> Заменить существующий Squid</label>
        <p class="small muted">Этот режим переносит действующую установку с её адресами и логином. Перед остановкой панель проверит системную службу Squid и сохранит конфигурацию для отката при ошибке.</p></div>
        <h3>Подключение к серверу</h3><p id="proxy-access-route" class="small muted"></p><div class="form-grid">
          <label>SSH-адрес<input name="host" required autocomplete="off"></label><label>SSH-порт<input name="ssh_port" type="number" min="1" max="65535" value="22" required></label>
          <label>SSH-пользователь<input name="username" value="root" required autocomplete="off"></label>
          <label>Способ входа<select id="proxy-auth-method"><option value="password" selected>Пароль</option><option value="key">SSH-ключ</option></select></label>
          <div id="proxy-password-fields" class="wide"><label>SSH-пароль пользователя сервера<input name="password" type="password" autocomplete="off" required></label></div>
          <div id="proxy-key-fields" class="wide" hidden><label>Приватный SSH-ключ для входа<textarea name="private_key" rows="4" autocomplete="off" spellcheck="false" disabled></textarea></label><label>Пароль SSH-ключа, если задан<input name="key_passphrase" type="password" autocomplete="off" disabled></label></div>
        </div>
        <div id="proxy-reconcile-fields" hidden><label>Действующий пароль прокси, если он ещё не сохранён в панели<input id="proxy-reconcile-password" type="password" minlength="1" maxlength="72" autocomplete="off" disabled></label><p class="small muted">Для сохранённого доступа оставьте поле пустым. Параметры установки сверяются с журналом панели.</p></div>
        <div id="proxy-access-fields"><h3>Режимы и доступ</h3><div class="form-grid">
          <label class="check"><input id="proxy-http-enabled" type="checkbox" checked> HTTP-прокси</label><label>HTTP-порт<input id="proxy-http-port" name="http_port" type="number" min="1" max="65535" value="3128"></label>
          <label class="check"><input id="proxy-https-enabled" type="checkbox" checked> HTTPS-прокси с TLS</label><label>HTTPS-порт<input id="proxy-https-port" name="https_port" type="number" min="1" max="65535" value="8443"></label>
          <label class="wide">Домен / SNI<input id="proxy-domain" name="domain" placeholder="node.example.com"><span id="proxy-domain-help" class="small muted">DNS должен указывать на выбранную ноду. TLS-сертификат проверяется при подготовке установки.</span></label>
          <label><span id="proxy-user-label">Новый логин прокси</span><input name="proxy_username" placeholder="Например, rime_proxy" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*" maxlength="64" required autocomplete="off"></label>
          <label><span id="proxy-password-label">Новый пароль прокси</span><input id="proxy-proxy-password" name="proxy_password" type="password" minlength="12" maxlength="72" autocomplete="off" required></label>
        </div>
        <p class="small muted">Свободность выбранных портов будет проверена через SSH перед установкой.</p>
        <div class="form-actions"><button id="proxy-generate" type="button" class="quiet">Сгенерировать новый пароль</button></div>
        <p id="proxy-secret-help" class="small muted">После успешной установки доступы сохранятся в панели для копирования.</p>
        <details><summary>Собственный TLS-сертификат</summary><div class="form-grid"><label>Сертификат PEM<textarea name="certificate" rows="4" spellcheck="false"></textarea></label><label>Приватный ключ PEM<textarea name="certificate_key" rows="4" autocomplete="off" spellcheck="false"></textarea></label></div></details>
        </div>
        <div class="form-actions"><button id="proxy-edit-cancel" type="button" class="quiet" hidden>Отмена изменений</button><button id="proxy-preflight" class="primary">Проверить сервер</button></div>
      </form>
      <section id="proxy-fingerprint-card" hidden><h3>Проверка подлинности сервера</h3><p class="small muted">Отпечаток публичного SSH-ключа. Сверьте его с данными провайдера или ранее проверенного доступа.</p><code id="proxy-fingerprint"></code><label class="check"><input id="proxy-trust" type="checkbox"> Отпечаток проверен</label><div class="form-actions"><button id="proxy-key-back" type="button" class="quiet">Вернуться к форме</button><button id="proxy-verify" type="button" class="primary" disabled>Продолжить проверку</button></div></section>
      <section id="proxy-plan" hidden><h3>План установки</h3><div id="proxy-plan-details"></div><p class="small muted">После успешного применения готовые адреса с логином и паролем доступны в карточке прокси.</p><div class="form-actions"><button id="proxy-back" type="button" class="quiet">Вернуться к форме</button><button id="proxy-deploy" type="button" class="primary">Установить прокси</button></div></section>
      <section id="proxy-job" hidden><h3>Установка прокси</h3><p id="proxy-job-state" role="status"></p><ol id="proxy-steps" class="job-steps"></ol><div class="form-actions"><button id="proxy-retry" type="button" class="secondary" hidden>Повторить проверку</button><button id="proxy-new" type="button" class="quiet" hidden>К форме установки</button></div></section>
      <p id="proxy-error" class="error" role="alert"></p>`;
    document.body.append(dialog);
    $("close").addEventListener("click",()=>dialog.close());
    dialog.addEventListener("close",()=>{revision++;clearTimeout(pollTimer);clearTimeout(planTimer);clearConnections();clearSensitive();editingService=null;reconciling=false;});
    $("form").addEventListener('input',invalidateForm);
    $("auth-method").addEventListener('change',()=>{invalidateForm();authMode(true);});
    $("replace-legacy").addEventListener('change',()=>{invalidateForm();legacyMode(true);});
    $("add").addEventListener('click',()=>{changeContext();forgetJob();resetForm();});
    $("edit-cancel").addEventListener('click',()=>{changeContext();resetForm();$("form").hidden=true;$("add").hidden=false;});
    $("http-enabled").addEventListener("change",modes);$("https-enabled").addEventListener("change",modes);
    $("generate").addEventListener("click",()=>{if($("replace-legacy").checked)return;invalidateForm();$("proxy-password").value=randomPassword();});
    $("form").addEventListener("submit",preflight);
    $("trust").addEventListener("change",()=>{$("verify").disabled=!$("trust").checked;});
    $("verify").addEventListener("click",verify);
    $("key-back").addEventListener("click",()=>{changeContext();$("fingerprint-card").hidden=true;$("form").hidden=false;$("preflight").disabled=false;draft=null;});
    $("back").addEventListener("click",()=>{changeContext();clearTimeout(planTimer);$("plan").hidden=true;$("form").hidden=false;$("preflight").disabled=false;plan=null;});
    $("deploy").addEventListener("click",deploy);
    $("new").addEventListener("click",()=>{changeContext();forgetJob();resetForm();});
    $("retry").addEventListener("click",()=>{
      const previous=currentJob,target=registeredServices.get(currentJob.id);
      if(target?.reconcile_allowed){reconcileService(target);return;}
      changeContext();forgetJob();resetForm();
      if(previous.context.replace_service){
        const service=registeredServices.get(previous.context.replace_service)||{id:previous.context.replace_service,domain:previous.context.domain,username:previous.context.proxy_username,http_port:previous.context.http_port,https_port:previous.context.https_port,locked_domain:true};
        configureEdit(service);
      }
      for(const name of fields){const field=$("form").elements.namedItem(name);if(field&&previous.context[name]!=null)field.value=previous.context[name];}
      $("http-enabled").checked=previous.context.http_port!=null;$("https-enabled").checked=previous.context.https_port!=null;
      $("replace-legacy").checked=!editingService&&!!previous.context.replace_legacy_squid;legacyMode();
      if(previous.state==="failed")$("form").elements.namedItem("cleanup_job").value=previous.id;
      modes();message(editingService?'Введите SSH-доступ заново для повторной проверки изменений.':'Введите SSH-доступ заново и сохраните пароль прокси перед установкой.');
    });
    $("check-cancel").addEventListener("click",()=>{changeContext();checkingRequest++;$("check-form").hidden=true;$("check-password").value="";$("remember").checked=false;checking=null;$("form").hidden=true;$("add").hidden=false;$("check-form").querySelector('button[type="submit"],button:not([type])').disabled=false;});
    $("check-form").addEventListener("submit",async event=>{
      event.preventDefault();const version=revision,request=++checkingRequest,button=event.submitter;button.disabled=true;message("");
      const current=()=>version===revision&&request===checkingRequest&&dialog.open;
      try{const value=await api('/api/fleet/proxy/'+encodeURIComponent(checking)+'/check',{method:'POST',timeoutMs:120000,json:{proxy_password:$("check-password").value,remember:$("remember").checked}});if(!current())return;$("check-password").value="";$("remember").checked=false;$("check-form").hidden=true;$("form").hidden=true;await loadServices();if(current()&&!value.passed)message("Подключение с введённым паролем не прошло проверку. Подробности находятся в карточке прокси.");}
      catch(error){if(current())message(error.message);}finally{if(current())button.disabled=false;}
    });
  }
  async function loadServices(){
    const version=revision;
    clearConnections();
    const services=await api('/api/fleet/nodes/'+encodeURIComponent(node.id)+'/proxies');
    if(version!==revision||!dialog.open)return;
    registeredServices=new Map(services.map(service=>[service.id,service]));
    const fragment=document.createDocumentFragment();
    for(const service of services){
      const needsReview=!!service.deployment_state&&service.deployment_state!=='succeeded';
      const card=element("article",null,"card"),title=element("h3",service.domain);card.append(title);
      const status=needsReview?'Установка требует сверки':service.stale?"Требуется сверка привязки к текущей ноде":service.result.passed?"HTTPS-трафик через прокси прошёл":"Последняя проверка завершилась сбоем";
      card.append(element("p",status,needsReview?'small muted':service.stale||!service.result.passed?"small error":"small"));
      if(needsReview&&service.deployment_error)card.append(element('p',service.deployment_error,'small muted'));
      card.append(element("p",(needsReview?'Последняя сохранённая проба · ':'Последняя проба · ')+(service.result.origin||"Источник не указан")+" · "+new Date(service.checked_at*1000).toLocaleString('ru-RU',{timeZone:'UTC'})+" UTC","small muted"));
      const detail=element("details"),summary=element("summary","Результаты проверки");detail.append(summary);
      const stages={proxy_connect:'Соединение с прокси',authorization:'Авторизация',payload:'Передача трафика'};
      for(const check of service.result.checks||[]){
        const failure=check.authorized_status===407?'Пароль отклонён':check.error==='SSLCertVerificationError'?'Проверка TLS-сертификата не пройдена':stages[check.stage]||'Проверка не завершена';
        detail.append(element("p",`${check.mode.toUpperCase()} · ${check.passed?'трафик прошёл':failure} · ${check.latency_ms} мс`,"small"));
      }
      card.append(detail);
      card.append(connectionFields(service,!!service.stale||needsReview));
      const saved=credentialsSaved(service)===true;
      const button=element("button",saved?'Проверить':'Проверить с паролем',"quiet");button.type="button";
      button.disabled=!!service.stale||needsReview;
      button.addEventListener("click",()=>{if(saved)return checkSaved(service,button);clearConnections(false);checkingRequest++;checking=service.id;$("remember").checked=false;$("check-password").value='';$("form").hidden=true;$("check-form").hidden=false;$("check-form").querySelector('button[type="submit"],button:not([type])').disabled=false;$("check-password").focus();});
      const edit=element('button','Изменить прокси','secondary');edit.type='button';edit.disabled=!!service.stale||needsReview||service.edit_allowed===false||credentialsSaved(service)===false;
      edit.addEventListener('click',()=>editService(service));
      const remove=element('button','Удалить прокси','quiet danger');remove.type='button';
      remove.addEventListener('click',()=>window.RimeProxyDelete.open(node,service));
      const actions=element('div',null,'form-grid');actions.append(edit,button,remove);card.append(actions);fragment.append(card);
      if(service.reconcile_allowed){const reconcile=element('button','Сверить по SSH','secondary');reconcile.type='button';reconcile.addEventListener('click',()=>reconcileService(service));actions.append(reconcile);}
    }
    $("services-list").replaceChildren(fragment);
    const pending=window.RimeProxyDelete?.pending(node);
    if(pending){const resume=element('button','Открыть процесс удаления прокси','secondary');resume.type='button';resume.addEventListener('click',()=>window.RimeProxyDelete.resume(node,pending));$('services-list').prepend(resume);}
    $("services-empty").hidden=services.length>0;
    $("services-empty").textContent='В панели пока нет зарегистрированных прокси. Для действующей системной службы выберите перевод существующего Squid.';
    $("add").hidden=services.length===0;
    return services;
  }
  async function preflight(event){
    const version=revision;
    event.preventDefault();invalidateForm();const formEpoch=formVersion;
    const current=()=>version===revision&&formEpoch===formVersion&&dialog.open;
    message("");$("preflight").disabled=true;
    try{
      if(!reconciling&&!$("http-enabled").checked&&!$("https-enabled").checked)throw new Error("Выберите HTTP или HTTPS-прокси.");
      const data=Object.fromEntries(new FormData($("form")));
      for(const name of ["host","username","domain","proxy_username"])data[name]=String(data[name]||'').trim();
      data.ssh_port=Number(data.ssh_port);data.http_port=$("http-enabled").checked?Number($("http-port").value):null;
      data.https_port=$("https-enabled").checked?Number($("https-port").value):null;
      data.replace_legacy_squid=$("replace-legacy").checked;
      if(data.replace_legacy_squid)data.proxy_username='';
      if(!data.replace_service)delete data.replace_service;
      const useKey=$("auth-method").value==='key';
      data.password=useKey?'':data.password||'';data.private_key=useKey?data.private_key||'':'';data.key_passphrase=useKey?data.key_passphrase||'':'';
      if(!data.cleanup_job)delete data.cleanup_job;
      if(useKey&&!data.private_key.trim())throw new Error('Укажите приватный SSH-ключ для входа.');
      if(!useKey&&!data.password)throw new Error('Введите SSH-пароль пользователя сервера.');
      if(!reconciling){
        const options=await api('/api/fleet/proxy/options');
        if(!current())return;
        if(!options.enabled)throw new Error("Образ HTTP/HTTPS-прокси ещё не подготовлен на панели.");
      }
      const scanned=await api('/api/fleet/provision/host-key',{method:'POST',timeoutMs:45000,json:{host:data.host,ssh_port:data.ssh_port}});
      if(!current())return;
      data.address=scanned.address;data.fingerprint=scanned.fingerprint;draft=data;
      $("fingerprint").textContent=scanned.fingerprint;$("trust").checked=false;$("verify").disabled=true;$("fingerprint-card").hidden=false;
      $("form").hidden=true;
      $("fingerprint-card").scrollIntoView({block:'center'});
    }catch(error){if(current())message(error.message);}finally{if(current())$("preflight").disabled=false;}
  }
  async function verify(){
    const version=revision,formEpoch=formVersion,payload=draft;
    if(!payload||!$("trust").checked)return;
    const reconciliation=reconciling?editingService.id:null;
    const current=()=>version===revision&&formEpoch===formVersion&&dialog.open&&draft===payload;
    $("verify").disabled=true;message("");
    try{
      if(reconciliation){
        const data=Object.fromEntries(['host','address','ssh_port','username','password','private_key','key_passphrase','fingerprint'].map(key=>[key,payload[key]]));
        data.proxy_password=$("reconcile-password").value||'';
        const job=await api('/api/fleet/proxy/'+encodeURIComponent(reconciliation)+'/reconcile',{method:'POST',timeoutMs:120000,json:data});
        if(!current())return;
        clearSensitive();currentJob={id:job.id};showJob(job.id);return;
      }
      const value=await api('/api/fleet/proxy/preflight',{method:'POST',timeoutMs:120000,json:payload});
      if(!current())return;
      plan=value;
      const details=element("dl");for(const [key,value]of Object.entries(plan.summary))details.append(element("dt",key,"muted"),element("dd",value));
      const checks=element("ul");for(const check of plan.checks)checks.append(element("li",(check.passed?'✓ ':'! ')+check.message));
      $("plan-details").replaceChildren(details,checks);$("form").hidden=true;$("fingerprint-card").hidden=true;$("plan").hidden=false;$("deploy").disabled=!plan.ready;
      const id=plan.id;clearTimeout(planTimer);planTimer=setTimeout(()=>{if(plan?.id===id){resetForm();message("План истёк. Введите доступ и повторите проверку.");}},Math.max(0,plan.expires_at*1000-Date.now()));
    }catch(error){
      if(!current())return;
      if(reconciliation&&(!error.status||error.status>=500)){clearSensitive();currentJob={id:reconciliation};showJob(reconciliation);}
      else message(error.message);
    }finally{if(current())$("verify").disabled=!$("trust").checked;}
  }
  function showJob(id){
    saveJob(id);$("form").hidden=true;$("plan").hidden=true;$("fingerprint-card").hidden=true;$("job").hidden=false;$("add").disabled=true;poll(id);
  }
  async function deploy(){
    if(!plan?.ready){message('Подготовьте и проверьте план перед применением.');return;}
    const version=revision;$("deploy").disabled=true;const id=plan.id;message("");saveJob(id);
    try{const job=await api('/api/fleet/proxy/deploy',{method:'POST',json:{plan_id:id}});if(version!==revision||!dialog.open)return;clearTimeout(planTimer);plan=null;clearSensitive();currentJob={id:job.id};showJob(job.id);}
    catch(error){if(version!==revision)return;if(error.status&&error.status<500){forgetJob();message(error.message);$("deploy").disabled=false;return;}clearTimeout(planTimer);plan=null;clearSensitive();currentJob={id};showJob(id);}
  }
  async function poll(id,failures=0){
    const version=revision;
    clearTimeout(pollTimer);if(!dialog.open)return;
    try{
      const value=await api('/api/fleet/proxy/jobs/'+encodeURIComponent(id));
      if(version!==revision||!dialog.open)return;
      if(value.node!==node.id){forgetJob();resetForm();return;}
      currentJob=value;$("job-state").textContent=value.message;
      let progress=$('progress');
      if(!progress){progress=element('div');progress.id='proxy-progress';$('job-state').after(progress);}
      window.RimeProgress?.mount(progress).update(window.RimeProgress.job(value));
      $("steps").replaceChildren(...value.steps.map(step=>element("li",step.message)));
      if(['succeeded','failed','rolled_back'].includes(value.state)){$("new").hidden=false;$("retry").hidden=value.state==='succeeded'||!value.context?.host;$("add").disabled=false;await loadServices();}
      else pollTimer=setTimeout(()=>poll(id),1500);
    }catch(error){
      if(version!==revision||!dialog.open)return;
      if(error.name==='UnauthorizedError'||error.name==='SessionChangedError')return;
      message(error.message);if(error.status===404&&failures>=2){forgetJob();$("new").hidden=false;return;}
      pollTimer=setTimeout(()=>poll(id,failures+1),Math.min(10000,1500*(failures+1)));
    }
  }
  async function open(value){
    ensureDialog();revision++;clearSensitive();
    const version=revision;
    clearConnections();registeredServices=new Map();accessMetadata=null;node=value;api=window.Rime.api;resetForm();$("form").hidden=true;$("add").hidden=true;
    $("services-list").replaceChildren();$("services-empty").hidden=false;$("services-empty").textContent='Загрузка сведений…';
    $("title").textContent=value.name+' · HTTP/HTTPS-прокси';if(!dialog.open)dialog.showModal();
    try{const [services,access]=await Promise.all([loadServices(),node.tunnel_access?.active?api('/api/fleet/nodes/'+encodeURIComponent(node.id)+'/proxy-access'):Promise.resolve(null)]);if(version!==revision||!dialog.open)return;accessMetadata=access;if(access)for(const name of ['host','ssh_port','username'])$("form").elements.namedItem(name).value=access[name];$('access-route').textContent=access?.via_entry?'SSH через '+access.entry_name+' к выходной ноде':'Прямой SSH-доступ к ноде';let id;try{id=sessionStorage.getItem(storageKey());}catch{}if(/^[a-f0-9]{32}$/.test(id||''))showJob(id);else $("form").hidden=services.length>0;}
    catch(error){if(version===revision){$("services-empty").textContent='Сведения об установленных прокси не загружены.';message(error.message);}}
  }
  function reset(){
    revision++;
    clearTimeout(pollTimer);clearTimeout(planTimer);draft=null;plan=null;currentJob=null;editingService=null;reconciling=false;registeredServices=new Map();
    if(dialog){clearConnections();clearSensitive();if(dialog.open)dialog.close();}
    try{for(const key of Object.keys(sessionStorage))if(key.startsWith('rime.proxy.job.'))sessionStorage.removeItem(key);}catch{}
  }
  window.RimeProxy={open,reset};
  document.addEventListener('rime:proxy-deleted',event=>{if(dialog?.open&&node?.id===event.detail.node)loadServices();});
})();
