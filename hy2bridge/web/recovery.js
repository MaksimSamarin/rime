"use strict";
(() => {
  const {api,el,stamp}=window.Rime;
  const dialog=el('dialog');dialog.id='recovery-dialog';dialog.setAttribute('aria-labelledby','recovery-title');
  dialog.innerHTML=`<header class="card-heading"><h2 id="recovery-title">Комплект восстановления</h2><button type="button" class="quiet" data-close aria-label="Закрыть">×</button></header>
    <p id="recovery-description" class="muted"></p><div id="recovery-summary" class="recovery-summary" role="status"></div>
    <section class="form-section"><h3>Сохранённый архив</h3><p class="muted">Импортируйте конфигурационный tar.gz старой ноды. Ключи и настройки сохранятся в зашифрованном виде на панели.</p>
      <label>Архив конфигурации<input id="recovery-file" type="file" accept=".tar.gz,.tgz,.tar"></label><button id="recovery-import" type="button" class="secondary" disabled>Импортировать архив</button></section>
    <details class="form-section"><summary>Обновить с доступной исходной ноды</summary><p class="muted">Прямое чтение по SSH. Службы исходного сервера продолжают работать.</p>
      <form id="recovery-capture"><div class="form-grid"><label>SSH-адрес<input name="host" required></label><label>SSH-порт<input name="ssh_port" type="number" min="1" max="65535" value="22" required></label>
      <label>Пользователь<input name="username" value="root" required></label><label>Способ входа<select id="recovery-auth"><option value="password">Пароль</option><option value="key">SSH-ключ</option></select></label>
      <label id="recovery-password-label" class="wide">SSH-пароль<input name="password" type="password" autocomplete="off" required></label>
      <label id="recovery-key-label" class="wide" hidden>Приватный SSH-ключ<textarea name="private_key" rows="4" autocomplete="off" spellcheck="false" disabled></textarea></label>
      <label id="recovery-passphrase-label" class="wide" hidden>Пароль ключа<input name="key_passphrase" type="password" autocomplete="off" disabled></label></div>
      <button id="recovery-scan" type="submit" class="secondary">Проверить SSH-ключ</button></form>
      <div id="recovery-fingerprint" class="recovery-fingerprint" hidden><code id="recovery-key-value"></code><label class="check"><input id="recovery-trust" type="checkbox"> Отпечаток проверен</label><button id="recovery-read" class="primary" type="button" disabled>Сохранить конфигурацию ноды</button></div></details>
    <p id="recovery-error" class="error" role="alert"></p><div class="form-actions"><button class="quiet" type="button" data-close>Закрыть</button><button id="recovery-transfer" class="primary" type="button" disabled>Перейти к переносу</button></div>`;
  document.body.append(dialog);
  const $=id=>document.getElementById('recovery-'+id);
  let current=null,epoch=0,draft=null,revision=0;
  function syncAuth(){
    const key=$('auth').value==='key',form=$('capture');
    for(const [name,visible] of [['password',!key],['private_key',key],['key_passphrase',key]]){
      const field=form.elements.namedItem(name);field.disabled=!visible;field.value='';field.required=visible&&name!=='key_passphrase';
    }
    $('password-label').hidden=key;$('key-label').hidden=!key;$('passphrase-label').hidden=!key;
  }
  function invalidate(){revision++;draft=null;$('fingerprint').hidden=true;$('trust').checked=false;$('read').disabled=true;}
  async function refresh(){
    const ticket=epoch,node=current;
    const value=await api('/api/fleet/nodes/'+encodeURIComponent(node.id)+'/recovery');
    if(ticket!==epoch||!dialog.open)return;
    const missing=value.missing_inbounds||[];
    $('summary').replaceChildren(el('strong',value.available?'Комплект готов к проверке переноса':'Комплект требует дополнения'),
      el('p',(value.protocol==='vless'?'VLESS':value.protocol==='hysteria2'?'Hysteria2':'VPN не сохранён')+' · прокси '+value.proxies+' · '+stamp(value.updated_at),'muted'));
    if(missing.length)$('summary').append(el('p','Не хватает входов '+missing.join(', '),'error'));
    if(value.missing_proxies?.length)$('summary').append(el('p','Не хватает конфигураций прокси · '+value.missing_proxies.length,'error'));
    $('transfer').disabled=!value.available;
  }
  async function open(node){
    reset();current=node;epoch++;$('title').textContent='Восстановление · '+node.name;
    $('description').textContent='Готовый комплект хранится на панели: старый VPS для переноса не нужен. Новые установки VPN и прокси сохраняются автоматически. Для прежних установок дополните комплект сейчас, пока сервер доступен, либо импортируйте его архив.';
    $('capture').elements.namedItem('host').value=node.address||'';
    dialog.showModal();$('summary').textContent='Загрузка комплекта…';
    const ticket=epoch;
    try{await refresh();}catch(error){if(ticket===epoch)$('error').textContent=error.message;}
  }
  function reset(){epoch++;current=null;draft=null;if(dialog.open)dialog.close();$('capture').reset();syncAuth();invalidate();$('file').value='';$('import').disabled=true;$('scan').disabled=false;$('transfer').disabled=true;$('error').textContent='';$('key-value').textContent='';}
  dialog.addEventListener('close',()=>{epoch++;current=null;draft=null;for(const field of $('capture').querySelectorAll('input[type=password],textarea'))field.value='';});
  dialog.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>dialog.close()));
  $('capture').addEventListener('input',invalidate);$('auth').addEventListener('change',syncAuth);
  $('file').addEventListener('change',()=>{$('import').disabled=!$('file').files.length;});
  $('import').addEventListener('click',async()=>{
    const file=$('file').files[0];if(!file||!current)return;
    if(file.size>64*1024*1024){$('error').textContent='Архив должен быть меньше 64 MiB';return;}
    const ticket=epoch,node=current;$('import').disabled=true;$('error').textContent='Импорт конфигурации…';
    try{await api('/api/fleet/nodes/'+encodeURIComponent(node.id)+'/recovery/import',{method:'POST',body:file,timeoutMs:120000});if(ticket===epoch){$('error').textContent='';await refresh();}}
    catch(error){if(ticket===epoch)$('error').textContent=error.message;}
    finally{if(ticket===epoch)$('import').disabled=false;}
  });
  $('capture').addEventListener('submit',async event=>{
    event.preventDefault();invalidate();const ticket=epoch,version=revision;
    const data=Object.fromEntries(new FormData($('capture')));data.ssh_port=Number(data.ssh_port);
    $('scan').disabled=true;$('error').textContent='';
    try{const scan=await api('/api/fleet/provision/host-key',{method:'POST',json:{host:data.host.trim(),ssh_port:data.ssh_port},timeoutMs:45000});
      if(ticket!==epoch||version!==revision)return;draft={...data,...scan};$('key-value').textContent=scan.fingerprint;$('fingerprint').hidden=false;
    }catch(error){if(ticket===epoch&&version===revision)$('error').textContent=error.message;}
    finally{if(ticket===epoch)$('scan').disabled=false;}
  });
  $('trust').addEventListener('change',()=>{$('read').disabled=!$('trust').checked||!draft;});
  $('read').addEventListener('click',async()=>{
    if(!draft||!current||!$('trust').checked)return;
    const ticket=epoch,node=current,data=draft;$('read').disabled=true;$('error').textContent='Чтение конфигурации…';
    try{await api('/api/fleet/nodes/'+encodeURIComponent(node.id)+'/recovery/capture',{method:'POST',json:data,timeoutMs:180000});
      if(ticket===epoch){$('error').textContent='';invalidate();$('capture').reset();syncAuth();await refresh();}
    }catch(error){if(ticket===epoch)$('error').textContent=error.message;}
    finally{if(ticket===epoch)$('read').disabled=!draft||!$('trust').checked;}
  });
  $('transfer').addEventListener('click',async()=>{const node=current;dialog.close();try{await window.Rime.prepareTransfer(node.id);}catch(error){window.Rime.showError(error.message);}});
  window.RimeRecovery={open,reset};
})();
