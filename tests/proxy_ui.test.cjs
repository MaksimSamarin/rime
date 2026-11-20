const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');

function setup({services=[],respond}={}) {
  const ids=new Map(),fields=new Map(),created=[],calls=[],copies=[];
  let dialog;
  class Element {
    constructor(tag='div') { this.tag=tag;this.value='';this.hidden=false;this.disabled=false;this.required=false;this.checked=false;this.open=false;this.textContent='';this.listeners={};this.children=[]; }
    set innerHTML(html) {
      for(const match of html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*)>/g)) {
        const attrs=match[2],id=attrs.match(/\bid="([^"]+)"/)?.[1],name=attrs.match(/\bname="([^"]+)"/)?.[1];
        if(!id&&!name)continue;
        const item=new Element(match[1]);item.value=attrs.match(/\bvalue="([^"]*)"/)?.[1]||'';
        item.defaultValue=item.value;item.hidden=/\bhidden\b/.test(attrs);item.disabled=/\bdisabled\b/.test(attrs);item.checked=/\bchecked\b/.test(attrs);item.defaultChecked=item.checked;
        if(id)ids.set(id,item);if(name)fields.set(name,item);
      }
      get('form').elements={namedItem:name=>fields.get(name)};
      get('form').reset=()=>{
        for(const item of fields.values())item.value=item.defaultValue;
        for(const item of ids.values())item.checked=item.defaultChecked;
        get('auth-method').value='password';
      };
    }
    addEventListener(type,callback) { (this.listeners[type]||=[]).push(callback); }
    async fire(type,event={}) { for(const callback of this.listeners[type]||[])await callback({preventDefault(){},submitter:this,currentTarget:this,...event}); }
    click() { return this.fire('click'); }
    querySelector(selector) { return selector.startsWith('#')?ids.get(selector.slice(1)):get('check-submit'); }
    setAttribute() {}
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children=items; }
    showModal() { this.open=true; }
    close() { this.open=false;this.fire('close'); }
    scrollIntoView() {}
    focus() {}
  }
  const get=name=>{const id='proxy-'+name;if(!ids.has(id))ids.set(id,new Element());return ids.get(id);};
  const storage={};
  Object.defineProperties(storage,{
    getItem:{value:key=>storage[key]||null},setItem:{value:(key,value)=>storage[key]=value},removeItem:{value:key=>delete storage[key]}
  });
  const api=async(url,options={})=>{
    calls.push({url,json:options.json?JSON.parse(JSON.stringify(options.json)):null});
    if(respond){const value=respond(url,options);if(value!==undefined)return value;}
    if(url.endsWith('/proxies'))return services;
    if(url.endsWith('/options'))return {enabled:true};
    if(url.endsWith('/host-key'))return {fingerprint:'SHA256:synthetic',address:'192.0.2.1'};
    if(url.endsWith('/preflight'))return {id:'a'.repeat(32),ready:true,expires_at:Date.now()/1000+300,summary:{},checks:[]};
    if(url.endsWith('/deploy'))return {id:'a'.repeat(32)};
    throw new Error('Unexpected synthetic request');
  };
  const documentEvents={};
  const document={body:{append(){}},createElement:tag=>{const item=new Element(tag);created.push(item);if(tag==='dialog')dialog=item;return item;},createDocumentFragment:()=>new Element(),
    addEventListener(type,callback){(documentEvents[type]||=[]).push(callback);}};
  const window={Rime:{api}};
  class FormData {
    constructor() { this.values=[...fields].filter(([,item])=>!item.disabled).map(([name,item])=>[name,item.value]); }
    [Symbol.iterator]() { return this.values[Symbol.iterator](); }
  }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web/proxy.js'),'utf8'),{
    window,document,FormData,crypto:webcrypto,btoa:text=>Buffer.from(text,'binary').toString('base64'),
    navigator:{clipboard:{writeText:async text=>copies.push(text)}},sessionStorage:storage,setTimeout:()=>1,clearTimeout(){},
  });
  const node={id:'synthetic-node',name:'Synthetic node',protocol:'hysteria2',address:'192.0.2.1',settings:{domain:'node.example.invalid'}};
  return {get,fields,created,calls,copies,window,node,storage,
    open:value=>window.RimeProxy.open(value||node),
    mode:async value=>{get('auth-method').value=value;await get('auth-method').fire('change');},
    legacy:async enabled=>{get('replace-legacy').checked=enabled;await get('replace-legacy').fire('change');},
    scan:()=>get('form').fire('submit',{submitter:get('preflight')}),
    verify:async()=>{get('trust').checked=true;await get('trust').fire('change');await get('verify').fire('click');},
    close:()=>dialog.close(),
  };
}

function credentials(h) {
  h.fields.get('password').value='synthetic-ssh';
  h.fields.get('proxy_username').value='new_proxy';
  h.get('proxy-password').value='Synthetic-proxy-password';
}

test('new proxy form uses password auth and protocol-aware ports without a saved account',async()=>{
  const h=setup();await h.open();
  assert.equal(h.get('password-fields').hidden,false);assert.equal(h.fields.get('private_key').disabled,true);
  assert.equal(h.get('https-port').value,'443');assert.equal(h.fields.get('proxy_username').value,'');assert.equal(h.get('proxy-password').value,'');
  await h.open({...h.node,id:'vless-node',protocol:'xray'});assert.equal(h.get('https-port').value,'8443');
});

test('registered proxy configuration is displayed before the collapsed new form',async()=>{
  const service={id:'existing',domain:'node.example.invalid',username:'current_user',http_port:3128,https_port:443,checked_at:1,result:{passed:true,checks:[]}};
  const h=setup({services:[service]});await h.open();
  assert.equal(h.get('form').hidden,true);assert.equal(h.get('add').hidden,false);
  assert.ok(h.created.some(item=>item.tag==='input'&&item.readOnly&&item.value==='https://current_user:••••••••@node.example.invalid:443'));
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
  const check=h.created.find(item=>item.tag==='button'&&item.textContent==='Проверить с паролем');
  await check.fire('click');await h.get('check-cancel').fire('click');assert.equal(h.get('form').hidden,true);
  await h.get('add').fire('click');assert.equal(h.get('form').hidden,false);assert.equal(h.fields.get('proxy_username').value,'');assert.equal(h.get('add').hidden,true);
});

test('an unfinished durable deployment cannot claim the previous successful probe is current readiness',async()=>{
  const service={id:'pending',domain:'node.example.invalid',username:'current_user',http_port:3128,https_port:443,checked_at:1,deployment_state:'running',result:{passed:true,checks:[]}};
  const h=setup({services:[service]});await h.open();
  assert.ok(h.created.some(item=>item.textContent==='Установка требует сверки'));
  assert.equal(h.created.some(item=>item.textContent==='HTTPS-трафик через прокси прошёл'),false);
  assert.ok(h.created.some(item=>item.textContent.startsWith('Последняя сохранённая проба · ')));
  assert.equal(h.created.find(item=>item.tag==='button'&&item.textContent==='Проверить с паролем').disabled,true);
});

test('SSH method switches clear inactive credentials and preserve proxy and TLS passwords',async()=>{
  const h=setup();await h.open();credentials(h);h.fields.get('certificate_key').value='synthetic-tls-key';
  await h.mode('key');assert.equal(h.fields.get('password').value,'');assert.equal(h.fields.get('password').disabled,true);
  h.fields.get('private_key').value='synthetic-private-key';h.fields.get('key_passphrase').value='synthetic-passphrase';
  await h.mode('password');assert.equal(h.fields.get('private_key').value,'');assert.equal(h.fields.get('key_passphrase').value,'');
  assert.equal(h.get('proxy-password').value,'Synthetic-proxy-password');assert.equal(h.fields.get('certificate_key').value,'synthetic-tls-key');
});

test('new proxy payload carries empty inactive SSH fields and an explicit false legacy flag',async()=>{
  const h=setup();await h.open();credentials(h);await h.scan();
  await h.get('verify').fire('click');assert.equal(h.calls.some(call=>call.url.endsWith('/preflight')),false);
  await h.verify();const data=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(data.replace_legacy_squid,false);assert.equal(data.password,'synthetic-ssh');assert.equal(data.private_key,'');assert.equal(data.key_passphrase,'');
  assert.equal(data.https_port,443);assert.equal(data.proxy_username,'new_proxy');
});

test('legacy mode preserves current access instead of generating a new account',async()=>{
  const h=setup();await h.open();credentials(h);await h.legacy(true);
  assert.equal(h.get('proxy-password').value,'');assert.equal(h.get('proxy-password').minLength,1);
  assert.equal(h.fields.get('proxy_username').disabled,true);assert.equal(h.get('http-port').value,'3128');assert.equal(h.get('https-port').value,'443');
  assert.equal(h.get('http-port').disabled,true);assert.equal(h.get('https-port').disabled,true);assert.equal(h.get('generate').hidden,true);
  h.get('proxy-password').value='short';await h.get('generate').fire('click');
  assert.equal(h.get('proxy-password').value,'short');assert.equal(h.copies.length,0);
  await h.scan();await h.verify();const data=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(data.replace_legacy_squid,true);assert.equal(data.proxy_username,'');assert.equal(data.proxy_password,'short');
  await h.legacy(false);assert.equal(h.get('proxy-password').value,'');assert.equal(h.fields.get('proxy_username').disabled,false);assert.equal(h.get('proxy-password').minLength,12);
});

test('changing SSH auth invalidates a pending scan without restoring its fingerprint',async()=>{
  let finish;
  const h=setup({respond:url=>url.endsWith('/host-key')?new Promise(resolve=>{finish=resolve;}):undefined});await h.open();credentials(h);
  const pending=h.scan();await new Promise(resolve=>setImmediate(resolve));await h.mode('key');
  finish({fingerprint:'SHA256:old',address:'192.0.2.1'});await pending;
  assert.equal(h.get('fingerprint-card').hidden,true);assert.equal(h.get('fingerprint').textContent,'');assert.equal(h.get('verify').disabled,true);
});

test('a late legacy preflight cannot replace a newly selected new-install mode',async()=>{
  let finish;
  const h=setup({respond:url=>url.endsWith('/preflight')?new Promise(resolve=>{finish=resolve;}):undefined});await h.open();credentials(h);await h.legacy(true);h.get('proxy-password').value='short';
  await h.scan();const pending=h.verify();await new Promise(resolve=>setImmediate(resolve));await h.legacy(false);
  finish({id:'old',ready:true,summary:{},checks:[]});await pending;assert.equal(h.get('plan').hidden,true);assert.equal(h.get('deploy').disabled,true);
});

test('closing the dialog discards a late services response and clears credentials',async()=>{
  let finish;
  const h=setup({respond:url=>url.endsWith('/proxies')?new Promise(resolve=>{finish=resolve;}):undefined});
  const pending=h.open();h.fields.get('password').value='synthetic-ssh';h.close();finish([]);await pending;
  assert.equal(h.fields.get('password').value,'');assert.equal(h.get('form').hidden,true);
});

test('retry context restores legacy mode while requiring credentials again',async()=>{
  const h=setup({respond:url=>url.includes('/proxy/jobs/')?{id:'a'.repeat(32),node:'synthetic-node',state:'failed',message:'Synthetic retry',steps:[],context:{host:'192.0.2.1',domain:'node.example.invalid',http_port:3128,https_port:443,replace_legacy_squid:true}}:undefined});
  await h.open();credentials(h);await h.legacy(true);h.get('proxy-password').value='short';await h.scan();await h.verify();
  await h.get('deploy').fire('click');await new Promise(resolve=>setImmediate(resolve));await h.get('retry').fire('click');
  assert.equal(h.get('replace-legacy').checked,true);assert.equal(h.get('proxy-password').value,'');assert.equal(h.fields.get('password').value,'');assert.equal(h.get('https-port').value,443);
});

function registeredService(overrides={}) {
  return {id:'current',node:'synthetic-node',domain:'node.example.invalid',username:'current_user',http_port:3128,https_port:443,
    checked_at:1,deployment_state:'succeeded',credentials_available:true,edit_allowed:true,locked_domain:true,result:{passed:true,checks:[]},...overrides};
}
function connectionData() {
  return {id:'current',node:'synthetic-node',credentials_available:true,needs_password:false,password:'current@secret',
    urls:{http:'http://current_user:current%40secret@node.example.invalid:3128',https:'https://current_user:current%40secret@node.example.invalid:443'}};
}
const currentInputs=h=>h.created.filter(item=>item.tag==='input'&&item.readOnly);
const action=(h,text)=>h.created.find(item=>item.tag==='button'&&item.textContent===text);

test('copy retrieves the protected current URL only after an explicit click',async()=>{
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?connectionData():undefined});await h.open();
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
  assert.ok(currentInputs(h).every(input=>!input.value.includes('current%40secret')));
  await action(h,'Копировать HTTPS').fire('click');
  assert.equal(h.calls.filter(call=>call.url.endsWith('/connection')).length,1);
  assert.equal(h.copies[0],connectionData().urls.https);
  assert.ok(currentInputs(h).every(input=>!input.value.includes('current%40secret')));
  assert.equal(Object.values(h.storage).some(value=>String(value).includes('secret')),false);
});

test('revealed URLs can be masked again and are erased when the dialog closes',async()=>{
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?connectionData():undefined});await h.open();
  const show=action(h,'Показать пароль');await show.fire('click');
  assert.ok(currentInputs(h).every(input=>input.value.includes('current%40secret')));
  await show.fire('click');assert.ok(currentInputs(h).every(input=>input.value.includes('••••••••')));
  assert.equal(h.calls.filter(call=>call.url.endsWith('/connection')).length,1);
  await show.fire('click');h.close();assert.ok(currentInputs(h).every(input=>input.value===''));
});

test('a delayed credential response after close cannot write to clipboard or restore secret fields',async()=>{
  let finish;
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?new Promise(resolve=>{finish=resolve;}):undefined});await h.open();
  const pending=action(h,'Копировать HTTP').fire('click');h.close();finish(connectionData());await pending;
  assert.equal(h.copies.length,0);assert.ok(currentInputs(h).every(input=>input.value===''));
});

test('session reset clears revealed access and discards a pending protected response',async()=>{
  let finish;
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?new Promise(resolve=>{finish=resolve;}):undefined});await h.open();
  const pending=action(h,'Показать пароль').fire('click');h.window.RimeProxy.reset();finish(connectionData());await pending;
  assert.equal(h.copies.length,0);assert.ok(currentInputs(h).every(input=>input.value===''));assert.deepEqual(Object.keys(h.storage),[]);
});

test('editing prefills current metadata and keeps its password through an empty replacement input',async()=>{
  const h=setup({services:[registeredService()]});await h.open();await action(h,'Изменить прокси').fire('click');
  assert.equal(h.fields.get('username').value,'root');assert.equal(h.fields.get('proxy_username').value,'current_user');
  assert.equal(h.fields.get('replace_service').value,'current');assert.equal(h.get('https-port').value,443);assert.equal(h.get('domain').readOnly,true);
  assert.equal(h.get('proxy-password').value,'');assert.equal(h.get('proxy-password').required,false);
  h.fields.get('password').value='synthetic-ssh';h.fields.get('proxy_username').value='changed_user';h.get('http-enabled').checked=false;await h.get('http-enabled').fire('change');h.get('https-port').value='9443';
  await h.scan();await h.verify();const data=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(data.replace_service,'current');assert.equal(data.proxy_password,'');assert.equal(data.proxy_username,'changed_user');
  assert.equal(data.http_port,null);assert.equal(data.https_port,9443);assert.equal(data.replace_legacy_squid,false);
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
  assert.equal(h.get('deploy').disabled,false);
});

test('opening a new form after edit removes its replacement target and pending copy',async()=>{
  let finish;
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?new Promise(resolve=>{finish=resolve;}):undefined});await h.open();
  const copy=action(h,'Копировать HTTP'),pending=copy.fire('click');
  await h.get('add').fire('click');finish(connectionData());await pending;
  assert.equal(h.copies.length,0);assert.equal(copy.disabled,false);
  await action(h,'Изменить прокси').fire('click');await h.get('edit-cancel').fire('click');await h.get('add').fire('click');
  assert.equal(h.fields.get('replace_service').value,'');assert.equal(h.fields.get('proxy_username').value,'');assert.equal(h.get('proxy-password').required,true);
});

test('password remembering is explicit and an unsuccessful check never sends stored access implicitly',async()=>{
  const service=registeredService({credentials_available:false,edit_allowed:false});
  const h=setup({services:[service],respond:url=>url.endsWith('/check')?{passed:false}:undefined});await h.open();
  assert.equal(action(h,'Изменить прокси').disabled,true);assert.equal(action(h,'Копировать HTTP').disabled,true);
  await action(h,'Проверить с паролем').fire('click');assert.equal(h.get('remember').checked,false);
  h.get('check-password').value='short';h.get('remember').checked=true;await h.get('check-form').fire('submit');
  const data=h.calls.find(call=>call.url.endsWith('/check')).json;assert.equal(data.remember,true);assert.equal(data.proxy_password,'short');
  assert.equal(h.get('check-password').value,'');assert.equal(h.get('remember').checked,false);
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
});

test('current vault URLs are never exposed for an unfinished deployment',async()=>{
  const h=setup({services:[registeredService({deployment_state:'running'})]});await h.open();
  assert.equal(action(h,'Копировать HTTP').disabled,true);assert.equal(action(h,'Показать пароль').disabled,true);assert.equal(action(h,'Изменить прокси').disabled,true);
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
});

test('a saved-password probe asks the server to decrypt without retrieving secrets into the UI',async()=>{
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/check')?{passed:true}:undefined});await h.open();
  await action(h,'Проверить').fire('click');
  const request=h.calls.find(call=>call.url.endsWith('/check'));
  assert.equal(request.json.proxy_password,'');assert.equal(request.json.remember,false);
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
  assert.equal(h.get('check-form').hidden,true);assert.ok(currentInputs(h).every(input=>!input.value.includes('current%40secret')));
});

test('a protected response that became pending cannot disclose a formerly ready connection',async()=>{
  const h=setup({services:[registeredService()],respond:url=>url.endsWith('/connection')?{...connectionData(),deployment_state:'running'}:undefined});await h.open();
  await action(h,'Копировать HTTPS').fire('click');
  assert.equal(h.copies.length,0);assert.ok(currentInputs(h).every(input=>input.value.includes('••••••••')));
  assert.ok(h.created.some(item=>item.textContent==='Установка требует сверки. Дождитесь завершения задачи.'));
});

test('a remembered successful password unlocks current access without prefetching plaintext',async()=>{
  const service=registeredService({credentials_available:false,edit_allowed:false});
  const h=setup({services:[service],respond:url=>{if(url.endsWith('/check')){service.credentials_available=true;service.edit_allowed=true;return {passed:true};}}});await h.open();
  await action(h,'Проверить с паролем').fire('click');h.get('check-password').value='short';h.get('remember').checked=true;
  await h.get('check-form').fire('submit');
  assert.equal(h.created.filter(item=>item.tag==='button'&&item.textContent==='Копировать HTTP').at(-1).disabled,false);
  assert.equal(h.created.filter(item=>item.tag==='button'&&item.textContent==='Изменить прокси').at(-1).disabled,false);
  assert.equal(h.calls.some(call=>call.url.endsWith('/connection')),false);
});

test('retrying a failed edit preserves the replacement identity and requests fresh SSH credentials',async()=>{
  const h=setup({services:[registeredService()],respond:url=>url.includes('/proxy/jobs/')?{
    id:'a'.repeat(32),node:'synthetic-node',state:'failed',message:'Synthetic edit retry',steps:[],
    context:{host:'192.0.2.1',domain:'node.example.invalid',proxy_username:'changed_user',http_port:null,https_port:9443,replace_service:'current'}
  }:undefined});await h.open();await action(h,'Изменить прокси').fire('click');
  h.fields.get('password').value='synthetic-ssh';await h.scan();await h.verify();await h.get('deploy').fire('click');
  await new Promise(resolve=>setImmediate(resolve));await h.get('retry').fire('click');
  assert.equal(h.fields.get('replace_service').value,'current');assert.equal(h.fields.get('proxy_username').value,'changed_user');
  assert.equal(h.get('https-port').value,9443);assert.equal(h.get('http-enabled').checked,false);
  assert.equal(h.fields.get('password').value,'');assert.equal(h.get('proxy-password').value,'');assert.equal(h.get('proxy-password').required,false);
});

test('eligible pending installation can be reconciled only after a new pinned SSH scan',async()=>{
  const service=registeredService({deployment_state:'failed',reconcile_allowed:true});
  const h=setup({services:[service],respond:url=>url.endsWith('/reconcile')?{id:'current'}:url.includes('/proxy/jobs/')?{id:'current',node:'synthetic-node',state:'succeeded',message:'Synthetic reconciliation',steps:[],context:{}}:undefined});await h.open();
  await action(h,'Сверить по SSH').fire('click');
  assert.equal(h.get('access-fields').hidden,true);assert.equal(h.fields.get('domain').disabled,true);assert.equal(h.fields.get('proxy_username').disabled,true);assert.equal(h.get('reconcile-fields').hidden,false);
  h.fields.get('password').value='synthetic-ssh';await h.scan();await h.get('verify').fire('click');
  assert.equal(h.calls.some(call=>call.url.endsWith('/reconcile')),false);
  await h.verify();const data=h.calls.find(call=>call.url.endsWith('/reconcile')).json;
  assert.deepEqual(Object.keys(data).sort(),['address','fingerprint','host','key_passphrase','password','private_key','proxy_password','ssh_port','username'].sort());
  assert.equal(data.password,'synthetic-ssh');assert.equal(data.fingerprint,'SHA256:synthetic');assert.equal(data.proxy_password,'');
  assert.equal(h.calls.some(call=>call.url.endsWith('/preflight')||call.url.endsWith('/deploy')||call.url.endsWith('/connection')),false);
});

test('reconciliation accepts an explicit current password and cancellation restores a normal new form',async()=>{
  const h=setup({services:[registeredService({deployment_state:'failed',credentials_available:false,reconcile_allowed:true})],respond:url=>url.endsWith('/reconcile')?{id:'current'}:url.includes('/proxy/jobs/')?{id:'current',node:'synthetic-node',state:'failed',message:'Synthetic state',steps:[],context:{}}:undefined});await h.open();
  await action(h,'Сверить по SSH').fire('click');h.fields.get('password').value='synthetic-ssh';h.get('reconcile-password').value='short';await h.scan();await h.verify();
  assert.equal(h.calls.find(call=>call.url.endsWith('/reconcile')).json.proxy_password,'short');
  await h.get('edit-cancel').fire('click');await h.get('add').fire('click');
  assert.equal(h.get('access-fields').hidden,false);assert.equal(h.fields.get('domain').disabled,false);assert.equal(h.get('reconcile-fields').hidden,true);assert.equal(h.get('reconcile-password').value,'');
});

test('an uncertain reconciliation response resumes the existing job without a second deploy',async()=>{
  const h=setup({services:[registeredService({deployment_state:'failed',reconcile_allowed:true})],respond:url=>{if(url.endsWith('/reconcile'))throw new Error('Synthetic network failure');if(url.includes('/proxy/jobs/'))return {id:'current',node:'synthetic-node',state:'running',message:'Synthetic pending',steps:[],context:{}};}});await h.open();
  await action(h,'Сверить по SSH').fire('click');h.fields.get('password').value='synthetic-ssh';await h.scan();await h.verify();
  assert.ok(h.calls.some(call=>call.url.endsWith('/jobs/current')));assert.equal(h.calls.some(call=>call.url.endsWith('/deploy')),false);
  assert.equal(h.fields.get('password').value,'');assert.equal(h.get('reconcile-password').value,'');
});
