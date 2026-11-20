const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const OLD = 'a'.repeat(32), NEW = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const ROUTE = 'd'.repeat(32), JOB = 'e'.repeat(32);
const copy = value => JSON.parse(JSON.stringify(value));
const settle = () => new Promise(resolve => setImmediate(resolve));

function setup(options = {}) {
  const ids = new Map(), calls = [], timers = new Map(), stored = new Map(options.saved ? [['rime.relay.job',JOB]] : []);
  let timerId = 0;
  class Element {
    constructor(tag = 'div', text, className = '') {
      this.tagName = tag.toUpperCase(); this.textContent = text || ''; this.className = className;
      this.children = []; this.listeners = {}; this.dataset = {}; this.attributes = {};
      this.open = false; this.hidden = false; this.disabled = false; this.checked = false;
      this.classList = {add: name => {this.className += ' ' + name;}};
    }
    set value(value) {this.inputValue = String(value);}
    get value() {return this.inputValue || (this.tagName === 'SELECT' ? this.children[0]?.value || '' : '');}
    get elements() {
      const fields = Object.fromEntries(this.querySelectorAll('[name]').map(item => [item.name,item]));
      fields.namedItem = name => fields[name]; return fields;
    }
    setAttribute(name, value) {
      this.attributes[name] = String(value);
      if (name === 'id') {this.id = value; ids.set(value,this);}
      else if (name === 'name') this.name = value;
      else if (name === 'class') this.className = value;
      else if (['disabled','hidden','checked'].includes(name)) this[name] = true;
      else if (name === 'value') this.value = value;
      else this[name] = value;
    }
    removeAttribute(name) {delete this.attributes[name]; if (['disabled','hidden'].includes(name)) this[name] = false;}
    getAttribute(name) {return this.attributes[name];}
    append(...items) {
      for (const item of items) {item.parentElement = this; this.children.push(item);}
    }
    forget() {for (const child of this.children) child.forget(); if (this.id) ids.delete(this.id);}
    replaceChildren(...items) {for (const child of this.children) child.forget(); this.children = []; this.append(...items);}
    set innerHTML(html) {
      this.replaceChildren(); const stack = [this];
      for (const match of html.matchAll(/<\/?[a-z][^>]*>|[^<]+/gi)) {
        const token = match[0];
        if (token.startsWith('</')) {stack.pop(); continue;}
        if (!token.startsWith('<')) {stack.at(-1).append(new Element('#text',token)); continue;}
        const tag = token.match(/^<([a-z][a-z0-9]*)/i)[1], item = new Element(tag);
        const attrs = token.slice(tag.length + 1,-1);
        for (const attr of attrs.matchAll(/([a-z][a-z0-9_-]*)(?:="([^"]*)")?/gi)) item.setAttribute(attr[1],attr[2] || '');
        stack.at(-1).append(item);
        if (!['input','br','hr','img'].includes(tag)) stack.push(item);
      }
    }
    addEventListener(type, callback) {(this.listeners[type] ||= []).push(callback);}
    async fire(type) {
      if (type === 'click' && this.disabled) return;
      for (const callback of this.listeners[type] || []) await callback({preventDefault(){}});
    }
    querySelectorAll(selector) {
      const matches = item => selector === '[name]' ? Boolean(item.name) : selector.startsWith('.') ?
        item.className.split(/\s+/).includes(selector.slice(1)) : item.tagName.toLowerCase() === selector;
      const result = [];
      for (const child of this.children) {if (matches(child)) result.push(child); result.push(...child.querySelectorAll(selector));}
      return result;
    }
    querySelector(selector) {return this.querySelectorAll(selector)[0] || null;}
    showModal() {this.open = true;}
    close() {this.open = false; this.fire('close');}
    focus() {}
    scrollIntoView() {}
  }
  const body = new Element('body');
  for (const name of ['error','add-entry','add-route','entry-list','route-list']) {
    const item = new Element(name.startsWith('add-') ? 'button' : 'div'); item.setAttribute('id','relay-' + name); body.append(item);
  }
  const now = Date.now() / 1000;
  const catalog = {runtime_available:true,entries:[
    {id:OLD,name:'Old entry',domain:'old.example',state:'active',fresh:options.oldFresh ?? false,health:{}},
    ...(options.noAlternative ? [] : [{id:NEW,name:'New entry',domain:'new.example',state:'active',fresh:true,health:{}}]),
    {id:OTHER,name:'Other entry',domain:'other.example',state:'active',fresh:Boolean(options.otherFresh),health:{}}
  ],tunnels:[{id:ROUTE,node:'node-a',entry:OLD,entry_name:'Old entry',entry_domain:'old.example',origin:'192.0.2.20',
    state:'active',checked_at:now,result:{passed:true},old_cleanup_pending:Boolean(options.cleanupPending),
    services:[{kind:'vpn',state:'active',origin_port:443,public_port:10443,protocol:'tcp',traffic:{rx:100,tx:50}}]}]};
  let job = {id:JOB,state:'running',message:'Проверка нового входа',steps:['Проверка нового входа'],
    context:{operation:'route-switch',progress:{completed:2,total:7,phase:'verify',label:'Проверка нового входа'}}};
  const plan = {id:JOB,kind:'route-switch',message:'Новый вход проверяется перед переключением',
    from_entry:{id:OLD,name:'Old entry',domain:'old.example'},to_entry:{id:NEW,name:'New entry',domain:'new.example'},
    services:[{kind:'vpn',public_port:10443,origin_port:443,protocol:'tcp'}]};
  const api = async (url, settings = {}) => {
    calls.push({url,settings:copy(settings)});
    const custom = options.respond?.(url,settings);
    if (custom !== undefined) return custom;
    if (url === '/api/fleet/relays') return copy(catalog);
    if (url.endsWith('/switch/plan')) return copy(plan);
    if (url.endsWith('/deploy')) return {id:JOB};
    if (url.includes('/jobs/')) return copy(job);
    throw new Error('Unexpected test endpoint ' + url);
  };
  const window = {Rime:{api,el:(...args) => new Element(...args),bytes:String,stamp:String,
    table:(target,head,rows) => {target.rows = rows;},state:{token:'synthetic',overview:{nodes:[{id:'node-a',name:'Synthetic exit',role:'exit'}]}}}};
  const document = {body,createElement:tag => new Element(tag),createTextNode:text => new Element('#text',text),getElementById:id => ids.get(id)};
  class FormData {
    constructor(form) {this.values = form.querySelectorAll('[name]').filter(field => !field.disabled && (field.type !== 'checkbox' || field.checked)).map(field => [field.name,field.value]);}
    [Symbol.iterator]() {return this.values[Symbol.iterator]();}
  }
  const context = {window,globalThis:window,document,FormData,location:{hash:'#relays'},Date,
    sessionStorage:{getItem:key => stored.get(key) || null,setItem:(key,value) => stored.set(key,value),removeItem:key => stored.delete(key)},
    setTimeout:(callback,delay) => {timers.set(++timerId,{callback,delay}); return timerId;},clearTimeout:id => timers.delete(id),addEventListener(){}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web/progress.js'),'utf8'),context);
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web/relays.js'),'utf8'),context);
  const get = name => ids.get('relay-' + name);
  const text = element => element.textContent + element.children.map(text).join('');
  const findButton = (label,root = body) => root.querySelectorAll('button').find(button => button.textContent === label);
  return {window,body,get,calls,stored,catalog,plan,findButton,text,
    setJob: next => {job = next;},job:() => job,
    dialog:() => body.querySelector('dialog'),
    async navigate() {await window.RimeRelays.navigate(); await settle();},
    async openSwitch() {await this.navigate(); await findButton('Сменить вход').fire('click');},
    async submit() {await get('form').fire('submit'); await settle();},
    async tick() {const next = [...timers].sort((a,b) => a[1].delay - b[1].delay)[0]; assert.ok(next,'A retry is scheduled'); timers.delete(next[0]); await next[1].callback(); await settle();}
  };
}

test('an offline current entry can be replaced with a fresh alternative through one switch action',async () => {
  const h = setup(); await h.openSwitch();
  assert.equal(h.get('dialog-title').textContent,'Сменить входной сервер');
  assert.ok(h.text(h.get('dialog-body')).includes('Нет свежей связи с текущим входом'));
  assert.deepEqual(h.get('form').elements.entry.children.map(option => option.value),[NEW]);
  await h.submit();
  const request = h.calls.find(call => call.url.endsWith('/switch/plan'));
  assert.equal(request.url,'/api/fleet/relays/routes/' + ROUTE + '/switch/plan');
  assert.deepEqual(request.settings.json,{entry:NEW,grace_seconds:86400});
  assert.ok(h.text(h.get('dialog-body')).includes('Old entry → New entry'));
  assert.equal(h.calls.some(call => call.url.includes('host-key')),false);
  await h.findButton('Сменить вход',h.dialog()).fire('click'); await settle();
  assert.equal(h.stored.get('rime.relay.job'),JOB);
  const progress = h.get('progress').querySelector('progress');
  assert.equal(progress.value,'2'); assert.equal(progress.max,7);
});

test('the switch dialog explains when another ready entry is required',async () => {
  const h = setup({noAlternative:true}); await h.openSwitch();
  assert.ok(h.text(h.get('dialog-body')).includes('Других готовых входных серверов'));
  assert.equal(h.get('form'),undefined);
  assert.equal(h.calls.some(call => call.url.endsWith('/plan')),false);
});

test('the switch preview distinguishes HTTP and HTTPS and displays one subscription notice',async () => {
  const h = setup();
  h.plan.message = 'Обновите существующую подписку после переключения.';
  h.plan.services.push({kind:'proxy',mode:'http',public_port:13128,origin_port:3128,protocol:'tcp'},
    {kind:'proxy',mode:'https',public_port:18443,origin_port:8443,protocol:'tcp'});
  await h.openSwitch(); await h.submit();
  const rows = copy(h.get('dialog-body').querySelector('.table-wrap').rows);
  assert.deepEqual(rows.map(row => row[0]),['VPN','HTTP-прокси','HTTPS-прокси']);
  assert.equal(h.text(h.get('dialog-body')).split(h.plan.message).length - 1,1);
});

test('the previous entry cannot be deleted while its old rules await cleanup',async () => {
  const h = setup(); h.catalog.entries[0].pending_cleanup_count = 1;
  h.catalog.tunnels[0].entry = NEW; await h.navigate();
  const oldCard = h.get('entry-list').children[0];
  const remove = h.findButton('Удалить вход',oldCard);
  assert.equal(remove.disabled,true); assert.ok(remove.title.includes('Дождитесь очистки'));
});

test('pending rollback cleanup keeps the previous route label instead of claiming a working new entry',async () => {
  const h = setup(); h.catalog.tunnels[0].switch = {phase:'rollback_pending'};
  await h.navigate();
  const notice = h.get('route-list').querySelector('.relay-cleanup-note');
  assert.ok(notice.textContent.includes('Прежний маршрут сохранён'));
  assert.equal(notice.textContent.includes('Новый вход работает'),false);
});

test('changing the selected entry invalidates a late plan response',async () => {
  let finish;
  const h = setup({otherFresh:true,respond:url => url.endsWith('/switch/plan') ? new Promise(resolve => {finish = resolve;}) : undefined});
  await h.openSwitch(); const pending = h.get('form').fire('submit');
  h.get('form').elements.entry.value = OTHER; await h.get('form').fire('input');
  finish(copy(h.plan)); await pending;
  assert.ok(h.get('form')); assert.equal(h.get('form').querySelector('button').disabled,false);
  assert.equal(h.findButton('Сменить вход',h.dialog()),undefined);
});

test('confirmation is dispatched once and a running final phase stays below 100 percent',async () => {
  let finish;
  const h = setup({respond:url => url.endsWith('/deploy') ? new Promise(resolve => {finish = resolve;}) : undefined});
  await h.openSwitch(); await h.submit();
  const confirm = h.findButton('Сменить вход',h.dialog()), pending = confirm.fire('click');
  assert.equal(confirm.disabled,true); await confirm.fire('click');
  assert.equal(h.calls.filter(call => call.url.endsWith('/deploy')).length,1);
  h.setJob({...h.job(),context:{operation:'route-switch',progress:{completed:7,total:7,label:'Завершение операции'}}});
  finish({id:JOB}); await pending; await settle();
  assert.equal(h.get('progress').querySelector('progress').value,'6');
});

test('a committed switch with deferred old cleanup finishes successfully and explains the remaining cleanup',async () => {
  const h = setup({saved:true,cleanupPending:true});
  h.setJob({...h.job(),state:'succeeded',message:'Вход переключён',context:{operation:'route-switch',old_cleanup_pending:true,progress:{completed:7,total:7,label:'Готово'}}});
  await h.navigate(); await settle();
  assert.equal(h.get('progress').querySelector('progress').value,'7');
  assert.equal(h.get('job-note').hidden,false);
  assert.ok(h.get('job-note').textContent.includes('Новый вход работает'));
  assert.ok(h.text(h.get('route-list')).includes('Очистка прежних правил ожидает связи или сверки'));
  assert.equal(h.stored.has('rime.relay.job'),false);
});

test('saved operation resumes after refresh and polling errors preserve the job for retry',async () => {
  let fail = true;
  const h = setup({saved:true,respond:url => {
    if (url.includes('/jobs/') && fail) {fail = false; throw new Error('Connection lost');}
  }});
  await h.navigate();
  assert.equal(h.dialog().open,true); assert.equal(h.stored.get('rime.relay.job'),JOB);
  assert.ok(h.get('dialog-error').textContent.includes('Повторяем проверку'));
  await h.tick();
  assert.equal(h.get('dialog-title').textContent,'Смена входного сервера');
  assert.equal(h.get('dialog-error').textContent,'');
  assert.equal(h.get('progress').querySelector('progress').value,'2');
});

test('closing a running job preserves refresh recovery and a rollback is never shown as complete',async () => {
  const h = setup({saved:true}); await h.navigate(); h.dialog().close();
  assert.equal(h.stored.get('rime.relay.job'),JOB); await h.navigate();
  h.setJob({...h.job(),state:'rolled_back',message:'Новый вход недоступен. Прежний маршрут сохранён.'});
  await h.tick();
  assert.equal(h.get('progress').dataset.state,'failed');
  assert.notEqual(h.get('progress').querySelector('progress').value,'7');
  assert.ok(h.get('job-message').textContent.includes('Прежний маршрут сохранён'));
  assert.equal(h.get('job-note').hidden,true); assert.equal(h.stored.has('rime.relay.job'),false);
});

test('an ambiguous deploy response reconciles the existing job instead of submitting it twice',async () => {
  const h = setup({respond:url => {
    if (url.endsWith('/deploy')) {const error = new Error('Response lost'); error.status = 503; throw error;}
  }});
  await h.openSwitch(); await h.submit(); await h.findButton('Сменить вход',h.dialog()).fire('click'); await settle();
  assert.equal(h.calls.filter(call => call.url.endsWith('/deploy')).length,1);
  assert.equal(h.get('dialog-title').textContent,'Смена входного сервера');
  assert.equal(h.stored.get('rime.relay.job'),JOB);
});


test('forced direct publication requires confirmation and uses the selected route',async()=>{
  const h=setup({respond:url=>url.endsWith('/detach')?{id:JOB}:undefined});await h.navigate();
  await h.findButton('Вернуть прямой адрес').fire('click');
  const input=h.get('dialog-body').querySelector('input');
  const submit=h.findButton('Вернуть прямой адрес',h.dialog());
  assert.equal(submit.disabled,true);await submit.fire('click');
  assert.equal(h.calls.some(c=>c.url.endsWith('/detach')),false);
  input.checked=true;await input.fire('change');await submit.fire('click');await settle();
  const request=h.calls.find(c=>c.url.endsWith('/detach'));
  assert.equal(request.url,'/api/fleet/relays/routes/'+ROUTE+'/detach');
  assert.deepEqual(request.settings.json,{confirmation:ROUTE});
});

test('forget entry requires exact domain and is available after its routes are withdrawn',async()=>{
  const h=setup({respond:url=>url.endsWith('/forget')?{forgotten:true}:undefined});
  h.catalog.tunnels=[];await h.navigate();await h.findButton('Забыть вход').fire('click');
  const input=h.get('dialog-body').querySelector('input'),submit=h.findButton('Забыть вход',h.dialog());
  input.value='wrong.example';await input.fire('input');assert.equal(submit.disabled,true);
  input.value='old.example';await input.fire('input');assert.equal(submit.disabled,false);
  await submit.fire('click');await settle();
  const request=h.calls.find(c=>c.url.endsWith('/forget'));
  assert.equal(request.url,'/api/fleet/relays/entry/'+OLD+'/forget');
  assert.deepEqual(request.settings.json,{confirmation:'old.example'});
  assert.equal(h.dialog().open,false);
});

test('planned switch shows the grace deadline separately from failed cleanup',async()=>{
  const h=setup();h.catalog.tunnels[0].grace_until=Date.now()/1000+86400;await h.navigate();
  assert.ok(h.text(h.get('route-list')).includes('Прежний вход сохранён до'));
  assert.ok(!h.text(h.get('route-list')).includes('Очистка прежних правил ожидает связи'));
});

test('quarantined observations remain visible while health can stay fresh',async()=>{
  const h=setup();h.catalog.entries[0].health.quarantined_packets=3;await h.navigate();
  assert.ok(h.text(h.get('entry-list')).includes('Пакетов телеметрии в карантине · 3'));
});
