const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor() {
    this.value = ''; this.hidden = false; this.disabled = false; this.required = false;
    this.checked = false; this.textContent = ''; this.listeners = {};
    this.classList = {add(){}, remove(){}};
  }
  addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
  async fire(type, event = {}) {
    const action = {preventDefault(){}, currentTarget:this, submitter:this, ...event};
    for (const callback of this.listeners[type] || []) await callback(action);
  }
  append() {}
  replaceChildren() {}
  scrollIntoView() {}
  focus() {}
}

function setup(respond) {
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const fields = Object.fromEntries(['name','host','domain','username','ssh_port','vpn_port','protocol',
    'password','private_key','key_passphrase','certificate','certificate_key','cleanup_job','move_node'].map(name=>[name,new Element()]));
  Object.assign(fields.name, {value:'Synthetic node'});
  Object.assign(fields.host, {value:'node.example.invalid'});
  Object.assign(fields.domain, {value:'node.example.invalid'});
  Object.assign(fields.username, {value:'root'});
  Object.assign(fields.ssh_port, {value:'22'});
  Object.assign(fields.vpn_port, {value:'443'});
  Object.assign(fields.protocol, {value:'hysteria2'});
  get('deploy-auth-method').value = 'password';
  const form = get('deploy-form');
  form.elements = {namedItem:name=>fields[name]};
  form.reset = () => {
    for (const field of Object.values(fields)) field.value = '';
    get('deploy-auth-method').value = 'password';
  };
  const calls = [];
  const api = async (url, options = {}) => {
    calls.push({url, json:options.json ? JSON.parse(JSON.stringify(options.json)) : null});
    if (respond) { const value = respond(url, options); if (value !== undefined) return value; }
    if (url.endsWith('/options')) return {enabled:true,protocols:{hysteria2:true,vless:true},automatic_tls:true};
    if (url.endsWith('/recovery')) return {available:true};
    if (url.endsWith('/host-key')) return {fingerprint:'SHA256:synthetic',address:'192.0.2.1'};
    if (url.endsWith('/preflight')) return {id:'synthetic-plan',ready:true,expires_at:Date.now()/1000+300,summary:{},checks:[]};
    throw new Error('Unexpected test request');
  };
  api.abortAll = () => {};
  const window = {
    RimeSession:{createSession:()=>({token:null}),createApi:()=>api},
    addEventListener(){}, sessionStorage:{getItem(){return null;},removeItem(){}}
  };
  class FormData {
    constructor() { this.values=Object.entries(fields).filter(([,field])=>!field.disabled).map(([name,field])=>[name,field.value]); }
    [Symbol.iterator]() { return this.values[Symbol.iterator](); }
  }
  const document = {getElementById:get, addEventListener(){}, readyState:'loading'};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web/app.js'),'utf8'), {
    window,document,FormData,Node:Element,URL,URLSearchParams,Intl,Date,
    location:{hash:'#deploy'},setTimeout:()=>1,clearTimeout(){},fetch(){throw new Error('External request');}
  });
  return {get, fields, calls, state:window.Rime.state, prepareTransfer:window.Rime.prepareTransfer,
    mode:async value=>{get('deploy-auth-method').value=value;await get('deploy-auth-method').fire('change');},
    scan:()=>form.fire('submit',{submitter:get('preflight')}),
    verify:async()=>{get('trust-host').checked=true;await get('trust-host').fire('change');await get('verify-host').fire('click');}
  };
}

test('password is the default and switching methods clears only SSH secrets', async()=>{
  const h=setup();
  assert.equal(h.get('deploy-password-fields').hidden,false);
  assert.equal(h.fields.password.required,true);
  assert.equal(h.fields.private_key.disabled,true);
  h.fields.password.value='synthetic-password';h.fields.certificate_key.value='synthetic-tls-key';
  await h.mode('key');
  assert.equal(h.get('deploy-password-fields').hidden,true);
  assert.equal(h.fields.password.disabled,true);assert.equal(h.fields.password.value,'');
  assert.equal(h.fields.private_key.required,true);assert.equal(h.fields.key_passphrase.disabled,false);
  h.fields.private_key.value='synthetic-key';h.fields.key_passphrase.value='synthetic-passphrase';
  await h.mode('password');
  assert.equal(h.fields.private_key.value,'');assert.equal(h.fields.key_passphrase.value,'');
  assert.equal(h.fields.private_key.disabled,true);assert.equal(h.fields.certificate_key.value,'synthetic-tls-key');
});

test('password payload retains API fields and requires explicit host verification', async()=>{
  const h=setup();h.fields.password.value='synthetic-password';
  await h.scan();
  assert.equal(h.get('verify-host').disabled,true);assert.equal(h.get('trust-host').checked,false);
  await h.get('verify-host').fire('click');
  assert.equal(h.calls.some(call=>call.url.endsWith('/preflight')),false);
  await h.verify();
  const data=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(data.password,'synthetic-password');assert.equal(data.private_key,'');assert.equal(data.key_passphrase,'');
  assert.equal(data.fingerprint,'SHA256:synthetic');assert.equal(data.address,'192.0.2.1');
});

test('key payload excludes an inactive password and preserves the optional passphrase', async()=>{
  const h=setup();await h.mode('key');h.fields.private_key.value='synthetic-key';h.fields.key_passphrase.value='synthetic-passphrase';
  h.fields.password.value='inactive-value';await h.scan();await h.verify();
  const data=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(data.password,'');assert.equal(data.private_key,'synthetic-key');assert.equal(data.key_passphrase,'synthetic-passphrase');
});

test('new attempt resets the method and all credential fields', async()=>{
  const h=setup();await h.mode('key');h.fields.private_key.value='synthetic-key';
  await h.get('job-new').fire('click');
  assert.equal(h.get('deploy-auth-method').value,'password');assert.equal(h.get('deploy-key-fields').hidden,true);
  assert.equal(h.fields.password.disabled,false);assert.equal(h.fields.password.required,true);assert.equal(h.fields.private_key.value,'');
});

test('a late host scan cannot restore credentials or trust after switching methods', async()=>{
  let finish;
  const h=setup(url=>url.endsWith('/host-key')?new Promise(resolve=>{finish=resolve;}):undefined);
  h.fields.password.value='synthetic-password';const pending=h.scan();
  await new Promise(resolve=>setImmediate(resolve));await h.mode('key');
  finish({fingerprint:'SHA256:old',address:'192.0.2.1'});await pending;
  assert.equal(h.state.draft,null);assert.equal(h.get('host-key-card').hidden,true);
  assert.equal(h.get('host-key').textContent,'');assert.equal(h.get('verify-host').disabled,true);
});

test('editing server inputs invalidates the previous fingerprint and plan', async()=>{
  const h=setup();h.fields.password.value='synthetic-password';await h.scan();await h.verify();
  h.fields.host.value='changed.example.invalid';await h.get('deploy-form').fire('input');
  assert.equal(h.state.plan,null);assert.equal(h.state.draft,null);assert.equal(h.get('plan-card').hidden,true);
  assert.equal(h.get('trust-host').checked,false);assert.equal(h.fields.password.value,'synthetic-password');
});

test('a late preflight cannot replace a newly selected method', async()=>{
  let finish;
  const h=setup(url=>url.endsWith('/preflight')?new Promise(resolve=>{finish=resolve;}):undefined);
  h.fields.password.value='synthetic-password';await h.scan();const pending=h.verify();
  await new Promise(resolve=>setImmediate(resolve));await h.mode('key');
  finish({id:'old-plan',ready:true,summary:{},checks:[]});await pending;
  assert.equal(h.state.plan,null);assert.equal(h.get('plan-card').hidden,true);assert.equal(h.get('verify-host').disabled,true);
});


test('transfer locks the original endpoint and submits its identity through the normal wizard', async()=>{
  const h=setup(url=>url.includes('/transfer/')?{node:'xray:5',name:'Original',protocol:'vless',domain:'original.example',vpn_port:443,old_address:'192.0.2.5',instructions:'Synthetic transfer'}:undefined);
  await h.prepareTransfer('xray:5');
  assert.equal(h.fields.move_node.value,'xray:5');
  assert.equal(h.fields.protocol.disabled,true);
  for(const key of ['name','domain','vpn_port'])assert.equal(h.fields[key].readOnly,true);
  h.fields.host.value='node.example.invalid';h.fields.username.value='root';h.fields.ssh_port.value='22';h.fields.password.value='synthetic-secret';
  await h.scan();await h.verify();
  const payload=h.calls.find(call=>call.url.endsWith('/preflight')).json;
  assert.equal(payload.move_node,'xray:5');assert.equal(payload.protocol,'vless');assert.equal(payload.domain,'original.example');
  await h.get('job-new').fire('click');
  assert.equal(h.fields.move_node.value,'');assert.equal(h.fields.protocol.disabled,false);assert.equal(h.fields.domain.readOnly,false);
});
