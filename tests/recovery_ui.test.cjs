const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function setup(respond){
  const ids=new Map(),fields=new Map(),calls=[];
  let dialog;
  class Element{
    constructor(tag='div'){this.tag=tag;this.value='';this.listeners={};this.files=[];this.open=false;this.disabled=false;this.children=[];}
    set innerHTML(html){
      for(const match of html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*)>/g)){
        const attrs=match[2],id=attrs.match(/\bid="([^"]+)"/)?.[1],name=attrs.match(/\bname="([^"]+)"/)?.[1];
        if(!id&&!name)continue;
        const item=new Element(match[1]);item.value=attrs.match(/\bvalue="([^"]*)"/)?.[1]||'';item.defaultValue=item.value;
        item.disabled=/\bdisabled\b/.test(attrs);if(id)ids.set(id,item);if(name)fields.set(name,item);
      }
      get('auth').value='password';get('capture').elements={namedItem:name=>fields.get(name)};
      get('capture').reset=()=>{for(const item of fields.values())item.value=item.defaultValue;get('auth').value='password';};
    }
    addEventListener(type,callback){(this.listeners[type]||=[]).push(callback);}
    async fire(type){for(const callback of this.listeners[type]||[])await callback({preventDefault(){}});}
    querySelectorAll(selector){return selector==='[data-close]'?[]:[...fields.values()].filter(item=>item.tag==='textarea'||['password','key_passphrase'].some(name=>fields.get(name)===item));}
    setAttribute(){}
    append(...items){this.children.push(...items);}
    replaceChildren(...items){this.children=items;}
    showModal(){this.open=true;}
    close(){this.open=false;this.fire('close');}
  }
  const get=name=>ids.get('recovery-'+name);
  const el=(tag,text)=>{const item=new Element(tag);item.textContent=text;if(tag==='dialog')dialog=item;return item;};
  const api=async(url,options={})=>{calls.push({url,options});return respond?.(url,options)??{available:true,protocol:'vless',proxies:1,updated_at:1};};
  const window={Rime:{api,el,stamp:String}};
  class FormData{constructor(){this.values=[...fields].filter(([,item])=>!item.disabled).map(([name,item])=>[name,item.value]);}[Symbol.iterator](){return this.values[Symbol.iterator]();}}
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web/recovery.js'),'utf8'),{window,document:{body:{append(){}},getElementById:id=>ids.get(id)},FormData});
  return {get,fields,calls,dialog,window,open:node=>window.RimeRecovery.open(node||{id:'synthetic',name:'Synthetic',address:'node.invalid'})};
}

test('recovery readiness requires a complete server profile',async()=>{
  const h=setup(()=>({available:false,missing_inbounds:['XHTTP'],proxies:0}));await h.open();
  assert.equal(h.get('transfer').disabled,true);assert.ok(h.get('summary').children.some(item=>item.textContent?.includes('XHTTP')));
});

test('closing and reopening clears SSH secrets and resets in-flight controls',async()=>{
  let finish;const h=setup(url=>url.endsWith('/host-key')?new Promise(resolve=>finish=resolve):undefined);await h.open();
  h.fields.get('password').value='temporary';const pending=h.get('capture').fire('submit');
  assert.equal(h.get('scan').disabled,true);h.dialog.close();assert.equal(h.fields.get('password').value,'');
  await h.open({id:'other',name:'Other',address:'other.invalid'});assert.equal(h.get('scan').disabled,false);
  finish({fingerprint:'stale'});await pending;assert.equal(h.get('fingerprint').hidden,true);
});

test('editing access while a scan runs invalidates its fingerprint and credentials',async()=>{
  let finish;const h=setup(url=>url.endsWith('/host-key')?new Promise(resolve=>finish=resolve):undefined);await h.open();
  const pending=h.get('capture').fire('submit');h.fields.get('host').value='changed.invalid';await h.get('capture').fire('input');
  finish({fingerprint:'stale'});await pending;assert.equal(h.get('fingerprint').hidden,true);assert.equal(h.get('read').disabled,true);
});

test('a late load failure cannot overwrite a different recovery dialog',async()=>{
  let fail;const h=setup(url=>url.includes('first')?new Promise((_,reject)=>fail=reject):undefined);
  const pending=h.open({id:'first',name:'First'});h.dialog.close();await h.open();fail(new Error('stale error'));await pending;
  assert.equal(h.get('error').textContent,'');assert.equal(h.get('transfer').disabled,false);
});

test('oversized archives are rejected before upload',async()=>{
  const h=setup();await h.open();h.get('file').files=[{size:64*1024*1024+1}];await h.get('import').fire('click');
  assert.ok(h.get('error').textContent.includes('64 MiB'));assert.equal(h.calls.some(call=>call.url.endsWith('/import')),false);
});
