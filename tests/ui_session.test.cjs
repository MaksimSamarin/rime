const {test} = require('node:test');
const assert = require('node:assert/strict');
const {createSession, createApi} = require('../hy2bridge/web/session.js');
const token = (sub='admin', exp=2000) => [Buffer.from('{}').toString('base64url'),Buffer.from(JSON.stringify({sub,exp})).toString('base64url'),'signature'].join('.');
function storage() { const values=new Map(); return {values,getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)}; }
function setup() { const store=storage(), session=createSession({storage:store,now:()=>1000});session.set(token(),'admin');return {store,session}; }
test('tab storage survives a page reload without storing a password',()=>{
 const {store,session}=setup();const restored=createSession({storage:store,now:()=>1001});
 assert.equal(restored.token,session.token);assert.equal(restored.username,'admin');
 assert.deepEqual(Object.keys(JSON.parse(store.getItem('rime.admin.session'))).sort(),['token','username']);
});
test('expired and malformed sessions are removed',()=>{
 for(const value of ['broken',JSON.stringify({token:'bad',username:'admin'}),JSON.stringify({token:token('admin',900),username:'admin'})]){
  const store=storage();store.setItem('rime.admin.session',value);const session=createSession({storage:store,now:()=>1000});
  assert.equal(session.token,null);assert.equal(store.getItem('rime.admin.session'),null);
 }
});
test('unavailable storage does not break an in-memory session',()=>{
 const session=createSession({storage:{getItem(){throw Error('blocked')},setItem(){throw Error('blocked')},removeItem(){throw Error('blocked')}},now:()=>1000});
 session.set(token(),'admin');assert.equal(session.token,token());session.clear();assert.equal(session.token,null);
});
test('logout does not remove unrelated application storage',()=>{
 const {store,session}=setup();store.setItem('other','keep');session.clear();assert.equal(store.getItem('other'),'keep');
});
test('server errors and network failures retain authorization',async()=>{
 for(const send of [async()=>new Response('{"detail":"temporarily unavailable"}',{status:503}),async()=>{throw new TypeError('Failed to fetch')}]){
  const {session}=setup();let logout=0;const api=createApi({session,fetch:send,onUnauthorized:()=>logout++});
  await assert.rejects(api('/read'));assert.equal(session.token,token());assert.equal(logout,0);
 }
});
test('request timeout keeps the session',async()=>{
 const {session}=setup();const api=createApi({session,timeout:10,fetch:(_,{signal})=>new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('aborted','AbortError'))))});
 await assert.rejects(api('/slow'),/Сессия сохранена/);assert.equal(session.token,token());
});

test('a caller can extend one request without forwarding the timeout option',async()=>{
 const {session}=setup();let request;
 const api=createApi({session,timeout:5,fetch:(_path,options)=>{
  request=options;
  return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>resolve(new Response('{}')),15);
   options.signal.addEventListener('abort',()=>{clearTimeout(timer);reject(new DOMException('aborted','AbortError'));});
  });
 }});
 await api('/long-check',{timeoutMs:100});
 assert.equal(request.timeoutMs,undefined);assert.equal(session.token,token());
});

test('per-request timeouts are bounded and invalid values keep the default',(t)=>{
 const {session}=setup();const delays=[],schedule=global.setTimeout;
 t.mock.method(global,'setTimeout',(callback,delay)=>{delays.push(delay);return schedule(callback,delay);});
 const api=createApi({session,fetch:async()=>new Response('{}')});
 return (async()=>{
  for(const timeoutMs of [120000,999999,0,-1,Infinity,NaN,'90000',undefined])await api('/read',{timeoutMs});
  assert.deepEqual(delays,[120000,180000,20000,20000,20000,20000,20000,20000]);
 })();
});
test('a current 401 clears the session once',async()=>{
 const {session}=setup();let logout=0;const api=createApi({session,fetch:async()=>new Response('{}',{status:401}),onUnauthorized:()=>logout++});
 await assert.rejects(api('/read'),{name:'UnauthorizedError'});assert.equal(session.token,null);assert.equal(logout,1);
});
test('a late 401 cannot log out a newer login',async()=>{
 const {session}=setup();let resolve,logout=0;const api=createApi({session,fetch:()=>new Promise(r=>resolve=r),onUnauthorized:()=>logout++});
 const pending=api('/old');session.set(token('second'),'second');resolve(new Response('{}',{status:401}));
 await assert.rejects(pending,{name:'SessionChangedError'});assert.equal(session.token,token('second'));assert.equal(logout,0);
});
test('same JWT bytes after a new login still invalidate old requests',async()=>{
 const {session}=setup();let resolve;const api=createApi({session,fetch:()=>new Promise(r=>resolve=r)});
 const pending=api('/old');session.clear();session.set(token(),'admin');resolve(new Response('{}',{status:401}));
 await assert.rejects(pending,{name:'SessionChangedError'});assert.equal(session.token,token());
});
test('a late success cannot update a new session',async()=>{
 const {session}=setup();let resolve;const api=createApi({session,fetch:()=>new Promise(r=>resolve=r)});
 const pending=api('/old');session.clear();resolve(new Response('{"old":"data"}'));
 await assert.rejects(pending,{name:'SessionChangedError'});
});
test('parallel unauthorized responses do not repeatedly expire authorization',async()=>{
 const {session}=setup();let logout=0;const api=createApi({session,fetch:async()=>new Response('{}',{status:401}),onUnauthorized:()=>logout++});
 const results=await Promise.allSettled([api('/a'),api('/b'),api('/c')]);assert.equal(logout,1);assert.ok(results.every(x=>x.status==='rejected'));
});
test('caller options are not mutated and JSON is encoded',async()=>{
 const {session}=setup();let request;const api=createApi({session,fetch:async(path,options)=>{request=options;return new Response('{}')}});
 const options={method:'POST',json:{value:1},headers:{'X-Test':'yes'}};await api('/save',options);
 assert.deepEqual(options,{method:'POST',json:{value:1},headers:{'X-Test':'yes'}});assert.equal(request.body,'{"value":1}');assert.equal(request.headers.Authorization,'Bearer '+token());
});
test('external cancellation keeps authorization',async()=>{
 const {session}=setup();const external=new AbortController();
 const api=createApi({session,fetch:(_,{signal})=>new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('aborted','AbortError'))))});
 const pending=api('/cancel',{signal:external.signal});external.abort();await assert.rejects(pending,/отменён/);assert.equal(session.token,token());
});
