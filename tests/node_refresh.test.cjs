const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function beginRefresh(selected,next){
  const source=fs.readFileSync(require.resolve('../hy2bridge/web/console.js'),'utf8');
  const start=source.indexOf('  async function nodeDetail('),end=source.indexOf('    const [n,h]=await',start);
  const elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,{disabled:false,textContent:''});return elements.get(id);};
  const context=vm.createContext({$:get,nodeRequest:0,activeNode:selected,location:{hash:'#node/'+encodeURIComponent(next)},nodeRole(){}});
  vm.runInContext(source.slice(start,end)+'return activeNode;};globalThis.begin=nodeDetail;',context);
  return {result:context.begin(),get};
}
test('background node refresh keeps the visible node available to recovery and transfer',async()=>{
  const selected={id:'xray:3',name:'Synthetic'};const h=beginRefresh(selected,'xray:3');
  assert.equal(await h.result,selected);
  for(const id of ['node-transfer','node-recovery','node-proxy'])assert.equal(h.get(id).disabled,false);
});
test('switching to another node blocks actions until its own details arrive',async()=>{
  const h=beginRefresh({id:'xray:3'},'different-node');assert.equal(await h.result,null);
  for(const id of ['node-transfer','node-recovery','node-proxy'])assert.equal(h.get(id).disabled,true);
});
