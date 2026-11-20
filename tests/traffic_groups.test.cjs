const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

function fixture(){
  class Element{
    constructor(tag,text){this.tag=tag;this.textContent=text;this.attrs={};this.children=[];this.handlers={};this.clientWidth=900;}
    setAttribute(key,value){this.attrs[key]=value;}
    append(...items){this.children.push(...items);}
    replaceChildren(...items){this.children=items;}
    addEventListener(name,fn){this.handlers[name]=fn;}
    getBoundingClientRect(){return {left:0,width:900};}
  }
  const code=fs.readFileSync(require.resolve('../hy2bridge/web/app.js'),'utf8');
  const context=vm.createContext({window:{RimeMonitor:require('../hy2bridge/web/monitoring.js')},document:{createElementNS:(ns,tag)=>new Element(tag)},el:(tag,text)=>new Element(tag,text),bytes:value=>String(value),byteFormat:new Intl.NumberFormat('ru-RU'),empty(){},requestAnimationFrame:fn=>fn(),cancelAnimationFrame(){},WeakMap,Intl});
  vm.runInContext(code.slice(code.indexOf('  const chartStates='),code.indexOf('  function eventList('))+';globalThis.draw=chart;',context);
  const target=new Element('div');target.id='traffic-chart';return {target,draw:context.draw};
}

test('grouped lines and keyboard readout use the supplied group keys and labels',()=>{
  const f=fixture();f.draw(f.target,[{hour:'2026-11-07 00:00:00',g0:10,g1:30},{hour:'2026-11-07 01:00:00',g0:20,g1:40}],[{key:'g0',label:'Sauna'},{key:'g1',label:'Fondue'}]);
  const [svg,readout]=f.target.children;
  assert.equal(svg.children.filter(n=>n.tag==='polyline').length,2);
  assert.deepEqual(readout.children.slice(1).map(n=>n.textContent),['Sauna 20','Fondue 40']);
  svg.handlers.keydown({key:'Home',preventDefault(){}});
  assert.deepEqual(readout.children.slice(1).map(n=>n.textContent),['Sauna 10','Fondue 30']);
});

test('missing values split grouped lines and do not become zero readings',()=>{
  const f=fixture();f.draw(f.target,[{hour:'2026-11-07 00:00:00',g0:10},{hour:'2026-11-07 01:00:00',g0:null},{hour:'2026-11-07 02:00:00',g0:20}],[{key:'g0',label:'krit'}]);
  const [svg,readout]=f.target.children;
  assert.equal(svg.children.filter(n=>n.tag==='polyline').length,0);
  assert.equal(svg.children.filter(n=>n.tag==='circle').length,2);
  svg.handlers.keydown({key:'ArrowLeft',preventDefault(){}});
  assert.equal(readout.children[1].textContent,'krit нет данных');
});
