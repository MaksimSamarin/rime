const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function setup(file){
  const ids=new Map(),calls=[];
  class Element{
    constructor(tag='div',text=''){this.tag=tag;this.textContent=text;this.children=[];this.value='';this.checked=false;this.hidden=false;this.dataset={};this.style={};this.listeners={};this.classList={add(){},remove(){},toggle(){}};}
    set id(value){this._id=value;ids.set(value,this);}
    get id(){return this._id;}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;}
    addEventListener(name,fn){this.listeners[name]=fn;}
    setAttribute(){}
    querySelector(){return new Element();}
    querySelectorAll(){return [];}
    insertBefore(){}
    before(){}
    reset(){}
    getBoundingClientRect(){return {top:0,bottom:76};}
  }
  const element=id=>{if(!ids.has(id)){const item=new Element();item.id=id;}return ids.get(id);};
  const el=(tag,text,cls)=>{const item=new Element(tag,text);item.className=cls;return item;};
  const state={events:[],overview:{nodes:[{id:'n1',name:'Node one'}]}};
  const window={Rime:{el,state,api:async()=>{calls.push('api');throw new Error('Unexpected network request');},table:(target,headers,rows)=>Object.assign(target,{headers,rows}),chart(){},bytes:String,stamp:String,badge(){},nodeBadge(){},showError(){},loadTraffic(){}},scrollTo(){}};
  const document={getElementById:element,querySelector:()=>new Element(),querySelectorAll:()=>[],createElement:el,createTextNode:text=>text,createDocumentFragment:()=>new Element()};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../hy2bridge/web',file),'utf8'),{window,document,location:{hash:'#docs/faq'},innerWidth:1440,scrollY:0,getComputedStyle:()=>({position:'fixed'}),requestAnimationFrame:fn=>fn(),setTimeout:()=>1,setInterval:()=>1,clearTimeout(){},URLSearchParams});
  return {window,state,element,ids,calls};
}

test('active incidents disappear after a successful recovery and remain in history',()=>{
  const h=setup('console.js');h.element('events-open').checked=true;
  h.state.events=[{id:1,node:'n1',code:'client_unreachable',message:'Failed',first_at:1,last_at:2,occurrences:3,resolved_at:null,action:{acknowledged:true}}];
  h.window.RimeConsole.events();assert.equal(h.element('events-table').rows.length,1);
  assert.equal(h.element('events-table').rows[0][3].textContent,'Активно');
  h.state.events[0].resolved_at=3;h.window.RimeConsole.events();assert.equal(h.element('events-table').children[0].textContent,'Активных проблем нет.');
  h.element('events-open').checked=false;h.window.RimeConsole.events();assert.equal(h.element('events-table').rows.length,1);
  assert.equal(h.element('events-table').rows[0][3].textContent,'Восстановлено');
  assert.equal(h.ids.has('event-action'),false);assert.deepEqual(h.calls,[]);
});

test('documentation mounts guides and keyboard-operable FAQ once',()=>{
  const h=setup('help.js');h.window.RimeHelp.navigate();
  assert.equal(h.element('help-content').children.length,12);assert.equal(h.element('help-toc').children.length,12);
  const questions=h.element('help-faq').children.filter(child=>child.tag==='details');
  assert.equal(questions.length,10);assert.ok(questions.every(child=>child.children[0].tag==='summary'&&child.children[1].textContent));
  h.window.RimeHelp.navigate();assert.equal(h.element('help-content').children.length,12);assert.deepEqual(h.calls,[]);
});

test('the console exposes automatic incident state and a separate documentation route',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../hy2bridge/web/index.html'),'utf8');
  assert.ok(html.includes('href="#docs" data-page="docs"'));assert.ok(html.includes('id="page-docs"'));
  assert.ok(html.includes('Только активные'));assert.equal(html.includes('id="event-action"'),false);
  assert.equal(html.includes('Единое рабочее пространство'),false);
});
