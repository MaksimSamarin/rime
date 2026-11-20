const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function fixture(hash) {
  const source = fs.readFileSync(path.join(__dirname, '../hy2bridge/web/app.js'), 'utf8');
  const start = source.indexOf('  let lastRoute=');
  const end = source.indexOf('  function showApp(', start);
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {id, value:'', hidden:true, textContent:'', href:'', focus(){}});
    return elements.get(id);
  };
  const links = ['overview','nodes','traffic'].map(page => ({
    dataset:{page}, current:null,
    setAttribute(name, value){this.current=value;},
    removeAttribute(){this.current=null;}
  }));
  const scroll = [];
  const state = {overview:{nodes:[{id:'xray:6',name:'Synthetic node'}]}, token:null};
  let cleared = 0;
  const context = vm.createContext({
    $:element, location:{hash}, state,
    titles:{overview:'Обзор',nodes:'Ноды',node:'Нода',traffic:'VPN-трафик'},
    document:{querySelectorAll:selector=>selector==='nav a'?links:[]},
    window:{scrollTo:(...args)=>scroll.push(args)},
    clearTrafficReport:()=>cleared++,
    renderNodes(){},renderOverview(){},renderEvents(){},resetWizard(){},refresh(){},
    overviewTraffic:null,loadTraffic(){}
  });
  vm.runInContext(source.slice(start,end)+';globalThis.navigation={navigate,updateTrafficContext};',context);
  return {context, state, links, scroll, element, navigation:context.navigation, cleared:()=>cleared};
}

test('node report keeps an encoded return route and clears unrelated filters', () => {
  const f=fixture('#traffic/xray%3A6');
  f.element('filter-protocol').value='hysteria2';
  assert.equal(f.navigation.updateTrafficContext(),true);
  assert.equal(f.element('filter-node').value,'xray:6');
  assert.equal(f.element('filter-protocol').value,'');
  assert.equal(f.element('traffic-back').href,'#node/xray%3A6');
  assert.equal(f.element('traffic-back').textContent,'← К ноде Synthetic node');
  f.element('filter-user').value='synthetic_user';
  f.navigation.updateTrafficContext();
  assert.equal(f.element('filter-user').value,'synthetic_user');
});

test('direct reload waits for node metadata before applying its report filter', () => {
  const f=fixture('#traffic/xray%3A6');
  const overview=f.state.overview;f.state.overview=null;
  assert.equal(f.navigation.updateTrafficContext(),false);
  f.state.overview=overview;
  assert.equal(f.navigation.updateTrafficContext(),true);
  assert.equal(f.element('filter-node').value,'xray:6');
});

test('deleted nodes and malformed routes cannot silently load the global report', () => {
  const f=fixture('#traffic/missing');
  assert.equal(f.navigation.updateTrafficContext(),false);
  assert.equal(f.element('traffic-back').href,'#nodes');
  assert.match(f.element('traffic-status').textContent,/недоступна/);
  f.context.location.hash='#traffic/%invalid';
  assert.equal(f.navigation.updateTrafficContext(),false);
  assert.match(f.element('traffic-status').textContent,/Некорректная/);
});

test('route transitions reset scroll while background navigation keeps position', () => {
  const f=fixture('#traffic/xray%3A6');
  f.navigation.navigate({load:false});
  assert.equal(f.scroll.length,1);
  assert.equal(f.cleared(),1);
  assert.equal(f.element('breadcrumb').textContent,'VPN-трафик');
  f.navigation.navigate({load:false});
  assert.equal(f.scroll.length,1);
  f.context.location.hash='#node/xray%3A6';
  f.navigation.navigate({load:false});
  assert.equal(f.scroll.length,2);
  assert.equal(f.links.find(link=>link.dataset.page==='nodes').current,'page');
});

test('global report has a consistent title and no stale node return link', () => {
  const f=fixture('#traffic');
  f.navigation.navigate({load:false});
  assert.equal(f.navigation.updateTrafficContext(),true);
  assert.equal(f.element('traffic-back').hidden,true);
  assert.equal(f.element('breadcrumb').textContent,'VPN-трафик');
  const html=fs.readFileSync(path.join(__dirname,'../hy2bridge/web/index.html'),'utf8');
  assert.match(html,/data-page="traffic"[^\n]*VPN-трафик/);
  assert.match(html,/id="node-report"[^\n]*>VPN-трафик<\/a>/);
});
