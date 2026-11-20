const {test} = require('node:test');
const assert = require('node:assert/strict');
const progress = require('../hy2bridge/web/progress.js');

test('a long running phase does not report a completed operation', () => {
  const value = progress.job({state:'running', steps:[{message:'Передача проверенного образа ноды'}]});
  assert.equal(value.state,'running');
  assert.ok(value.value<value.total);
});
test('unknown or historical steps remain indeterminate', () => {
  assert.equal(progress.job({state:'running',steps:[{message:'Legacy worker operation'}]}).value,null);
});
test('only a verified successful job fills the bar', () => {
  const value=progress.job({state:'succeeded',steps:[]});
  assert.equal(value.state,'done');
  assert.equal(value.value,value.total);
});
test('rollback and error never appear as a completed installation', () => {
  for(const state of ['rolled_back','failed']) {
    const value=progress.job({state,steps:[{message:'Проверка настоящего VPN-трафика'}]});
    assert.equal(value.state,'failed');
    assert.ok(value.value<value.total);
  }
});
