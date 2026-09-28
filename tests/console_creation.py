"""Isolated API regression: new console users receive enabled VLESS inbounds."""
import base64,json,os,socketserver,sqlite3,sys,threading
import e2e as t

def links(user):return base64.b64decode(t.request(user['subscription_url'])).decode().splitlines()

try:
    t.save('xray.json',{'log':{'loglevel':'warning'},'inbounds':[
        {'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'tcp'}}
        for tag,port in [('VLESS_A',16443),('VLESS_B',16444)]],
        'outbounds':[{'tag':'DIRECT','protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]})
    t.save('panel.json',{'node_tokens':{},'safe_period_reset':False})
    migration=t.start('migrate',[sys.executable,'-m','alembic','upgrade','head']);assert migration.wait(timeout=40)==0
    panel,admin=t.panel('console')
    t.request('/api/admin',{'username':'labadmin','password':t.ENV['SUDO_PASSWORD'],'is_sudo':True},token=admin)
    with sqlite3.connect(t.STATE/'db.sqlite3') as db:
        for index,node in enumerate(['external-a','external-b']):
            db.execute('INSERT INTO fleet_external_links VALUES(?,?,?,?)',(node,'hysteria2://','@'+node+'.invalid:443/#'+node,index))
    body={'username':'created_all','status':'active','tags':['test-group'],'nodes':None,'data_limit':0,'expire':0,'note':'test note'}
    user=t.request('/api/fleet/users',body,token=admin)
    t.check('console_create_selects_both_vless_inbounds',set(user['inbounds']['vless'])=={'VLESS_A','VLESS_B'})
    t.check('console_create_preserves_all_nodes_and_tags',user['nodes'] is None and user['tags']==['test-group'] and user['note']=='test note')
    issued=links(user)
    t.check('new_subscription_has_native_and_both_external_hy2',sum(x.startswith('vless://') for x in issued)==2 and sum(x.startswith('hysteria2://') for x in issued)==2)
    server=socketserver.ThreadingTCPServer(('127.0.0.1',18080),t.TCP);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    for index,port in enumerate([16443,16444]):
        local=18110+index
        cfg=t.save('client'+str(index)+'.json',{'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':local,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':18080,'network':'tcp'}}],
            'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':port,'users':[{'id':user['proxies']['vless']['id'],'encryption':'none'}]}]}}]})
        t.start('client'+str(index),[t.XRAY_BINARY,'run','-c',cfg]);t.wait(lambda:t.fresh(local))
        with t.conn(local) as connection:t.check('new_user_vless_payload_'+str(index),t.echo(connection,8192))
    modified=t.request('/api/fleet/users/'+user['username'],{**body,'tags':['changed']},method='PUT',token=admin)
    t.check('edit_keeps_old_url_uuid_and_vless',links(user)==issued and modified['proxies']==user['proxies'] and modified['inbounds']==user['inbounds'])
    selected=t.request('/api/fleet/users',{'username':'created_selected','status':'active','nodes':['xray:local'],'tags':[]},token=admin)
    t.check('selected_nodes_hide_unmapped_subscription_hosts',not links(selected))
    with sqlite3.connect(t.STATE/'db.sqlite3') as db:
        for host_id, in db.execute('SELECT id FROM hosts').fetchall():
            db.execute('INSERT OR REPLACE INTO fleet_host_nodes VALUES(?,?)',(host_id,'xray:local'))
    t.check('selected_nodes_do_not_grant_unselected_hy2',len(links(selected))==2 and all(x.startswith('vless://') for x in links(selected)))
    disabled=t.request('/api/fleet/users',{'username':'created_disabled','status':'disabled','nodes':None,'tags':[]},token=admin)
    t.check('disabled_creation_has_inbounds_but_stays_disabled',disabled['status']=='disabled' and len(disabled['inbounds']['vless'])==2)
    old_uuid=user['proxies'];old_url=user['subscription_url'];t.stop(panel);panel,admin=t.panel('restarted')
    after=t.request('/api/fleet/users/'+user['username'],token=admin)
    t.check('new_user_survives_panel_restart',after['proxies']==old_uuid and links({'subscription_url':old_url})==issued)
    print(json.dumps({'checks':len(t.RESULTS),'passed':sum(x['passed'] for x in t.RESULTS)}))
finally:
    for process in reversed(t.PROCESSES):t.stop(process)
    for log in t.LOGS:log.close()
    (t.STATE/'console-creation-results.json').write_text(json.dumps(t.RESULTS,indent=2))
