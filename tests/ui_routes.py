"""Exercise compatibility routes and CLI against the isolated cleanup image."""
from pathlib import Path
import json,os,subprocess,tempfile,time,urllib.request,urllib.error

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
results=[]
def check(name,value):
    assert value,name;results.append(name);print('PASS '+name,flush=True)

with tempfile.TemporaryDirectory(prefix='rime-ui-routes-') as d:
    root=Path(d)
    for suffix,alias in [('default','/dashboard/'),('custom','/control/')]:
        state=root/suffix;state.mkdir()
        env={**os.environ,'SQLALCHEMY_DATABASE_URL':'sqlite:///'+str(state/'db.sqlite3'),'DASHBOARD_PATH':alias,
             'XRAY_JSON':str(state/'xray.json'),'SUDO_USERNAME':'demo','SUDO_PASSWORD':'synthetic-test-password',
             'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':'/code','NO_PROXY':'*','no_proxy':'*',
             'HTTP_PROXY':'','HTTPS_PROXY':'','ALL_PROXY':''}
        (state/'xray.json').write_text(json.dumps({'inbounds':[{'tag':'TEST','listen':'127.0.0.1','port':16443,'protocol':'vless','settings':{'clients':[],'decryption':'none'}}],'outbounds':[{'protocol':'freedom','tag':'DIRECT'}]}))
        log=(state/'runtime.log').open('w')
        migration=subprocess.run(['python','-m','alembic','upgrade','head'],env=env,stdout=log,stderr=log)
        if migration.returncode:
            log.flush();print((state/'runtime.log').read_text()[-2000:]);raise RuntimeError('Fixture migration failed')
        process=subprocess.Popen(['python','-m','uvicorn','main:app','--host','127.0.0.1','--port','18800'],env=env,stdout=log,stderr=log)
        try:
            deadline=time.monotonic()+30
            while True:
                try:
                    with http.open('http://127.0.0.1:18800/fleet',timeout=2) as response:check(suffix+'_console_ready',b'Rime' in response.read())
                    break
                except Exception:
                    if time.monotonic()>deadline:raise
                    time.sleep(.25)
            for path in [alias.rstrip('/'),alias,alias+'users/edit']:
                try:http.open('http://127.0.0.1:18800'+path);raise AssertionError('Expected redirect')
                except urllib.error.HTTPError as error:check(suffix+'_redirect_'+path,error.code==307 and error.headers['Location']=='/fleet#users')
                try:http.open(urllib.request.Request('http://127.0.0.1:18800'+path,method='HEAD'));raise AssertionError('Expected HEAD redirect')
                except urllib.error.HTTPError as error:check(suffix+'_head_redirect_'+path,error.code==307 and error.headers['Location']=='/fleet#users' and error.read()==b'')
            for filename,mime in [('rime.svg','image/svg+xml'),('favicon.ico','image/vnd.microsoft.icon'),('favicon-32x32.png','image/png')]:
                with http.open('http://127.0.0.1:18800/statics/favicon/'+filename) as response:
                    data=response.read();check(suffix+'_icon_'+filename,bool(data) and response.headers.get_content_type() in (mime,'image/x-icon'))
            with http.open('http://127.0.0.1:18800/openapi.json') as response:
                check(suffix+'_api_preserved',json.load(response)['info']['title']=='Rime API')
        finally:
            process.terminate();process.wait(timeout=15);log.close()
    check('old_frontend_absent',not Path('/code/app/dashboard').exists())
    env.pop('CLI_PROG_NAME',None)
    for entry in ['rime-cli.py','marzban-cli.py']:
        result=subprocess.run(['python',entry,'--help'],env=env,capture_output=True,text=True,timeout=20)
        check(entry+'_compatible_help',result.returncode==0 and entry in result.stdout and 'admin' in result.stdout and 'subscription' in result.stdout)
    subprocess.run(['bash','-n','install_service.sh'],check=True)
    check('installer_shell_syntax',True)
print(json.dumps({'checks':len(results),'passed':len(results)}))
