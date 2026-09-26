"""Restore an offline SQLite snapshot, then roll back to the stock panel."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.request

source=Path('/lab/release/e2e6');target=Path('/lab/release/recovery')
target.mkdir(exist_ok=False)
with sqlite3.connect(source/'db.sqlite3') as src:
    with sqlite3.connect(target/'db.sqlite3') as dst:src.backup(dst)
proof=json.loads((source/'restore-proof.json').read_text())
env=dict(os.environ,PYTHONPATH='/lab/release/source:/code',
    SQLALCHEMY_DATABASE_URL='sqlite:///'+str(target/'db.sqlite3'),XRAY_JSON=str(source/'xray.json'),
    XRAY_EXECUTABLE_PATH='/lab/bin/xray',HY2_PANEL_CONFIG=str(source/'panel.json'))
http=urllib.request.build_opener(urllib.request.ProxyHandler({}));results=[]
for name,entry in [('restored_extended','panel_entry:app'),('rollback_stock','main:app')]:
    with (target/(name+'.log')).open('w') as log:
        proc=subprocess.Popen([sys.executable,'-m','uvicorn',entry,'--host','127.0.0.1','--port','18800'],env=env,cwd='/code',stdout=log,stderr=log)
        try:
            deadline=time.monotonic()+30
            while True:
                try:
                    with http.open('http://127.0.0.1:18800'+proof['old_url'],timeout=2) as response:body=response.read()
                    break
                except Exception:
                    if time.monotonic()>deadline:raise RuntimeError('Restored panel not ready')
                    time.sleep(.2)
            ok=body==base64.b64decode(proof['payload'])
            results.append({'name':name+'_old_subscription','passed':ok});assert ok
        finally:
            proc.terminate()
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
with sqlite3.connect(target/'db.sqlite3') as db:
    ok=db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    results.append({'name':'restored_database_integrity','passed':ok});assert ok
(target/'results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results),flush=True)
