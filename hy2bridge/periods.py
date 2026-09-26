"""Drain Hy2 before native period resets. An unavailable node prevents the reset."""
import functools
import json
import logging
import secrets
import sys
import threading
import time

from .store import Conflict


class Periods:
    def __init__(self,store):
        self.store=store
        self.node_ids=None
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_barriers(id TEXT PRIMARY KEY,
                auths TEXT NOT NULL,targets TEXT NOT NULL,acks TEXT NOT NULL,deadline REAL NOT NULL)''')

    def recover_after_controller_restart(self):
        # Called only after obtaining the exclusive controller file lock.
        # A native reset either committed atomically after draining, or did not.
        with self.store.connection(write=True) as db:db.execute('DELETE FROM fleet_barriers')

    def begin(self,auths,timeout=30):
        ident=secrets.token_hex(16)
        with self.store.connection(write=True) as db:
            db.execute('DELETE FROM fleet_barriers WHERE deadline<?',(time.time(),))
            if db.execute('SELECT 1 FROM fleet_barriers').fetchone():raise Conflict('Another period reset is in progress')
            known=self.node_ids() if self.node_ids else None
            targets=[r['node'] for r in db.execute('SELECT node FROM hy2_nodes') if known is None or r['node'] in known]
            db.execute('INSERT INTO fleet_barriers VALUES(?,?,?,?,?)',(ident,json.dumps(auths),json.dumps(targets),'[]',time.time()+timeout))
        return ident

    def ack(self,node,ident,seq):
        with self.store.connection(write=True) as db:
            row=db.execute('SELECT * FROM fleet_barriers WHERE id=? AND deadline>?',(ident,time.time())).fetchone()
            cursor=db.execute('SELECT seq FROM hy2_nodes WHERE node=?',(node,)).fetchone()
            if not row or node not in json.loads(row['targets']) or not cursor or cursor['seq']!=seq:
                raise Conflict('Barrier or accounting cursor does not match')
            acks=set(json.loads(row['acks']));acks.add(node)
            db.execute('UPDATE fleet_barriers SET acks=? WHERE id=?',(json.dumps(sorted(acks)),ident))
        return {'acknowledged':True}

    def complete(self,ident):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM fleet_barriers WHERE id=?',(ident,)).fetchone()
        return bool(row and row['deadline']>time.time() and set(json.loads(row['targets']))<=set(json.loads(row['acks'])))

    def end(self,ident):
        with self.store.connection(write=True) as db:db.execute('DELETE FROM fleet_barriers WHERE id=?',(ident,))

    def install(self):
        from app.db import crud
        from app import scheduler
        from fastapi import HTTPException
        reset_lock=threading.RLock();native_lock=threading.RLock()
        # Marzban 0.8.4 executes job modules without registering them in
        # sys.modules. Importing their package paths creates duplicate jobs.
        jobs=list(scheduler.get_jobs())
        record_jobs=[j for j in jobs if j.func.__name__=='record_user_usages']
        review_jobs=[j for j in jobs if j.func.__name__=='review']
        if len(record_jobs)!=1 or len(review_jobs)!=1:raise RuntimeError('Unsupported Marzban scheduler layout')
        original_record=record_jobs[0].func
        @functools.wraps(original_record)
        def record():
            with native_lock:return original_record()
        record_jobs[0].modify(func=record)

        def wrap(original,all_users=False):
            @functools.wraps(original)
            def reset(db,dbuser=None,admin=None):
                with reset_lock:
                    if all_users and dbuser is not None:admin=dbuser;dbuser=None
                    user_id=dbuser.id if dbuser is not None else None
                    owner_id=admin.id if admin is not None else None
                    with self.store.connection() as sql:
                        users=self.store.users(sql)
                    auths=[a for a,u in users.items() if (user_id is None or u['id']==user_id) and (owner_id is None or u['admin_id']==owner_id)]
                    db.rollback()
                    barrier=self.begin(auths)
                    try:
                        deadline=time.monotonic()+25
                        while not self.complete(barrier):
                            if time.monotonic()>deadline:raise HTTPException(409,'Reset deferred: a Hysteria node has not drained its durable usage')
                            time.sleep(.1)
                        with native_lock:
                            original_record()
                            db.expire_all()
                            if dbuser is not None:db.refresh(dbuser)
                            return original(db,admin=admin) if all_users else original(db,dbuser)
                    finally:self.end(barrier)
            return reset
        for name in ('reset_user_data_usage','reset_user_by_next','reset_all_users_data_usage'):
            original=getattr(crud,name);replacement=wrap(original,name=='reset_all_users_data_usage')
            # Marzban imports these functions both through crud and by name.
            for module_name,module in list(sys.modules.items()):
                if module_name.startswith('app.') and module and getattr(module,name,None) is original:
                    setattr(module,name,replacement)
            for job in jobs:
                namespace=job.func.__globals__
                if namespace.get(name) is original:namespace[name]=replacement
        # Waiting for an offline node must not stall the global expiry/limit
        # review loop and leave unrelated native VLESS users unrestricted.
        from app.db import GetDB
        from app import xray
        review_namespace=review_jobs[0].func.__globals__
        original_next=review_namespace['reset_user_by_next_report']
        pending=set();pending_lock=threading.Lock()
        def next_plan(db,user):
            user_id=user.id
            xray.operations.remove_user(user)
            with pending_lock:
                if user_id in pending or len(pending)>=2:return
                pending.add(user_id)
            def renew():
                try:
                    with GetDB() as session:
                        latest=crud.get_user_by_id(session,user_id)
                        if latest is not None and latest.next_plan is not None:original_next(session,latest)
                except Exception as exc:
                    logging.getLogger('fleet').warning('Next plan deferred for user %s (%s)',user_id,type(exc).__name__)
                finally:
                    with pending_lock:pending.discard(user_id)
            threading.Thread(target=renew,daemon=True).start()
        review_namespace['reset_user_by_next_report']=next_plan
