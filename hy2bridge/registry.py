"""Dynamic node credentials and additive subscription endpoints."""
import hashlib
import hmac
import json
import time
from urllib.parse import quote


class Registry:
    def __init__(self,store):
        self.store=store
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_managed(
                id TEXT PRIMARY KEY,protocol TEXT NOT NULL,token_hash TEXT,name TEXT NOT NULL,
                domain TEXT NOT NULL,port INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 0,
                native_id INTEGER,host_id INTEGER)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_external_links(
                node TEXT PRIMARY KEY,prefix TEXT NOT NULL,suffix TEXT NOT NULL,position INTEGER NOT NULL)''')

    def authorize(self,node,header):
        with self.store.connection() as db:
            row=db.execute('SELECT token_hash FROM fleet_managed WHERE id=? AND protocol=?',(node,'hysteria2')).fetchone()
        return bool(row and row['token_hash'] and hmac.compare_digest(row['token_hash'],hashlib.sha256(header.removeprefix('Bearer ').encode()).hexdigest()) and header.startswith('Bearer '))

    def links(self,auth):
        from .access import current
        with self.store.connection() as db:
            rows=db.execute("SELECT * FROM fleet_managed WHERE protocol='hysteria2' AND active=1 ORDER BY id").fetchall()
            external=db.execute('SELECT * FROM fleet_external_links ORDER BY position,node').fetchall()
            if current:
                user=self.store.users(db).get(str(auth))
                rows=[r for r in rows if user and current.allows(user['id'],r['id'],db)]
                external=[r for r in external if user and current.allows(user['id'],r['node'],db)]
        return [r['prefix']+quote(str(auth),safe='')+r['suffix'] for r in external]+[f"hysteria2://{quote(str(auth),safe='')}@{r['domain']}:{r['port']}/?sni={r['domain']}#{quote(r['name'],safe='')}" for r in rows]

    def install_links(self):
        from app.subscription import share
        from app.models import user
        original=share.generate_v2ray_links
        def generate(proxies,inbounds,extra_data,reverse):
            links=original(proxies,inbounds,extra_data,reverse)
            for protocol,settings in proxies.items():
                if str(protocol).lower().endswith('vless'):
                    auth=getattr(settings,'id',None) or (settings.get('id') if isinstance(settings,dict) else None)
                    if auth:links+=self.links(auth)
                    break
            return links
        share.generate_v2ray_links=generate;user.generate_v2ray_links=generate

    def callbacks(self,operations,settings):
        from app import xray
        from app.db import GetDB,crud
        from app.models.node import NodeCreate
        from app.models.proxy import ProxyHost
        from app.db.models import ProxyHost as DBHost
        from app.db.models import Node as DBNode

        def register(job,d,token):
            native_id=None
            if d['protocol']=='vless':
                t=settings['vless_template']
                with GetDB() as db:
                    n=crud.create_node(db,NodeCreate(name='fleet-'+job,address=d.get('_registration_address',d['host']),port=t['service_port'],api_port=t['api_port'],add_as_new_host=False))
                    native_id=n.id
            with self.store.connection(write=True) as db:
                db.execute('INSERT INTO fleet_managed(id,protocol,token_hash,name,domain,port,native_id) VALUES(?,?,?,?,?,?,?)',
                    (job,d['protocol'],hashlib.sha256(token.encode()).hexdigest(),d['name'],d['domain'],d['vpn_port'],native_id))
            if d['protocol']=='hysteria2':operations.ensure_node(job,d['name'],address=d['host'])
            else:
                operations.observers.register_native('xray:'+str(native_id),token,d['domain'],d['vpn_port'])
                xray.operations.connect_node(native_id)
            return {'node':job if native_id is None else 'xray:'+str(native_id),'native_id':native_id}

        def unregister(job,d):
            with self.store.connection() as db:row=db.execute('SELECT * FROM fleet_managed WHERE id=?',(job,)).fetchone()
            native_id=row['native_id'] if row else None
            if d['protocol']=='vless' and native_id is None:
                with GetDB() as db:
                    owned=db.query(DBNode).filter(DBNode.name=='fleet-'+job).first()
                    if owned:native_id=owned.id
            if native_id:
                xray.operations.remove_node(native_id)
                with GetDB() as db:
                    n=crud.get_node_by_id(db,native_id)
                    if n:crud.remove_node(db,n)
                    if row and row['host_id']:
                        host=db.query(DBHost).filter(DBHost.id==row['host_id']).first()
                        if host:db.delete(host);db.commit()
                    else:
                        for host in db.query(DBHost).filter(DBHost.remark==d['name']+' ['+job+']').all():db.delete(host)
                        db.commit()
                xray.hosts.update()
            with self.store.connection(write=True) as db:
                aliases=[job]+(['xray:'+str(native_id)] if native_id else [])
                for alias in aliases:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_observers'").fetchone():db.execute('DELETE FROM fleet_observers WHERE node=?',(alias,))
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_observer_sources'").fetchone():db.execute('DELETE FROM fleet_observer_sources WHERE node=?',(alias,))
                    db.execute('DELETE FROM fleet_health WHERE node=?',(alias,))
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_health_history'").fetchone():db.execute('DELETE FROM fleet_health_history WHERE node=?',(alias,))
                db.execute('DELETE FROM fleet_managed WHERE id=?',(job,))
                db.execute('DELETE FROM fleet_inventory WHERE id=?',(job,))
                db.execute('DELETE FROM fleet_health WHERE node=?',(job,))

        def ready(job,d):
            with self.store.connection() as db:row=db.execute('SELECT * FROM fleet_managed WHERE id=?',(job,)).fetchone()
            if not row:return False
            node_id=job if d['protocol']=='hysteria2' else 'xray:'+str(row['native_id'])
            with self.store.connection() as db:health=db.execute('SELECT seen_at,data FROM fleet_health WHERE node=?',(node_id,)).fetchone()
            node={'seen_at':health['seen_at'],'metrics':json.loads(health['data'])} if health else None
            from .telemetry import complete_resources
            ok=bool(node and complete_resources(node) and not node['metrics'].get('error'))
            if node and d.get('_expected_memory') is not None:ok=ok and node['metrics'].get('mem_total_bytes')==d['_expected_memory']
            if d['protocol']=='hysteria2':ok=ok and node['metrics'].get('accounting_durable') is True
            else:ok=ok and operations.native_probe(row['native_id']) is True
            if not ok:return False
            host_id=None
            if d['protocol']=='vless' and not row['active']:
                t=settings['vless_template']
                with GetDB() as db:
                    remark=d['name']+' ['+job+']'
                    host=db.query(DBHost).filter(DBHost.remark==remark,DBHost.address==d['domain'],DBHost.port==d['vpn_port']).one_or_none()
                    if host is None:
                        crud.add_host(db,t['inbound_tag'],ProxyHost(remark=remark,address=d['domain'],port=d['vpn_port'],sni=d['domain']))
                        host=db.query(DBHost).filter(DBHost.remark==remark,DBHost.address==d['domain'],DBHost.port==d['vpn_port']).one()
                    host_id=host.id
                xray.hosts.update()
            with self.store.connection(write=True) as db:
                db.execute('UPDATE fleet_managed SET active=1,host_id=COALESCE(?,host_id) WHERE id=?',(host_id,job))
                if host_id is not None:db.execute('INSERT OR REPLACE INTO fleet_host_nodes VALUES(?,?)',(host_id,node_id))
            return True
        return register,unregister,ready
