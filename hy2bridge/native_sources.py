"""Deliver a node's management source ACL through its independent HTTPS observer."""
import hashlib
import ipaddress
import json
import logging
import time

from .provision import ProvisionError


current = None


def sources_digest(sources):
    return hashlib.sha256(json.dumps(sources,separators=(',',':')).encode()).hexdigest()


class ManagementSources:
    def __init__(self,store,settings):
        self.store,self.settings=store,settings
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_native_management_sources(
                node TEXT PRIMARY KEY,revision INTEGER NOT NULL,sources TEXT NOT NULL,digest TEXT NOT NULL,
                ack_revision INTEGER NOT NULL DEFAULT 0,ack_digest TEXT NOT NULL DEFAULT '',ack_at REAL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_native_management_leases(
                node TEXT NOT NULL,entry TEXT NOT NULL,address TEXT NOT NULL,expires_at REAL NOT NULL,
                PRIMARY KEY(node,entry))''')
            db.execute('CREATE TABLE IF NOT EXISTS fleet_native_source_refresh(node TEXT PRIMARY KEY,requested_at REAL NOT NULL)')

    def desired(self,db,node):
        source=self.settings.get('control_source')
        try:sources={str(ipaddress.IPv4Address(source))}
        except (TypeError,ValueError):
            raise ProvisionError('Для защищённого управления задайте IPv4 панели в provision.control_source') from None
        tables={row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if {'fleet_tunnel_services','fleet_tunnels','fleet_relay_entries'}<=tables:
            rows=db.execute('''SELECT DISTINCT e.address FROM fleet_tunnels t
                JOIN fleet_tunnel_services s ON s.tunnel=t.id AND s.entry=t.entry
                JOIN fleet_relay_entries e ON e.id=t.entry WHERE t.node=?
                AND t.state IN ('preparing','active','needs_reconcile') AND s.kind='management'
                AND s.state IN ('preparing','active','needs_reconcile') AND e.state<>'deleted' ''',(node,))
            sources.update(str(ipaddress.IPv4Address(row['address'])) for row in rows)
        if {'fleet_relay_switches','fleet_relay_entries'}<=tables:
            rows=db.execute('''SELECT DISTINCT e.address FROM fleet_relay_switches s
                JOIN fleet_relay_entries e ON e.id=s.old_entry WHERE s.node=?
                AND s.phase IN ('prepared','installing','verified','published','grace_pending','cleanup_pending')
                AND e.state<>'deleted' ''',(node,))
            sources.update(str(ipaddress.IPv4Address(row['address'])) for row in rows)
        db.execute('DELETE FROM fleet_native_management_leases WHERE expires_at<?',(time.time(),))
        sources.update(row['address'] for row in db.execute('SELECT address FROM fleet_native_management_leases WHERE node=?',(node,)))
        if len(sources)>64:raise ProvisionError('Слишком много управляющих входов одной ноды')
        return sorted(sources)

    def refresh(self,node,entry=None,clear_leases=False):
        with self.store.connection(write=True) as db:
            if clear_leases:db.execute('DELETE FROM fleet_native_management_leases WHERE node=?',(node,))
            if entry:
                address=str(ipaddress.IPv4Address(entry['address']))
                db.execute('INSERT OR REPLACE INTO fleet_native_management_leases VALUES(?,?,?,?)',
                           (node,entry['id'],address,time.time()+900))
            sources=self.desired(db,node);digest=sources_digest(sources)
            row=db.execute('SELECT * FROM fleet_native_management_sources WHERE node=?',(node,)).fetchone()
            revision=(row['revision']+1) if row and row['digest']!=digest else row['revision'] if row else 1
            if row:
                db.execute('UPDATE fleet_native_management_sources SET revision=?,sources=?,digest=? WHERE node=?',
                           (revision,json.dumps(sources),digest,node))
            else:db.execute('INSERT INTO fleet_native_management_sources(node,revision,sources,digest) VALUES(?,?,?,?)',
                            (node,revision,json.dumps(sources),digest))
            db.execute('DELETE FROM fleet_native_source_refresh WHERE node=?',(node,))
        return {'node':node,'revision':revision,'sources':sources,'digest':digest}

    def response(self,node,ack=None):
        if not self.settings.get('control_source'):return None
        try:policy=self.refresh(node,clear_leases=self.pending(node))
        except (ProvisionError,ValueError):
            self.defer(node)
            return None
        if isinstance(ack,dict) and ack.get('revision')==policy['revision'] and ack.get('digest')==policy['digest']:
            with self.store.connection(write=True) as db:
                db.execute('UPDATE fleet_native_management_sources SET ack_revision=?,ack_digest=?,ack_at=? WHERE node=? AND revision=? AND digest=?',
                    (policy['revision'],policy['digest'],time.time(),node,policy['revision'],policy['digest']))
        return policy

    def pending(self,node):
        with self.store.connection() as db:
            return db.execute('SELECT 1 FROM fleet_native_source_refresh WHERE node=?',(node,)).fetchone() is not None

    def defer(self,node):
        with self.store.connection(write=True) as db:
            db.execute('INSERT OR REPLACE INTO fleet_native_source_refresh VALUES(?,?)',(node,time.time()))
        logging.getLogger('rime').warning('Native management source refresh deferred for %s',node)

    def wait_applied(self,policy,timeout=35):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            with self.store.connection() as db:
                row=db.execute('SELECT * FROM fleet_native_management_sources WHERE node=?',(policy['node'],)).fetchone()
            if row and row['revision']==policy['revision'] and row['digest']==policy['digest'] and row['ack_revision']==policy['revision'] and row['ack_digest']==policy['digest']:
                return True
            time.sleep(.2)
        raise ProvisionError('Наблюдатель выхода не подтвердил firewall нового входа. Публикация маршрута сохранена')
