"""Independent client-vantage observations. Resource heartbeats cannot populate them."""
import hmac
import ipaddress
import json
import time


class Reachability:
    def __init__(self, store, entries=()):
        self.store=store
        self.entries={entry['id']:entry for entry in entries}
        for entry in entries:
            if not isinstance(entry.get('token'),str) or len(entry['token'])<32:
                raise ValueError('A separate client-probe credential is required')
            if not isinstance(entry.get('nodes'),list) or not entry.get('label'):
                raise ValueError('Client probe requires a named origin and explicit node scope')
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_client_probes(
                node TEXT NOT NULL,probe TEXT NOT NULL,received_at REAL NOT NULL,
                checked_at REAL NOT NULL,data TEXT NOT NULL,PRIMARY KEY(node,probe))''')
            db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_client_probe_inventory_delete
                AFTER DELETE ON fleet_inventory BEGIN DELETE FROM fleet_client_probes WHERE node=OLD.id; END''')
            db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_client_probe_inventory_move
                AFTER UPDATE OF address ON fleet_inventory BEGIN DELETE FROM fleet_client_probes WHERE node=OLD.id; END''')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='nodes'").fetchone():
                db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_client_probe_native_delete
                    AFTER DELETE ON nodes BEGIN DELETE FROM fleet_client_probes WHERE node='xray:'||OLD.id; END''')
                db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_client_probe_native_move
                    AFTER UPDATE OF address,port,api_port ON nodes BEGIN DELETE FROM fleet_client_probes WHERE node='xray:'||OLD.id; END''')

    def authorize(self, probe, node, header):
        if not isinstance(header,str) or not header.isascii():return False
        entry=self.entries.get(probe)
        return bool(entry and node in entry['nodes'] and hmac.compare_digest(header,'Bearer '+entry['token']))

    def ingest(self, probe, node, value, guard=None):
        if probe not in self.entries or node not in self.entries[probe]['nodes']:
            raise ValueError('Node is outside probe scope')
        return self._ingest(probe,node,value,self.entries[probe]['label'],guard)

    def ingest_local(self,node,value,origin,guard=None,job=None):
        def owned(db):
            managed=db.execute("SELECT id FROM fleet_managed WHERE id=? OR 'xray:'||native_id=?",(node,node)).fetchone()
            if not managed or (job is not None and managed['id']!=job):
                raise ValueError('Managed node registration changed')
            if guard:guard(db)
        return self._ingest('panel-managed',node,value,origin,owned)

    def _ingest(self,probe,node,value,origin,guard=None):
        now=time.time()
        if not now-120<=value['checked_at']<=now+15:
            raise ValueError('Probe timestamp is outside the allowed window')
        if value.get('target_ip') is None:
            if value['passed'] or value['stage']!='configuration':
                raise ValueError('A target IP is required for network observations')
        else:
            ipaddress.ip_address(value['target_ip'])
        if value['passed'] and value['stage']!='payload':
            raise ValueError('A successful probe requires verified payload')
        data={**value,'origin':origin}
        with self.store.connection(write=True) as db:
            if guard:guard(db)
            native=node.startswith('xray:') and node[5:].isdigit()
            exists=db.execute('SELECT 1 FROM nodes WHERE id=?',(int(node[5:]),)).fetchone() if native else db.execute('SELECT 1 FROM fleet_inventory WHERE id=?',(node,)).fetchone()
            if not exists:raise ValueError('Node registration was removed')
            old=db.execute('SELECT checked_at FROM fleet_client_probes WHERE node=? AND probe=?',(node,probe)).fetchone()
            if old and old['checked_at']>value['checked_at']:raise ValueError('Stale probe result')
            db.execute('''INSERT INTO fleet_client_probes VALUES(?,?,?,?,?) ON CONFLICT(node,probe)
                DO UPDATE SET received_at=excluded.received_at,checked_at=excluded.checked_at,data=excluded.data''',
                (node,probe,now,value['checked_at'],json.dumps(data)))
            # One open incident per node; repeated failures update its counter.
            incident=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='client_unreachable' AND resolved_at IS NULL",(node,)).fetchone()
            # Clients of a node behind an entry server get the entry address. The per-minute route
            # check through the entry owns that node's client events (relay_client_unreachable);
            # the direct-address probe stays visible in the card but no longer raises an incident.
            tunnelled=db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_tunnels'").fetchone() is not None and                 db.execute("SELECT 1 FROM fleet_tunnels WHERE node=? AND state='active'",(node,)).fetchone() is not None
            if tunnelled:
                if incident:db.execute('UPDATE fleet_events SET resolved_at=?,last_at=? WHERE id=?',(now,now,incident['id']))
            elif value['passed'] and incident:
                db.execute('UPDATE fleet_events SET resolved_at=?,last_at=? WHERE id=?',(now,now,incident['id']))
            elif not value['passed'] and value['stage'] not in ('configuration','route'):
                if incident:db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(now,incident['id']))
                else:db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'client_unreachable','error',?,?)",(node,now,now))
        return {'received':True}

    def summary(self, db, node):
        rows=db.execute('SELECT * FROM fleet_client_probes WHERE node=? ORDER BY checked_at DESC',(node,)).fetchall()
        local=False
        if any(row['probe']=='panel-managed' for row in rows):
            local=db.execute("SELECT 1 FROM fleet_managed WHERE id=? OR 'xray:'||native_id=?",(node,node)).fetchone() is not None
        row=next((r for r in rows if (local and r['probe']=='panel-managed') or (r['probe'] in self.entries and node in self.entries[r['probe']]['nodes'])),None)
        if not row:return {'state':'unknown','origin':None,'checked_at':None,'fresh':False}
        data=json.loads(row['data']);fresh=time.time()-row['checked_at']<=180
        state=('available' if data['passed'] else 'unavailable') if fresh and data['stage'] not in ('configuration','route') else 'unknown'
        return {**data,'state':state,'fresh':fresh,'age_seconds':max(0,round(time.time()-row['checked_at'],1))}
