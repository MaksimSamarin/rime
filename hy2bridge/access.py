"""Per-user metadata and node authorization; absent metadata preserves all-node access."""
import json
from copy import deepcopy

current = None


class Access:
    def __init__(self, store):
        self.store = store
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_user_meta(
                user_id INTEGER PRIMARY KEY, user_created TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]', nodes TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_host_nodes(
                host_id INTEGER PRIMARY KEY, node TEXT NOT NULL)''')
            db.execute('CREATE TABLE IF NOT EXISTS fleet_node_labels(node TEXT PRIMARY KEY,name TEXT NOT NULL)')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='hosts'").fetchone() and db.execute("SELECT 1 FROM sqlite_master WHERE name='nodes'").fetchone():
                native=list(db.execute('SELECT id,address FROM nodes'))
                for host in db.execute('SELECT id,address FROM hosts'):
                    addresses={a.strip() for a in (host['address'] or '').split(',') if a.strip()}
                    candidates=['xray:'+str(n['id']) for n in native if addresses=={n['address']}]
                    if addresses and addresses<={'{SERVER_IP}','{SERVER_IPV6}'}:candidates=['xray:local']
                    if len(candidates)==1:
                        db.execute('INSERT OR IGNORE INTO fleet_host_nodes VALUES(?,?)',(host['id'],candidates[0]))

    def metadata(self, uid, db=None):
        if db is None:
            with self.store.connection() as conn:return self.metadata(uid, conn)
        row = db.execute('''SELECT m.* FROM fleet_user_meta m JOIN users u
            ON u.id=m.user_id AND u.created_at=m.user_created WHERE u.id=?''', (uid,)).fetchone()
        return {'tags': json.loads(row['tags']) if row else [],
                'nodes': json.loads(row['nodes']) if row and row['nodes'] is not None else None}

    def save(self, uid, tags, nodes):
        tags = sorted(set(t.strip() for t in tags if t.strip()), key=str.casefold)
        if len(tags)>20 or any(len(t)>40 for t in tags):raise ValueError('До 20 тегов, каждый не длиннее 40 символов')
        with self.store.connection(write=True) as db:
            user = db.execute('SELECT created_at FROM users WHERE id=?',(uid,)).fetchone()
            if not user:raise ValueError('Пользователь не найден')
            db.execute('''INSERT INTO fleet_user_meta VALUES(?,?,?,?) ON CONFLICT(user_id)
                DO UPDATE SET user_created=excluded.user_created,tags=excluded.tags,nodes=excluded.nodes''',
                (uid,user['created_at'],json.dumps(tags),json.dumps(sorted(set(nodes))) if nodes is not None else None))

    def allows(self, uid, node, db=None):
        selected=self.metadata(uid,db)['nodes']
        return selected is None or node in selected

    def host_allowed(self, username, host_id):
        with self.store.connection() as db:
            user=db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
            if not user:return False
            nodes=self.metadata(user['id'],db)['nodes']
            if nodes is None:return True
            host=db.execute('SELECT node FROM fleet_host_nodes WHERE host_id=?',(host_id,)).fetchone()
            if not host:
                host=db.execute("SELECT 'xray:'||native_id AS node FROM fleet_managed WHERE host_id=?",(host_id,)).fetchone()
            return bool(host and host['node'] in nodes)

    def filtered_config(self, config, node):
        copy=deepcopy(config)
        with self.store.connection() as db:
            for inbound in copy.get('inbounds',[]):
                settings=inbound.get('settings',{})
                if 'clients' in settings:
                    def allowed(client):
                        email=client.get('email','')
                        if not email.split('.',1)[0].isdigit():return True
                        return self.allows(int(email.split('.',1)[0]),node,db)
                    settings['clients']=[c for c in settings['clients'] if allowed(c)]
        return copy


def allows(uid,node):
    from .quotas import blocked
    return not blocked(node) and (current is None or current.allows(uid,node))


def filter_config(config,node):
    from .quotas import filter_config as quota_filter
    return quota_filter(current.filtered_config(config,node) if current else config,node)


def host_allowed(username,host_id):
    return current is None or current.host_allowed(username,host_id)
