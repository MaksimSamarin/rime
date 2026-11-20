"""Preserve selected entry routes when an existing node address is edited."""
import json
import secrets

from .provision import ProvisionError


class RelayEdits:
    def __init__(self, relays):
        self.relays=relays
        self.store=relays.store

    def source(self, node):
        with self.store.connection() as database:
            source=self.relays.transfer.snapshot(node,database)
        profile=self.relays.proxies.recovery.load(node)
        if not profile.get('vpn'):raise ProvisionError('Для проверки нового адреса нужен сохранённый профиль VPN')
        return source,profile

    def prepare_native(self, dbnode, modify):
        node='xray:'+str(dbnode.id)
        before=self.relays.changes.snapshot(node)
        if before is None:return None
        address=self.relays.provision.resolve(modify.address or dbnode.address,22)[0]
        service_port=modify.port or dbnode.port
        api_port=modify.api_port or dbnode.api_port
        if address==before['tunnel']['origin'] and service_port==dbnode.port and api_port==dbnode.api_port:return None
        return self.prepare(node,'native-edit',address,{'service_port':service_port,'api_port':api_port})

    def prepare_inventory(self, node, data):
        before=self.relays.changes.snapshot(node)
        if before is None:return None
        source,profile=self.source(node)
        address=self.relays.provision.resolve(data.origin_address,22)[0] if data.origin_address else before['tunnel']['origin']
        domain=data.address or source['domain']
        port=data.vpn_port or source['vpn_port']
        if address==before['tunnel']['origin'] and domain==source['domain'] and port==source['vpn_port']:return None
        return self.prepare(node,'inventory-edit',address,domain=domain,vpn_port=port)

    def prepare(self, node, kind, address, ports=None, domain=None, vpn_port=None):
        before=self.relays.changes.snapshot(node)
        if before is None:return None
        entry=self.relays.entry(before['tunnel']['entry'])
        if address==entry['address']:raise ProvisionError('Выходной адрес совпадает со входом. Укажите реальный адрес выходной ноды')
        source,profile=self.source(node)
        if domain:source={**source,'domain':domain}
        if vpn_port:source={**source,'vpn_port':vpn_port}
        identity=secrets.token_hex(16)
        self.relays.changes.prepare(identity,node,kind)
        with self.store.connection(write=True) as database:
            database.execute('INSERT INTO fleet_relay_edits VALUES(?,?,?)',(identity,node,'prepared'))
        try:
            self.relays.changes.suspended_management.add(node)
            self.relays.changes.retarget(identity,{'address':address,'_source':source,'_profile':profile,
                '_management_ports':ports or {},'vpn_port':vpn_port})
            return {'id':identity,'node':node,'address':address,'kind':kind}
        except Exception:
            self.relays.changes.finish(identity,False)
            raise

    def mark(self, identity, execute):
        change=self.relays.changes.read(identity)
        if not change:return
        if change['phase']=='abandoned':raise ProvisionError('Изменение маршрута отменено оператором')
        after=json.loads(change['after'])
        execute('UPDATE fleet_proxy_services SET address=? WHERE node=? AND active=1',
                (after['tunnel']['origin'],change['node']))
        execute("UPDATE fleet_relay_edits SET state='succeeded' WHERE id=?",(identity,))

    def finish(self, change, accepted):
        if change:self.relays.changes.finish(change['id'],accepted)
