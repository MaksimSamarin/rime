"""Explicit publication and management endpoints for selected tunnel routes."""
from copy import deepcopy


current = None


def host(value, inbound):
    if current is None or value.get('id') is None:
        return value
    with current.store.connection() as database:
        owner = database.execute('SELECT node FROM fleet_host_nodes WHERE host_id=?', (value['id'],)).fetchone()
    if owner is None:
        return value
    return current.published_host(owner['node'], value, inbound)


def management(node, address, port, api_port):
    if current is None:
        return address, port, api_port
    if node in current.changes.suspended_management:
        return address,port,api_port
    mapping = current.endpoint_map(node)
    service = mapping.get(('management', port, 'tcp'))
    api = mapping.get(('management', api_port, 'tcp'))
    if service and api:
        return service['address'], service['public_port'], api['public_port']
    return address, port, api_port


def outbound(config, service, address):
    result = deepcopy(config)
    if result.get('_kind') == 'hy2':
        result['server'] = address + ':' + str(service['public_port'])
    else:
        endpoint = result['outbounds'][0]['settings']['vnext'][0]
        endpoint.update(address=address, port=service['public_port'])
    return result
