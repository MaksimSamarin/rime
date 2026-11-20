"""Append already-authorized Hy2 links to sing-box and Mihomo subscriptions."""
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import re
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

import yaml


class Hy2SubscriptionError(ValueError):
    """An unsupported input, with credentials excluded from the error message."""


@dataclass(frozen=True)
class Hy2Link:
    server: str
    port: int
    password: str = field(repr=False)
    name: str
    sni: str = ''
    insecure: bool = False
    obfs: str = ''
    obfs_password: str = field(default='', repr=False)
    alpn: tuple[str, ...] = ()


def _text(value):
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Hy2SubscriptionError('Hysteria2 URI contains control characters')
    return value


def _decode(value):
    return _text(unquote_to_bytes(value).decode('utf-8', errors='strict'))


def _hostname(value):
    if not value or '%' in value:
        raise Hy2SubscriptionError('Unsupported Hysteria2 hostname')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        name = value.encode('idna').decode('ascii').lower()
        if len(name) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                       for label in name.rstrip('.').split('.')):
            raise Hy2SubscriptionError('Unsupported Hysteria2 hostname') from None
        return name


def parse_hy2_uri(uri: str) -> Hy2Link:
    """Parse one URI without dropping unknown TLS or transport parameters.

    Single ports, salamander, SNI, explicit insecure=0/1 and comma-separated
    ALPN are supported. Other extensions fail explicitly, without echoing URI.
    """
    try:
        if not isinstance(uri, str) or len(uri) > 16384 or uri != uri.strip():
            raise Hy2SubscriptionError('Invalid Hysteria2 URI')
        _text(uri)
        uri.encode('utf-8', errors='strict')
        if re.search(r'%(?![0-9a-fA-F]{2})', uri):
            raise Hy2SubscriptionError('Invalid Hysteria2 percent encoding')
        parts = urlsplit(uri)
        if parts.scheme.lower() not in {'hysteria2', 'hy2'} or parts.path not in {'', '/'}:
            raise Hy2SubscriptionError('Unsupported Hysteria2 URI scheme or path')
        if parts.netloc.count('@') != 1 or parts.netloc.endswith(':'):
            raise Hy2SubscriptionError('Hysteria2 authentication and server are required')
        password = _decode(parts.netloc.rsplit('@', 1)[0])
        if not password:
            raise Hy2SubscriptionError('Hysteria2 authentication is empty')
        server = _hostname(parts.hostname)
        port = parts.port if parts.port is not None else 443
        if not 1 <= port <= 65535:
            raise Hy2SubscriptionError('Invalid Hysteria2 port')
        parameters = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                               encoding='utf-8', errors='strict', max_num_fields=16)
        query = dict(parameters)
        supported = {'sni', 'insecure', 'obfs', 'obfs-password', 'alpn'}
        if len(query) != len(parameters) or set(query) - supported:
            raise Hy2SubscriptionError('Unsupported or repeated Hysteria2 URI parameter')
        for value in query.values():
            _text(value)
        insecure = query.get('insecure', '0')
        if insecure not in {'0', '1'}:
            raise Hy2SubscriptionError('Hysteria2 insecure must be 0 or 1')
        obfs = query.get('obfs', '')
        obfs_password = query.get('obfs-password', '')
        if obfs not in {'', 'salamander'} or bool(obfs) != bool(obfs_password):
            raise Hy2SubscriptionError('Unsupported or incomplete Hysteria2 obfuscation')
        alpn = tuple(query['alpn'].split(',')) if 'alpn' in query else ()
        if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./_-]{0,254}', item) for item in alpn):
            raise Hy2SubscriptionError('Unsupported Hysteria2 ALPN list')
        sni = _hostname(query['sni']) if query.get('sni') else ''
        fallback = f'[{server}]:{port}' if ':' in server else f'{server}:{port}'
        name = _decode(parts.fragment) or fallback
        if len(name) > 256:
            raise Hy2SubscriptionError('Hysteria2 name is too long')
        return Hy2Link(server, port, password, name, sni, insecure == '1', obfs, obfs_password, alpn)
    except Hy2SubscriptionError:
        raise
    except (ValueError, UnicodeError, TypeError, AttributeError):
        raise Hy2SubscriptionError('Invalid or unsupported Hysteria2 URI') from None


def _singbox(link):
    tls = {'enabled': True, 'insecure': link.insecure}
    if link.sni:
        tls['server_name'] = link.sni
    if link.alpn:
        tls['alpn'] = list(link.alpn)
    outbound = {'type': 'hysteria2', 'server': link.server, 'server_port': link.port,
                'password': link.password, 'tls': tls}
    if link.obfs:
        outbound['obfs'] = {'type': link.obfs, 'password': link.obfs_password}
    return outbound


def _clash(link):
    outbound = {'type': 'hysteria2', 'server': link.server, 'port': link.port,
                'password': link.password, 'skip-cert-verify': link.insecure}
    if link.sni:
        outbound['sni'] = link.sni
    if link.alpn:
        outbound['alpn'] = list(link.alpn)
    if link.obfs:
        outbound.update(obfs=link.obfs, **{'obfs-password': link.obfs_password})
    return outbound


def _append_proxy(proxies, candidate, name, label, occupied):
    for existing in proxies:
        if isinstance(existing.get(label), str) and {key: value for key, value in existing.items() if key != label} == candidate:
            return existing[label], False
    fingerprint = hashlib.sha256(json.dumps(candidate, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    tag = name
    if tag in occupied:
        for length in range(8, 65, 4):
            tag = f'{name} [hy2-{fingerprint[:length]}]'
            if tag not in occupied:
                break
        else:
            raise Hy2SubscriptionError('Hysteria2 name collision could not be resolved')
    occupied.add(tag)
    proxies.append({label: tag, **candidate})
    return tag, True


def _members(group, key):
    values = group.get(key)
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise Hy2SubscriptionError('Invalid subscription group members')
    return values


def _leaves(group, groups, member_key):
    pending = list(_members(group, member_key))
    leaves, visited = set(), set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        if name in groups:
            pending.extend(_members(groups[name], member_key))
        else:
            leaves.add(name)
    return leaves


def _extend_groups(groups, original_proxies, tags, label, member_key, modes):
    # Expand complete-catalog groups. Preserve regional subsets and relay chains.
    imported = set(tags)
    required = original_proxies - imported
    by_name = {group[label]: group for group in groups if isinstance(group.get(label), str)}
    eligible = []
    for group in groups:
        if group.get('type') not in modes:
            continue
        if group.get('include-all') or group.get('include-all-proxies'):
            continue
        excluded = str(group.get('exclude-type', '')).lower().split('|')
        if 'hysteria2' in excluded:
            continue
        leaves = _leaves(group, by_name, member_key)
        covers_catalog = required.issubset(leaves) if required else leaves.issubset(imported)
        if covers_catalog:
            eligible.append(group)
    changed = False
    for group in eligible:
        values = _members(group, member_key)
        additions = [tag for tag in tags if tag not in values]
        if additions:
            group[member_key] = [*values, *dict.fromkeys(additions)]
            changed = True
    return changed


def add_singbox_hy2(config: str, uris) -> str:
    """Append allowed links to JSON without changing existing outbound settings."""
    links = [parse_hy2_uri(uri) for uri in uris]
    if not links:
        return config
    try:
        data = json.loads(config)
        proxies = data['outbounds']
        if not isinstance(proxies, list) or not all(isinstance(item, dict) for item in proxies):
            raise TypeError()
        groups = [item for item in proxies if item.get('type') in {'selector', 'urltest'}]
        original = {item['tag'] for item in proxies if isinstance(item.get('tag'), str)
                    and item.get('type') not in {'selector', 'urltest', 'direct', 'block', 'dns'}}
        occupied = {item['tag'] for item in proxies if isinstance(item.get('tag'), str)}
        occupied.update(item['tag'] for item in data.get('endpoints', []) if isinstance(item.get('tag'), str))
        tags, changed = [], False
        for link in links:
            tag, appended = _append_proxy(proxies, _singbox(link), link.name, 'tag', occupied)
            tags.append(tag)
            changed |= appended
        changed |= _extend_groups(groups, original, tags, 'tag', 'outbounds', {'selector', 'urltest'})
        return json.dumps(data, ensure_ascii=False, indent=4) if changed else config
    except Hy2SubscriptionError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Hy2SubscriptionError('Invalid sing-box subscription structure') from None


def add_clash_hy2(config: str, uris, *, meta: bool = False) -> str:
    """Append to Mihomo YAML. Classic Clash content is returned byte-for-byte."""
    if meta is not True:
        return config
    links = [parse_hy2_uri(uri) for uri in uris]
    if not links:
        return config
    try:
        data = yaml.safe_load(config)
        if not isinstance(data, dict):
            raise TypeError()
        proxies = data.setdefault('proxies', [])
        groups = data.get('proxy-groups', [])
        if not isinstance(proxies, list) or not isinstance(groups, list) or not all(isinstance(item, dict) for item in [*proxies, *groups]):
            raise TypeError()
        original = {item['name'] for item in proxies if isinstance(item.get('name'), str)}
        occupied = original | {item['name'] for item in groups if isinstance(item.get('name'), str)}
        occupied.update({'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'})
        tags, changed = [], False
        for link in links:
            tag, appended = _append_proxy(proxies, _clash(link), link.name, 'name', occupied)
            tags.append(tag)
            changed |= appended
        changed |= _extend_groups(groups, original, tags, 'name', 'proxies', {'select', 'url-test', 'fallback', 'load-balance'})
        return yaml.safe_dump(data, allow_unicode=True, sort_keys=False) if changed else config
    except Hy2SubscriptionError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError):
        raise Hy2SubscriptionError('Invalid Mihomo subscription structure') from None
