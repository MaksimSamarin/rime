import json
import unittest
from urllib.parse import quote

import yaml

from hy2bridge.subscription_hy2 import (
    Hy2SubscriptionError,
    add_clash_hy2,
    add_singbox_hy2,
    parse_hy2_uri,
)


class SubscriptionHy2Tests(unittest.TestCase):
    def link(self, name='Sauna', host='sauna.example.com', password='test-user-id', query='sni=sauna.example.com'):
        return f'hysteria2://{quote(password, safe="")}@{host}:443/?{query}#{quote(name, safe="")}'

    def singbox(self):
        return {
            'inbounds': [{'type': 'mixed', 'tag': 'mixed', 'listen_port': 1080}],
            'outbounds': [
                {'type': 'selector', 'tag': 'proxy', 'outbounds': ['auto', 'A', 'B'], 'default': 'A'},
                {'type': 'urltest', 'tag': 'auto', 'outbounds': ['A', 'B'], 'tolerance': 50, 'url': 'https://example.com/'},
                {'type': 'selector', 'tag': 'narrow', 'outbounds': ['A']},
                {'type': 'selector', 'tag': 'only-direct', 'outbounds': ['direct']},
                {'type': 'vless', 'tag': 'A', 'server': 'a.example.com', 'server_port': 443,
                 'uuid': 'old-uuid-a', 'flow': 'xtls-rprx-vision', 'tls': {'reality': {'public_key': 'old-key'}}},
                {'type': 'vless', 'tag': 'B', 'server': 'b.example.com', 'server_port': 443, 'uuid': 'old-uuid-b'},
                {'type': 'direct', 'tag': 'direct'},
            ],
            'route': {'rules': [{'ip_is_private': True, 'outbound': 'direct'}], 'final': 'proxy'},
            'experimental': {'cache_file': {'enabled': True}},
        }

    def clash(self):
        return {
            'mode': 'rule',
            'proxies': [
                {'name': 'A', 'type': 'vless', 'server': 'a.example.com', 'port': 443, 'uuid': 'old-uuid-a',
                 'reality-opts': {'public-key': 'old-key', 'short-id': 'old-short-id'}},
                {'name': 'B', 'type': 'vless', 'server': 'b.example.com', 'port': 443, 'uuid': 'old-uuid-b'},
            ],
            'proxy-groups': [
                {'name': 'Auto', 'type': 'url-test', 'proxies': ['A', 'B'], 'url': 'https://example.com/', 'interval': 300},
                {'name': 'Proxy', 'type': 'select', 'proxies': ['Auto', 'DIRECT']},
                {'name': 'narrow', 'type': 'select', 'proxies': ['A']},
                {'name': 'relay', 'type': 'relay', 'proxies': ['A', 'B']},
                {'name': 'dynamic', 'type': 'select', 'include-all': True, 'filter': '^A$', 'proxies': ['DIRECT']},
                {'name': 'exclude', 'type': 'select', 'proxies': ['A', 'B'], 'exclude-type': 'Hysteria2'},
            ],
            'rules': ['DOMAIN-SUFFIX,example.org,DIRECT', 'MATCH,Proxy'],
            'dns': {'enable': True, 'nameserver': ['1.1.1.1']},
        }

    def test_singbox_preserves_original_settings_and_extends_complete_groups(self):
        original = self.singbox()
        result = json.loads(add_singbox_hy2(json.dumps(original), [self.link()]))
        for key in ['inbounds', 'route', 'experimental']:
            self.assertEqual(result[key], original[key])
        self.assertEqual(result['outbounds'][2:7], original['outbounds'][2:7])
        self.assertEqual(result['outbounds'][0], {**original['outbounds'][0], 'outbounds': ['auto', 'A', 'B', 'Sauna']})
        self.assertEqual(result['outbounds'][1], {**original['outbounds'][1], 'outbounds': ['A', 'B', 'Sauna']})
        self.assertEqual(result['outbounds'][-1], {
            'tag': 'Sauna', 'type': 'hysteria2', 'server': 'sauna.example.com', 'server_port': 443,
            'password': 'test-user-id', 'tls': {'enabled': True, 'insecure': False, 'server_name': 'sauna.example.com'}})

    def test_mihomo_preserves_uuid_rules_and_group_parameters(self):
        original = self.clash()
        result = yaml.safe_load(add_clash_hy2(yaml.safe_dump(original), [self.link()], meta=True))
        self.assertEqual(result['proxies'][:2], original['proxies'])
        self.assertEqual(result['rules'], original['rules'])
        self.assertEqual(result['dns'], original['dns'])
        self.assertEqual(result['proxy-groups'][2:], original['proxy-groups'][2:])
        self.assertEqual(result['proxy-groups'][0], {**original['proxy-groups'][0], 'proxies': ['A', 'B', 'Sauna']})
        self.assertEqual(result['proxy-groups'][1], {**original['proxy-groups'][1], 'proxies': ['Auto', 'DIRECT', 'Sauna']})
        self.assertEqual(result['proxies'][-1]['skip-cert-verify'], False)

    def test_both_adapters_only_add_the_acl_filtered_input(self):
        allowed = [self.link(name='allowed')]
        forbidden = 'forbidden.example.com'
        sing = add_singbox_hy2(json.dumps(self.singbox()), allowed)
        clash = add_clash_hy2(yaml.safe_dump(self.clash()), allowed, meta=True)
        self.assertIn('allowed', sing)
        self.assertIn('allowed', clash)
        self.assertNotIn(forbidden, sing)
        self.assertNotIn(forbidden, clash)
        self.assertEqual(sum(item['type'] == 'hysteria2' for item in json.loads(sing)['outbounds']), 1)
        self.assertEqual(sum(item['type'] == 'hysteria2' for item in yaml.safe_load(clash)['proxies']), 1)

    def test_repeated_uris_and_reapplication_are_idempotent(self):
        link = self.link()
        for adapter, config, options in [
            (add_singbox_hy2, json.dumps(self.singbox()), {}),
            (add_clash_hy2, yaml.safe_dump(self.clash()), {'meta': True}),
        ]:
            with self.subTest(adapter=adapter.__name__):
                first = adapter(config, [link, link], **options)
                self.assertEqual(first, adapter(first, [link, link], **options))

    def test_colliding_labels_get_deterministic_suffixes(self):
        for adapter, config, options, parse, key, label in [
            (add_singbox_hy2, json.dumps(self.singbox()), {}, json.loads, 'outbounds', 'tag'),
            (add_clash_hy2, yaml.safe_dump(self.clash()), {'meta': True}, yaml.safe_load, 'proxies', 'name'),
        ]:
            links = [self.link(name='A'), self.link(name='A', host='other.example.com')]
            first = adapter(config, links, **options)
            second = adapter(config, links, **options)
            self.assertEqual(first, second)
            names = [item[label] for item in parse(first)[key]]
            self.assertEqual(len(names), len(set(names)))
            added = [name for name in names if name.startswith('A [hy2-')]
            self.assertEqual(len(added), 2)
            self.assertEqual(first, adapter(first, links, **options))

    def test_group_and_endpoint_names_are_reserved_for_collisions(self):
        sing = self.singbox()
        sing['endpoints'] = [{'tag': 'endpoint', 'type': 'wireguard', 'private_key': 'unchanged'}]
        output = json.loads(add_singbox_hy2(json.dumps(sing), [self.link(name='proxy'), self.link(name='endpoint', host='other.example.com')]))
        self.assertEqual(output['endpoints'], sing['endpoints'])
        self.assertTrue(output['outbounds'][-2]['tag'].startswith('proxy [hy2-'))
        self.assertTrue(output['outbounds'][-1]['tag'].startswith('endpoint [hy2-'))
        clash = yaml.safe_load(add_clash_hy2(yaml.safe_dump(self.clash()), [self.link(name='Auto'), self.link(name='DIRECT', host='other.example.com')], meta=True))
        self.assertTrue(clash['proxies'][-2]['name'].startswith('Auto [hy2-'))
        self.assertTrue(clash['proxies'][-1]['name'].startswith('DIRECT [hy2-'))

    def test_unicode_ipv6_and_encoded_auth_are_preserved(self):
        password = 'юзер:п+ар@оль/?#%25'
        uri = self.link(name='Сауна 🇫🇮', host='[2001:db8::1]', password=password,
                        query='sni=sauna.example.com&alpn=h3%2Ch2&obfs=salamander&obfs-password=obfs%2Bsecret%2540')
        parsed = parse_hy2_uri(uri)
        self.assertEqual(parsed.password, password)
        self.assertEqual(parsed.server, '2001:db8::1')
        self.assertEqual(parsed.name, 'Сауна 🇫🇮')
        self.assertEqual(parsed.obfs_password, 'obfs+secret%40')
        self.assertNotIn(password, repr(parsed))
        sing = json.loads(add_singbox_hy2(json.dumps(self.singbox()), [uri]))['outbounds'][-1]
        clash = yaml.safe_load(add_clash_hy2(yaml.safe_dump(self.clash()), [uri], meta=True))['proxies'][-1]
        self.assertEqual(sing['password'], password)
        self.assertEqual(clash['password'], password)
        self.assertEqual(sing['tls']['alpn'], ['h3', 'h2'])
        self.assertEqual(clash['alpn'], ['h3', 'h2'])
        self.assertEqual(sing['obfs'], {'type': 'salamander', 'password': 'obfs+secret%40'})

    def test_userpass_and_literal_plus_are_decoded_once(self):
        self.assertEqual(parse_hy2_uri('hy2://user:pa%3Ass+word@node.example.com#name').password, 'user:pa:ss+word')
        self.assertEqual(parse_hy2_uri('hy2://user%253Apass@node.example.com#name').password, 'user%3Apass')
        self.assertEqual(parse_hy2_uri('hy2://password@node.example.com').port, 443)

    def test_insecure_is_enabled_only_when_explicitly_one(self):
        for value, expected in [('0', False), ('1', True)]:
            uri = self.link(query='insecure=' + value)
            self.assertEqual(json.loads(add_singbox_hy2(json.dumps(self.singbox()), [uri]))['outbounds'][-1]['tls']['insecure'], expected)
            self.assertEqual(yaml.safe_load(add_clash_hy2(yaml.safe_dump(self.clash()), [uri], meta=True))['proxies'][-1]['skip-cert-verify'], expected)

    def test_classic_clash_does_not_parse_or_add_hy2(self):
        original = '# classic preserved\nproxies: []\n'
        for meta in [False, None, 1, 'true']:
            self.assertEqual(add_clash_hy2(original, ['invalid-and-not-evaluated'], meta=meta), original)

    def test_empty_allowed_list_returns_original_bytes(self):
        for adapter, config, options in [
            (add_singbox_hy2, '{ "outbounds": [] }\n', {}),
            (add_clash_hy2, '# retained\nproxies: []\n', {'meta': True}),
        ]:
            self.assertEqual(adapter(config, [], **options), config)

    def test_empty_generated_groups_become_usable_for_hy2(self):
        config = {'outbounds': [{'type': 'selector', 'tag': 'proxy', 'outbounds': ['auto']},
                                {'type': 'urltest', 'tag': 'auto', 'outbounds': []},
                                {'type': 'direct', 'tag': 'direct'}]}
        result = json.loads(add_singbox_hy2(json.dumps(config), [self.link()]))
        self.assertEqual(result['outbounds'][0]['outbounds'], ['auto', 'Sauna'])
        self.assertEqual(result['outbounds'][1]['outbounds'], ['Sauna'])

    def test_existing_matching_hy2_is_reused_and_missing_group_membership_repaired(self):
        original = self.singbox()
        imported = json.loads(add_singbox_hy2(json.dumps(original), [self.link()]))['outbounds'][-1]
        original['outbounds'].append(imported)
        result = json.loads(add_singbox_hy2(json.dumps(original), [self.link()]))
        self.assertEqual(len(result['outbounds']), len(original['outbounds']))
        self.assertIn('Sauna', result['outbounds'][0]['outbounds'])
        self.assertEqual(result['outbounds'][-1], imported)

    def test_invalid_and_unsupported_uris_fail_without_echoing_secrets(self):
        password = 'top-secret-password'
        invalid = [
            f'hysteria2://{password}@node.example.com:443,8443/',
            f'hysteria2://{password}@node.example.com/?pinSHA256=abc',
            f'hysteria2://{password}@node.example.com/?ech=abc',
            f'hysteria2://{password}@node.example.com/?insecure=true',
            f'hysteria2://{password}@node.example.com/?insecure=0&insecure=1',
            f'hysteria2://{password}@node.example.com/?obfs=salamander',
            f'hysteria2://{password}@node.example.com/?obfs-password=orphan',
            f'hysteria2://{password}@node.example.com/?obfs=gecko&obfs-password=secret',
            f'hysteria2://{password}@node.example.com/?alpn=h3,,h2',
            f'hysteria2://{password}@node.example.com/?sni=bad%0Ahost',
            f'hysteria2://{password}%FF@node.example.com/',
            f'hysteria2://{password}%ZZ@node.example.com/',
            f'hysteria2://{password}@2001:db8::1/',
            f'hysteria2://{password}@[fe80::1%25eth0]/',
            f'hysteria2://{password}@node.example.com:0/',
            f'hysteria2://{password}@node.example.com/path',
            f'hysteria2://{password}@extra@node.example.com/',
            f'hysteria2://{password}@node.example.com/\n',
        ]
        for uri in invalid:
            with self.subTest(case=invalid.index(uri)):
                with self.assertRaises(Hy2SubscriptionError) as failure:
                    parse_hy2_uri(uri)
                self.assertNotIn(password, str(failure.exception))

    def test_invalid_original_config_is_rejected_without_partial_rewrite(self):
        for adapter, config, options in [
            (add_singbox_hy2, '{"outbounds":null}', {}),
            (add_singbox_hy2, 'broken', {}),
            (add_clash_hy2, 'proxies: null\n', {'meta': True}),
            (add_clash_hy2, '!!python/object:unsafe {}', {'meta': True}),
        ]:
            with self.assertRaises(Hy2SubscriptionError):
                adapter(config, [self.link()], **options)

    def test_group_cycles_are_bounded_and_preserved(self):
        original = self.singbox()
        original['outbounds'][:2] = [
            {'type': 'selector', 'tag': 'one', 'outbounds': ['two', 'A']},
            {'type': 'selector', 'tag': 'two', 'outbounds': ['one', 'B']},
        ]
        result = json.loads(add_singbox_hy2(json.dumps(original), [self.link()]))
        self.assertEqual(result['outbounds'][0]['outbounds'], ['two', 'A', 'Sauna'])
        self.assertEqual(result['outbounds'][1]['outbounds'], ['one', 'B', 'Sauna'])
