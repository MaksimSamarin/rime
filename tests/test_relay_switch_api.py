"""Exercise the sudo-only switch contract through the real FastAPI routes."""
import asyncio
import json
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, Header, HTTPException

from hy2bridge.provision import ProvisionError
from hy2bridge.relay_api import install


class RelaySwitchApiTests(unittest.TestCase):
    def setUp(self):
        def require_sudo(role: str | None = Header(default=None, alias='X-Test-Role')):
            if role != 'sudo':
                raise HTTPException(403, 'Administrator access is required')
            return SimpleNamespace(username='fixture-admin')

        admin = ModuleType('app.models.admin')
        admin.Admin = SimpleNamespace(check_sudo_admin=require_sudo)
        modules = {'app':ModuleType('app'), 'app.models':ModuleType('app.models'),
                   'app.models.admin':admin}
        self.modules = patch.dict(sys.modules, modules)
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.plan = Mock(return_value={'id':'c'*32, 'kind':'route-switch', 'ready':True})
        self.service = SimpleNamespace(switches=SimpleNamespace(plan=self.plan),
                                       deploy=Mock(return_value={'id':'c'*32}))
        application = FastAPI()
        install(application, self.service)
        self.application = application
        self.headers = {'X-Test-Role':'sudo'}
        self.url = '/api/fleet/relays/routes/' + 'a'*32 + '/switch/plan'

    def post(self, path, payload, headers=None):
        messages = []
        body = json.dumps(payload).encode()

        async def receive():
            return {'type':'http.request', 'body':body, 'more_body':False}

        async def send(message):
            messages.append(message)

        scope = {'type':'http', 'asgi':{'version':'3.0'}, 'http_version':'1.1',
                 'method':'POST', 'scheme':'http', 'path':path, 'raw_path':path.encode(),
                 'query_string':b'', 'client':('127.0.0.1',12345), 'server':('fixture',80),
                 'headers':[(b'content-type',b'application/json'),
                            *[(key.lower().encode(),value.encode()) for key,value in (headers or {}).items()]]}
        asyncio.run(self.application(scope, receive, send))
        raw = b''.join(message.get('body',b'') for message in messages[1:])
        return SimpleNamespace(status_code=messages[0]['status'], json=lambda:json.loads(raw))

    def test_switch_planning_requires_sudo(self):
        response = self.post(self.url, {'entry':'b'*32})
        self.assertEqual(response.status_code, 403)
        self.plan.assert_not_called()

    def test_selected_route_and_entry_reach_the_switch_planner(self):
        response = self.post(self.url, {'entry':'b'*32}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['kind'], 'route-switch')
        self.plan.assert_called_once_with('a'*32, 'b'*32)
        deployment = self.post('/api/fleet/relays/deploy', {'plan_id':response.json()['id']},
                               headers=self.headers)
        self.assertEqual(deployment.status_code, 200)
        self.service.deploy.assert_called_once_with('c'*32)

    def test_invalid_entry_is_rejected_before_planning(self):
        response = self.post(self.url, {'entry':'invalid-entry'}, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.plan.assert_not_called()

    def test_stale_route_is_a_reviewable_conflict(self):
        self.plan.side_effect = ProvisionError('Маршрут изменился. Повторите проверку')
        response = self.post(self.url, {'entry':'b'*32}, headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['detail'], 'Маршрут изменился. Повторите проверку')
        self.service.deploy.assert_not_called()


if __name__ == '__main__':
    unittest.main()
