import asyncio
import gzip
import unittest
from hy2bridge.http import FleetGZipMiddleware


class FleetHTTPTests(unittest.TestCase):
    def response(self,path,method='GET'):
        body=b'{"value":"'+b'x'*2000+b'"}'
        async def app(scope,receive,send):
            await send({'type':'http.response.start','status':200,'headers':[(b'content-type',b'application/json'),(b'content-length',str(len(body)).encode())]})
            await send({'type':'http.response.body','body':body})
        async def execute():
            messages=[]
            async def receive():return {'type':'http.request','body':b''}
            async def send(value):messages.append(value)
            await FleetGZipMiddleware(app,minimum_size=1024,compresslevel=5)(
                {'type':'http','method':method,'path':path,'headers':[(b'accept-encoding',b'gzip')]},receive,send)
            return messages
        messages=asyncio.run(execute());headers=dict(messages[0]['headers']);data=b''.join(m.get('body',b'') for m in messages[1:])
        return body,headers,data

    def test_large_console_response_decodes_to_identical_data(self):
        original,headers,data=self.response('/api/fleet/monitoring')
        self.assertEqual(headers[b'content-encoding'],b'gzip');self.assertEqual(gzip.decompress(data),original)
        self.assertLess(len(data),len(original))

    def test_subscriptions_and_agent_posts_are_outside_compression(self):
        for path,method in [('/sub/synthetic','GET'),('/api/fleet/client-probes/home/n1','POST'),('/api/hy2/nodes/n1/policy','GET')]:
            original,headers,data=self.response(path,method)
            self.assertNotIn(b'content-encoding',headers);self.assertEqual(data,original)
