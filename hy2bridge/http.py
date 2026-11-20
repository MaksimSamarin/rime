"""Compression is limited to console GET responses, outside subscription transport."""
from starlette.middleware.gzip import GZipMiddleware


class FleetGZipMiddleware(GZipMiddleware):
    async def __call__(self, scope, receive, send):
        if scope['type']=='http' and scope.get('method')=='GET' and scope.get('path','').startswith('/api/fleet/'):
            await super().__call__(scope,receive,send)
        else:
            await self.app(scope,receive,send)
