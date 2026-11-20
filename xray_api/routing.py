"""Keep legacy internal API handlers out of public outbound selection."""

PRIVATE_BLOCK_TAG = 'RIME_PRIVATE_BLOCKED'


def protect_balancers(routing,outbounds):
    # Xray balances by tag prefix, including its internal API handler. A
    # catch-all selector must be expanded before that handler is registered.
    internal={'API',PRIVATE_BLOCK_TAG}
    for rule in routing.get('rules',[]):
        if rule.get('outboundTag')=='API' and rule.get('inboundTag')!=['API_INBOUND']:
            raise ValueError('A public routing rule cannot use a legacy management handler')
    for outbound in outbounds:
        proxy=outbound.get('proxySettings') or {}
        socket_options=(outbound.get('streamSettings') or {}).get('sockopt') or {}
        if (outbound.get('tag')=='API' or proxy.get('tag')=='API'
                or socket_options.get('dialerProxy')=='API'):
            raise ValueError('A public outbound cannot chain through a legacy management handler')
    public=[row['tag'] for row in outbounds if row.get('tag') not in internal]
    for balancer in routing.get('balancers',[]):
        if balancer.get('fallbackTag') in internal:
            raise ValueError('A public balancer cannot fall back to a management handler')
        selectors=balancer.get('selector',[])
        if not isinstance(selectors,list) or not all(isinstance(value,str) for value in selectors):
            raise ValueError('Invalid public balancer selectors')
        if not selectors or any(tag.startswith(prefix) for tag in internal for prefix in selectors):
            selected=[tag for tag in public if not selectors or any(tag.startswith(prefix) for prefix in selectors)]
            if not selected or any(tag.startswith(prefix) for tag in internal for prefix in selected):
                raise ValueError('A public balancer selector overlaps the management handler')
            balancer['selector']=selected

