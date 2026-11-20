"""Verify and reconcile live VLESS accounts without restarting their core."""
import time
from uuid import UUID


def supports_inbound(node, tag):
    tags=getattr(node, '_user_tags', None)
    return not (getattr(node, '_user_reconcile', False) is True and isinstance(tags, (list, tuple))) or tag in tags


def account(value):
    if not isinstance(value,dict) or set(value)-{'id','email','level','flow','encryption'}:
        raise ValueError('Unsupported VLESS account fields')
    email=value.get('email')
    level=value.get('level',0)
    flow=value.get('flow','')
    if not isinstance(email,str) or not email or type(level)!=int or not 0<=level<=4294967295:
        raise ValueError('A VLESS account requires a unique email and valid level')
    if flow not in ('','xtls-rprx-vision') or value.get('encryption','') not in ('','none'):
        raise ValueError('Unsupported VLESS account settings')
    return {'email':email,'id':str(UUID(str(value['id']))),'level':level,'flow':flow}


def accounts(values):
    result={}
    for value in values:
        item=account(value)
        if item['email'] in result:raise ValueError('Duplicate VLESS account email')
        result[item['email']]=item
    return result


def reconcile(api,config,tags,make_account):
    """Return false only for unsupported schemas/API. Uncertainty raises.

    The caller must hold the same endpoint lock as user add/remove operations
    across this call and the following verified REST acknowledgement.
    """
    if not tags or len(tags)!=len(set(tags)):return False
    inbounds={item.get('tag'):item for item in config.get('inbounds',[])}
    try:
        desired={tag:accounts(inbounds[tag]['settings'].get('clients',[])) for tag in tags
                 if inbounds[tag].get('protocol')=='vless'}
        if set(desired)!=set(tags):return False
    except (ValueError,KeyError,TypeError):
        return False
    deadline=time.monotonic()+15
    def timeout():
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ConnectionError('VLESS user synchronization deadline exceeded')
        return min(2,remaining)
    try:
        actual={tag:accounts(api.get_inbound_users(tag,timeout=timeout())) for tag in tags}
    except (NotImplementedError,ValueError):
        return False
    for tag in tags:
        for email,old in actual[tag].items():
            if desired[tag].get(email)!=old:
                limit=timeout()
                try:api.remove_inbound_user(tag,email,timeout=limit)
                except Exception:pass
        for email,wanted in desired[tag].items():
            if actual[tag].get(email)!=wanted:
                limit=timeout()
                try:api.add_inbound_user(tag,make_account(**wanted),timeout=limit)
                except Exception:pass
    try:
        confirmed={tag:accounts(api.get_inbound_users(tag,timeout=timeout())) for tag in tags}
    except Exception:
        raise ConnectionError('Live VLESS users could not be verified') from None
    if confirmed!=desired:
        raise ConnectionError('Live VLESS users differ from the controller policy') from None
    # A timed-out mutation may have committed. The final live query is decisive.
    return True
