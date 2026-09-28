"""Protocol-specific connection summaries without credentials or destinations."""
from collections import Counter
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import struct
import time


def groups(values,key,family):
    rows=[]
    for source,count in sorted(values.items(),key=lambda item:(-item[1],item[0])):
        rows.append({'key':hmac.new(key,str(source).encode(),hashlib.sha256).hexdigest()[:12],
                     'count':count,'family':family(source)})
    return rows[:50],sum(row['count'] for row in rows[50:]),len(rows)


def tcp_summary(rows,processes,key,port):
    owned=set()
    for process in processes:
        try:
            for fd in (Path(process)/'fd').iterdir():
                try:
                    target=os.readlink(fd)
                    if target.startswith('socket:['):owned.add(target[8:-1])
                except OSError:pass
        except OSError:pass
    sources=Counter();confirmed=0;seen=set()
    for family,fields in rows:
        ident=(family,fields[1],fields[2])
        if ident in seen:continue
        seen.add(ident)
        raw=fields[2].split(':')[0]
        if family==4:address=ipaddress.ip_address(struct.pack('<I',int(raw,16)))
        else:
            address=ipaddress.ip_address(b''.join(struct.pack('<I',int(raw[i:i+8],16)) for i in range(0,32,8)))
            address=address.ipv4_mapped or address
        sources[str(address)]+=1
        if len(fields)>9 and fields[9] in owned:confirmed+=1
    details,other,count=groups(sources,key,lambda value:'ipv'+str(ipaddress.ip_address(value).version))
    return {'kind':'tcp_established','observed_at':time.time(),'total':len(seen),'local_port':port,
            'unique_source_ips':count,'authenticated_users':None,'confirmed_core_sockets':confirmed,
            'unverified_owner_sockets':len(seen)-confirmed,'groups':details,'other_connections':other}


def hy2_summary(online,key):
    if not isinstance(online,dict) or not all(type(v) is int and v>=0 for v in online.values()):raise ValueError('Invalid Hy2 online map')
    active={name:value for name,value in online.items() if value>0}
    details,other,count=groups(active,key,lambda _: 'account')
    return {'kind':'hy2_client_instances','observed_at':time.time(),'total':sum(active.values()),'authenticated_users':count,
            'unique_source_ips':None,'confirmed_core_sockets':None,'unverified_owner_sockets':None,
            'groups':details,'other_connections':other}
