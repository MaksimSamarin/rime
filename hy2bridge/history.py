"""History projections preserve every sample while avoiding unused telemetry data."""
import json

CHART_FIELDS=('cpu_percent','cpu_load1','mem_available_bytes','mem_total_bytes',
              'disk_free_bytes','disk_total_bytes','online_connections')


def read_history(store, since, node=None, view='full'):
    if view not in ('full','timeline','charts'):raise ValueError('Unknown history view')
    columns='*'
    if view=='timeline':columns='node,minute,state'
    if view=='charts':
        fields=','.join("'"+key+"',json_extract(metrics,'$."+key+"')" for key in CHART_FIELDS)
        columns='node,minute,state,json_object('+fields+') AS metrics'
    sql='SELECT '+columns+' FROM fleet_health_history WHERE minute>=?';params=[since]
    if node:sql+=' AND node=?';params.append(node)
    with store.connection() as db:
        result=[]
        for row in db.execute(sql+' ORDER BY minute',params):
            item=dict(row)
            if 'metrics' in item:item['metrics']=json.loads(item['metrics'])
            result.append(item)
        return result
