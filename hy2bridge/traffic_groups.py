"""Bounded chart series; detail rows and accounting totals remain unchanged."""


def grouped_chart(db, source, parameters, grouping, hours):
    if grouping not in ('node', 'tag', 'user'):
        raise ValueError('Неизвестная группировка графика')
    tagged = grouping == 'tag'
    if tagged:
        # Bind tags to the current account incarnation, never a reused id/name.
        source = '''SELECT s.*, t.value AS tag FROM (''' + source + ''') s
            LEFT JOIN users u ON u.id=s.user_id
            LEFT JOIN fleet_user_meta m ON m.user_id=u.id AND m.user_created=u.created_at
                AND ((s.protocol='xray' AND s.user_created=u.created_at) OR
                     (s.protocol='hysteria2' AND EXISTS(SELECT 1 FROM proxies p
                       WHERE p.user_id=u.id AND json_extract(p.settings,'$.id')=s.auth)))
            LEFT JOIN json_each(COALESCE(m.tags,'[]')) t ON 1=1'''
        key, label = "CASE WHEN tag IS NULL THEN 'untagged' ELSE 'tag:'||tag END", "COALESCE(tag,'Без тега')"
    elif grouping == 'user':
        key, label = "COALESCE(NULLIF(username,''),'(удалён)')", "COALESCE(NULLIF(username,''),'Удалённый пользователь')"
    else:
        key = label = 'node'
    grouped = 'SELECT '+key+' AS identity,'+label+' AS label,hour,SUM(total) AS total FROM ('+source+') GROUP BY identity,label,hour'
    # Rank in SQLite. At most six lines and 366*24 hourly values reach the UI.
    leaders = [dict(row) for row in db.execute('SELECT identity,label,SUM(total) AS total FROM ('+grouped+') GROUP BY identity,label ORDER BY total DESC,identity LIMIT 6',parameters)]
    count = db.execute('SELECT COUNT(DISTINCT identity) FROM ('+grouped+')',parameters).fetchone()[0]
    leaders = leaders[:5] if count > 6 else leaders
    keys = [row['identity'] for row in leaders]
    remapped = 'SELECT CASE WHEN identity IN ('+','.join('?' for _ in keys)+") THEN identity ELSE NULL END AS identity,hour,SUM(total) AS total FROM ("+grouped+') GROUP BY 1,hour'
    rows = db.execute(remapped,keys+parameters).fetchall()
    names = {}
    if grouping == 'node':
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'fleet_inventory' in tables:names.update({row['id']:row['name'] for row in db.execute('SELECT id,name FROM fleet_inventory')})
        if 'nodes' in tables:names.update({'xray:'+str(row['id']):row['name'] for row in db.execute('SELECT id,name FROM nodes')})
        if 'fleet_node_labels' in tables:names.update({row['node']:row['name'] for row in db.execute('SELECT node,name FROM fleet_node_labels')})
        names['xray:local']='Сервер панели'
    groups = [{'key':'g'+str(i),'label':names.get(row['identity'],row['label']),'total':row['total']} for i,row in enumerate(leaders)]
    mapping = {value:'g'+str(i) for i,value in enumerate(keys)}
    if count > 6:groups.append({'key':'other','label':'Остальные','total':0})
    series = {hour:{'hour':hour,**{row['key']:None for row in groups}} for hour in hours}
    for row in rows:
        target = mapping.get(row['identity'],'other')
        series.setdefault(row['hour'],{'hour':row['hour'],**{group['key']:None for group in groups}})[target]=row['total']
        if target=='other':groups[-1]['total']+=row['total']
    return {'chart_groups':groups,'chart_series':sorted(series.values(),key=lambda row:row['hour']),
            'chart_group_count':count,'chart_has_other':count>6,
            'chart_note':('Текущие теги: пользователь с несколькими тегами учитывается в каждом из них. Сумма линий может быть больше общего расхода. ' if tagged else '')+
                         ('Показаны 5 крупнейших групп; остальные объединены. ' if count>6 else '')+
                         'Пропуски записей показаны разрывами линий.'}
