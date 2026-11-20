"""Atomically accept cumulative native counters without destructive RPC reads."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import hashlib
import json
import threading
import weakref

from sqlalchemy import (BigInteger, Column, DateTime, Integer, MetaData, String,
                        Table, Text, and_, delete, exists, func, insert, select, text, update)

from app.db import GetDB
from app.db.models import Admin, Node, NodeUsage, NodeUserUsage, System, User


metadata = MetaData()
cursors = Table('fleet_native_usage_cursors', metadata,
    Column('node_id', Integer, primary_key=True),
    Column('epoch', String(64), primary_key=True),
    Column('kind', String(8), primary_key=True),
    Column('stat_key', String(64), primary_key=True),
    Column('stat', Text, nullable=False),
    Column('value', BigInteger, nullable=False),
    Column('seen_at', DateTime, nullable=False))
remainders = Table('fleet_native_usage_remainders', metadata,
    Column('node_id', Integer, primary_key=True),
    Column('identity', String(64), primary_key=True),
    Column('user_id', Integer, nullable=False),
    Column('username', String(34), nullable=False),
    Column('remainder', String(128), nullable=False),
    Column('seen_at', DateTime, nullable=False))
_schema_lock = threading.Lock()
_prepared_engines = weakref.WeakSet()


def uses_cumulative_usage(api):
    value = getattr(api, 'usage_epoch', None)
    return callable(value) or isinstance(value, str) and bool(value.strip())


def _epoch(api):
    value = api.usage_epoch
    value = value() if callable(value) else value
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError('The native counter epoch is unavailable')
    return value


def _schema(engine):
    with _schema_lock:
        if engine not in _prepared_engines:
            metadata.create_all(engine)
            _prepared_engines.add(engine)


def _snapshot(api, kind):
    epoch = _epoch(api)
    query = api.get_users_stats if kind == 'users' else api.get_outbounds_stats
    values = list(query(reset=False, timeout=30 if kind == 'users' else 10))
    if _epoch(api) != epoch:
        raise ValueError('The native core changed during counter collection')
    result = {}
    for stat in values:
        if not isinstance(stat.name, str) or stat.link not in ('uplink', 'downlink'):
            raise ValueError('The native counter identity is invalid')
        if type(stat.value) is not int or not 0 <= stat.value <= 2**63-1:
            raise ValueError('The native counter value is invalid')
        identity = json.dumps([stat.name, stat.link], ensure_ascii=False, separators=(',', ':'))
        if identity in result:
            raise ValueError('The native counter snapshot contains duplicate identities')
        result[identity] = (stat.name, stat.link, stat.value)
    return hashlib.sha256(epoch.encode()).hexdigest(), result


def _deltas(db, node_id, epoch, kind, samples, now):
    result = defaultdict(int)
    for identity, (name, direction, value) in samples.items():
        key = hashlib.sha256(identity.encode()).hexdigest()
        condition = and_(cursors.c.node_id == node_id, cursors.c.epoch == epoch,
                         cursors.c.kind == kind, cursors.c.stat_key == key)
        previous = db.execute(select(cursors).where(condition)).mappings().first()
        if previous and previous['stat'] != identity:
            raise ValueError('The native counter identity conflicts with its cursor')
        old = previous['value'] if previous else 0
        delta = value-old if value >= old else value
        result[name if kind == 'users' else direction] += delta
        if previous:
            db.execute(update(cursors).where(condition).values(value=value, seen_at=now))
        else:
            db.execute(insert(cursors).values(node_id=node_id, epoch=epoch, kind=kind,
                stat_key=key, stat=identity, value=value, seen_at=now))
    return result


def _user_history(db, node_id, user_id, amount, hour):
    table = NodeUserUsage.__table__
    condition = and_(table.c.node_id == node_id, table.c.user_id == user_id, table.c.created_at == hour)
    if db.execute(select(table.c.id).where(condition)).first() is None:
        db.execute(insert(table).values(node_id=node_id, user_id=user_id, created_at=hour, used_traffic=0))
    db.execute(update(table).where(condition).values(used_traffic=func.coalesce(table.c.used_traffic, 0)+amount))


def _charge_users(db, node_id, values, factor, history, now):
    total = 0
    table = User.__table__
    for email, delta in sorted(values.items()):
        prefix, separator, username = email.partition('.')
        if not delta or not separator or not prefix.isdigit() or not 0 < int(prefix) < 2**63:
            continue
        user_id = int(prefix)
        user = db.execute(select(table.c.id, table.c.username, table.c.admin_id)
            .where(table.c.id == user_id).with_for_update()).mappings().first()
        if user is None or user['username'] != username:
            continue
        identity = hashlib.sha256(email.encode()).hexdigest()
        condition = and_(remainders.c.node_id == node_id, remainders.c.identity == identity)
        previous = db.execute(select(remainders).where(condition)).mappings().first()
        with localcontext() as context:
            context.prec = 80
            weighted = Decimal(delta)*factor + Decimal(previous['remainder'] if previous else '0')
            amount = int(weighted)
            remainder = str(weighted-amount)
        if amount > 2**63-1:
            raise ValueError('The weighted native usage exceeds the stored counter range')
        saved = {'user_id':user_id, 'username':username, 'remainder':remainder, 'seen_at':now}
        if previous:
            db.execute(update(remainders).where(condition).values(**saved))
        else:
            db.execute(insert(remainders).values(node_id=node_id, identity=identity, **saved))
        db.execute(update(table).where(and_(table.c.id == user_id, table.c.username == username))
            .values(used_traffic=func.coalesce(table.c.used_traffic, 0)+amount, online_at=now))
        if history:
            _user_history(db, node_id, user_id, amount, now.replace(minute=0, second=0, microsecond=0))
        if not amount:
            continue
        if user['admin_id'] is not None:
            admins = Admin.__table__
            db.execute(update(admins).where(admins.c.id == user['admin_id'])
                .values(users_usage=func.coalesce(admins.c.users_usage, 0)+amount))
        total += amount
    return total


def _charge_outbounds(db, node_id, values, history, now):
    up, down = values['uplink'], values['downlink']
    if not (up or down):
        return 0
    system = System.__table__
    if db.execute(select(system.c.id)).first() is None:
        db.execute(insert(system).values(id=1, uplink=0, downlink=0))
    db.execute(update(system).values(uplink=func.coalesce(system.c.uplink, 0)+up,
                                     downlink=func.coalesce(system.c.downlink, 0)+down))
    if history:
        table = NodeUsage.__table__
        hour = now.replace(minute=0, second=0, microsecond=0)
        condition = and_(table.c.node_id == node_id, table.c.created_at == hour)
        if db.execute(select(table.c.id).where(condition)).first() is None:
            db.execute(insert(table).values(node_id=node_id, created_at=hour, uplink=0, downlink=0))
        db.execute(update(table).where(condition).values(uplink=func.coalesce(table.c.uplink, 0)+up,
                                                        downlink=func.coalesce(table.c.downlink, 0)+down))
    return up+down


def _prune(db, node_id, epoch, now):
    cutoff = now-timedelta(days=90)
    db.execute(delete(cursors).where(and_(cursors.c.node_id == node_id,
        cursors.c.epoch != epoch, cursors.c.seen_at < cutoff)))
    node_exists = exists(select(Node.__table__.c.id).where(Node.__table__.c.id == cursors.c.node_id))
    db.execute(delete(cursors).where(~node_exists))
    users = User.__table__
    owner_exists = exists(select(users.c.id).where(and_(users.c.id == remainders.c.user_id,
                                                       users.c.username == remainders.c.username)))
    db.execute(delete(remainders).where(and_(remainders.c.seen_at < cutoff, ~owner_exists)))
    remainder_node_exists = exists(select(Node.__table__.c.id)
                                  .where(Node.__table__.c.id == remainders.c.node_id))
    db.execute(delete(remainders).where(~remainder_node_exists))


def record_native_usage(api, node_id, kind, coefficient=1, history=True):
    """Query and commit one qualified core snapshot under its physical-node lock."""
    if kind not in ('users', 'outbound') or type(node_id) is not int:
        raise ValueError('The native usage scope is invalid')
    factor = Decimal(str(coefficient))
    if not factor.is_finite() or factor < 0:
        raise ValueError('The native usage coefficient must be finite and nonnegative')
    with api.control_lock, GetDB() as db:
        _schema(db.get_bind())
        nodes = Node.__table__
        if db.get_bind().dialect.name == 'mysql':
            # MySQL serializes collection on the node row without locking the
            # whole database while its read-only RPC is in flight.
            present = db.execute(select(nodes.c.id).where(nodes.c.id == node_id).with_for_update()).first()
            if present is None:
                return {'charged':0, 'counters':0}
            epoch, samples = _snapshot(api, kind)
        else:
            epoch, samples = _snapshot(api, kind)
            if db.get_bind().dialect.name == 'sqlite':
                db.execute(text('BEGIN IMMEDIATE'))
            if db.execute(select(nodes.c.id).where(nodes.c.id == node_id).with_for_update()).first() is None:
                return {'charged':0, 'counters':0}
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            values = _deltas(db, node_id, epoch, kind, samples, now)
            charged = (_charge_users(db, node_id, values, factor, history, now) if kind == 'users'
                       else _charge_outbounds(db, node_id, values, history, now))
            _prune(db, node_id, epoch, now)
            db.commit()
            return {'charged':charged, 'counters':len(samples)}
        except BaseException:
            db.rollback()
            raise
