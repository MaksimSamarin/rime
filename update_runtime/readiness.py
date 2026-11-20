"""Read-only readiness of the live application, including its scheduler."""
import time

_last_tick=0.0


def register(scheduler):
    from apscheduler.schedulers.background import BackgroundScheduler
    def heartbeat():
        global _last_tick
        _last_tick=time.monotonic()
    # This one job has no database writes or counter reads. It is deliberately
    # allowed during cutover so the host can test the real scheduler executor.
    BackgroundScheduler.add_job(scheduler,heartbeat,'interval',seconds=1,
        id='rime-update-readiness',replace_existing=True,max_instances=1)


def snapshot():
    from app import scheduler,__version__,xray
    from app.db import GetDB
    from sqlalchemy import text
    from alembic.script import ScriptDirectory
    from pathlib import Path
    expected=set(ScriptDirectory(str(Path(__file__).resolve().parents[1]/'app/db/migrations')).get_heads())
    with GetDB() as db:
        revisions={row[0] for row in db.execute(text('SELECT version_num FROM alembic_version'))}
        db.execute(text('SELECT id FROM users LIMIT 1')).first()
        db.execute(text('SELECT id FROM system LIMIT 1')).first()
    migrations=bool(expected) and revisions==expected
    scheduled=bool(scheduler.running and 0<time.monotonic()-_last_tick<10)
    hub=False
    if xray.core.started:
        try:
            xray.api.get_sys_stats(timeout=1)
            hub=True
        except Exception:pass
    return {'version':__version__,'migrations':migrations,'scheduler':scheduled,
            'hub_api':hub,'ready':migrations and scheduled and hub}
