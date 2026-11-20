"""Keep scheduled controller writes and destructive reads outside cutover."""
from datetime import datetime,timedelta,timezone
from functools import wraps

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.util import ref_to_obj

from .leases import acquire
import os


class CoordinatedScheduler(BackgroundScheduler):
    def __init__(self,*args,directory,**kwargs):
        self.update_directory=directory
        super().__init__(*args,**kwargs)

    def add_job(self,func,*args,**kwargs):
        original=ref_to_obj(func) if isinstance(func,str) else func
        trigger=args[0] if args else kwargs.get('trigger')
        once=trigger is None or trigger=='date' or isinstance(trigger,DateTrigger)

        @wraps(original)
        def coordinated(*values,**named):
            try:
                descriptor=acquire(self.update_directory)
            except BlockingIOError:
                if once:
                    self.add_job(original,'date',run_date=datetime.now(timezone.utc)+timedelta(seconds=1),
                        args=values,kwargs=named,id=kwargs.get('id'),replace_existing=True)
                return None
            try:return original(*values,**named)
            finally:os.close(descriptor)

        return super().add_job(coordinated,*args,**kwargs)
