"""Resolve update state without interpreting database credentials as paths."""
import os
from pathlib import Path


def sqlite_database(url):
    if not isinstance(url,str) or not url.startswith('sqlite:///'):
        return None
    value=url[len('sqlite:///'):].split('?',1)[0]
    if not value or value==':memory:':
        return None
    return Path(value)


def update_directory(url, environment=None):
    environment=os.environ if environment is None else environment
    explicit=environment.get('RIME_UPDATE_DIRECTORY')
    if explicit:
        value=Path(explicit)
        if not value.is_absolute():raise ValueError('RIME_UPDATE_DIRECTORY must be absolute')
        return value
    database=sqlite_database(url)
    return (database.parent if database is not None and database.is_absolute() else Path('/var/lib/marzban'))/'.updates'
