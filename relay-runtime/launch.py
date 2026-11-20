"""Start the forwarding process with an explicit counter epoch."""
import argparse
import json
import os
from pathlib import Path
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--state', required=True)
parser.add_argument('--binary', required=True)
args = parser.parse_args()
directory = Path(args.state)
temporary = directory / 'boot.next.json'
temporary.write_text(json.dumps({'epoch': uuid.uuid4().hex}))
temporary.chmod(0o600)
temporary.replace(directory / 'boot.json')
os.chdir(directory)
os.execl(args.binary, args.binary, '-C', str(directory / 'gost.json'))
