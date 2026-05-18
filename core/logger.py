import json
import logging
import os
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

_today = datetime.now().strftime('%Y-%m-%d')
log_filename = os.path.join(LOG_DIR, f'{_today}_akame.log')
JSONL_FILE = os.path.join(LOG_DIR, f'{_today}_events.jsonl')

_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s')

logger = logging.getLogger('akame')
logger.setLevel(logging.DEBUG)
logger.handlers.clear()
logger.addHandler(logging.FileHandler(log_filename, encoding='utf-8'))
logger.addHandler(logging.StreamHandler())
for _h in logger.handlers:
    _h.setFormatter(_formatter)
logger.propagate = False

_jsonl_lock = threading.Lock()


def log_event(event_type, path, severity='INFO', file_hash=None, extra=None):
    entry = {
        'timestamp': str(datetime.now()),
        'event_type': event_type,
        'severity': severity,
        'path': path,
        'sha256': file_hash,
        'extra': extra,
    }
    line = json.dumps(entry) + '\n'
    with _jsonl_lock:
        with open(JSONL_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
    log_fn = getattr(logger, severity.lower(), logger.info)
    log_fn(f'[{event_type}] {path}')
