import hashlib

from core.logger import logger


def hash_file(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
            return sha256.hexdigest()
    except OSError as exc:
        logger.warning('hash_file unreadable path=%s (%s)', path, exc)
        return 'unreadable'
