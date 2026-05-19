import winreg
from core.logger import logger, log_event
from config import RUN_KEYS

def scan_run_keys():
    total = 0
    logger.info("Registry scan has started")
    for (hive, path) in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0 
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        log_event("REGISTRY RUN KEY: ", key, severity='INFO', file_hash=None, extra=data)
                        total +=1;
                    except OSError:
                        break
            logger.info(f'Registry Scan complete. {total} entries found.')
        except PermissionError:
            logger.info("Registry scan couldn't scan due to a permission error")