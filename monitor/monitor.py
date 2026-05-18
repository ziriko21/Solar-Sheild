import winreg
from config import REGISTRY_RUN_KEYS
from core.logger import logger, log_event

def scan_registry_baseline():
    for (key_path, hive_string) in REGISTRY_RUN_KEYS:
        
        ...
