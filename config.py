import os
import winreg

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

_candidate_paths = [
    os.environ.get('TEMP') or '',
    os.environ.get('LOCALAPPDATA') or '',
    os.environ.get('APPDATA') or '',
]
HIGH_PRIORITY_PATHS = [
    os.path.normpath(p)
    for p in _candidate_paths
    if p and os.path.isdir(p)
]

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.com', '.bat', '.pif', '.msi', '.msp', '.scr', '.vbs', '.js',
    '.ps1', '.wsf', '.docm', '.xlsm', '.pptm', '.doc', '.xls', '.cpl',
    '.jar', '.iso', '.img', '.vhd', '.zip', '.rar', '.7z', '.arj',
}

PROCESS_CHECK_INTERVAL = 3

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
]

PROCESS_SNAPSHOT_EVERY = 10

EVENT_LOG_CHECK_INTERVAL = 10

EVENT_SEVERITY = {
    'Security': {
        4688: 'INFO', #NEW PROCESS CREAD WITH FULL COMMAND LINE
        4624: 'INFO', #SUCCESSFUL ACCOUNT LOGIN
        4625: 'WARNING', #FAILED LOGIN ATTEMPT
        4657: 'WARNING', #REGISTRY VALUE MODIFIED
        4698: 'WARNING', #SCHEDULE TASK CREATED
        1102: 'CRITICAL', #AUDIT LOG CLEARED
        4800: 'INFO', #workstation locked (Win+L)
        4801: 'INFO' #workstation unlocked
    },
    'System': {
        7045: 'CRITICAL' #NEW SERVICE INSTALLED
    }
}

COLUMNS_TO_DROP = {
    'timestamp', 'event_type', 'severity', 'path', 'extra', 'sha256', 'file_ext'
}

SENSITIVE_LOCATIONS = {
    'in_temp':     'temp',
    'in_appdata':  'appdata',
    'in_system32': 'system32',
    'in_startup':  'startup',
    'in_programdata': 'programdata',
}