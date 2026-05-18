import os

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

REGISTRY_RUN_KEYS = [
    (r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU'),
    (r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM'),
]

PROCESS_SNAPSHOT_EVERY = 10

WATCHED_EVENT_IDS = {
    'Security': [4688, 4624, 4625, 4657, 4698, 1102],
    'System': [7045],
}
EVENT_LOG_CHECK_INTERVAL = 10
