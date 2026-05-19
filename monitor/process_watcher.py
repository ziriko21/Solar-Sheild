import psutil
from config import PROCESS_CHECK_INTERVAL, PROCESS_SNAPSHOT_EVERY
from core.logger import logger, log_event

def start_process_watcher(stop_event):
    logger.info('Process watcher starting...')
    log_system_snapshot()
    watch_processes(stop_event)
    logger.info('Process watcher stopped.')

def get_process_snapshot():
    snapshot = {}
    data = ['pid', 'name', 'exe', 'ppid']
    for proc in psutil.process_iter(data):
        try:
            info = proc.info
            snapshot[info['pid']] = {
                'name': info['name'],
                'exe': info['exe'],
                'ppid': info['ppid']
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return snapshot

def log_system_snapshot():
    cpu_percent = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    totalGB = round(ram.total/1024**3, 2)
    usedGB = round(ram.used/1024**3, 2)

    log_event('SYSTEM_SNAPSHOT', path='system', severity='INFO', extra={
        'cpu_percent': cpu_percent,
        'ram_percent': ram.percent,
        'ram_used_gb': usedGB,
        'ram_total_gb': totalGB
    })

def watch_processes(stop_event):
    known_state = get_process_snapshot()
    for pid, info in known_state.items():
        log_event('PROCESS_BASELINE', info['name'], severity='DEBUG', extra={
            'pid': pid,
            'exe': info['exe'],
            'ppid': info['ppid']
        })
    cycle = 0 
    while not stop_event.is_set():
        stop_event.wait(PROCESS_CHECK_INTERVAL)
        current_state = get_process_snapshot()
        log_new_pids(current_state, known_state)
        log_ended_pids(current_state, known_state)
        cycle +=1
        if cycle >= PROCESS_SNAPSHOT_EVERY:
            log_event('PROCESS_SNAPSHOT', 'system', severity='DEBUG', extra={
                'processes': [
                    {'pid':pid, 'name':info['name']}
                    for pid, info in current_state.items()
                ]
            })
            cycle = 0
        known_state = current_state
        
def log_new_pids(current_state, known_state):
    new_pids = current_state.keys() - known_state.keys()
    for pid in new_pids:
        info = current_state[pid]
        log_event('PROCESS_STARTED', info['name'], severity='WARNING', extra={
            'pid': pid,
            'exe': info['exe'],
            'ppid': info['ppid']
        })

def log_ended_pids(current_state, known_state):
    ended_pids = known_state.keys() - current_state.keys()
    for pid in ended_pids:
        info = known_state[pid]
        log_event('PROCESS_ENDED', info['name'], severity='INFO', extra={
            'pid': pid,
            'exe': info['exe']
        })

