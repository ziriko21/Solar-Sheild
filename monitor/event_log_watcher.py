import win32evtlog
from datetime import datetime
from config import EVENT_LOG_CHECK_INTERVAL, EVENT_SEVERITY
from core.logger import logger, log_event 

def start_event_log_watcher(stop_event):
    last_scan = {
        'Security': datetime.now(),
        'System': datetime.now()
    }
    
    logger.info('Event log has started')
    while not stop_event.is_set():
        stop_event.wait(EVENT_LOG_CHECK_INTERVAL)
        for channel, watched_ids in EVENT_SEVERITY.items():
            try:
                last_scan[channel] = log_channel(channel, watched_ids, last_scan)
            except PermissionError:
                continue
    logger.info('Event log has stopped')

def log_channel(channel, watched_ids, last_scan):
    handle = win32evtlog.OpenEventLog(None, channel)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_event = 0
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        for event in events:
            event_id = event.EVENTID & 0xFFFF
            if event.TimeGenerated <= last_scan or event not in watched_ids:
                continue
            severity = EVENT_SEVERITY.get(event_id, 'INFO')
            log_event(event_type="WINDOWS_EVENT", path=channel, severity=severity, extra={
                'event_id': event_id,
                'source': event.source,
                'string_inserts': event.StringInserts
            })
            last_event = event.TimeGenerated
        last_scan[channel] = last_event
    finally:
        win32evtlog.CloseEventLog(handle)
        
    return last_scan[channel]
    
        

