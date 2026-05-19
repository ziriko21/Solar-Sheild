import threading
from core.logger import logger
from monitor.registry_scan import scan_run_keys
from monitor.file_watcher import start_file_watcher
from monitor.process_watcher import start_process_watcher
from monitor.event_log_watcher import start_event_log_watcher

def main():
    logger.info("Solar Sheild monitor is online.")
    stop_event = threading.Event()
    i = 0
    thread_functions = {
        (start_file_watcher, 'FileWatcher'),
        (start_process_watcher, 'ProcessWatcher'),
        (start_event_log_watcher, 'EventWatcher')
    }

    scan_run_keys()
    threads = []
    for function, name in thread_functions:
        t = threading.Thread(
            target=function,
            args=(stop_event,),
            daemon=True,
            name=name
        )
        threads.append(t)
        t.start()

    try:
        while not stop_event.is_set():
            stop_event.wait(0.5)
    except KeyboardInterrupt:
        logger.info('Solar Shield is shutting down')
        stop_event.set()
        for t in threads:
            t.join(timeout=5)
        logger.info('Shutdown complete')

if __name__ == "__main__":
    main()