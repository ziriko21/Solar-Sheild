from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import HIGH_PRIORITY_PATHS, SUSPICIOUS_EXTENSIONS
from core.logger import logger, log_event
from core.hasher import hash_file
import os

class AkameHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return
        h = hash_file(event.src_path)
        _, extension = os.path.splitext(event.src_path)
        if extension in SUSPICIOUS_EXTENSIONS:
            log_event('FILE_CREATED', event.src_path, 'CRITICAL', h)
        else: 
            log_event('FILE_CREATED', event.src_path, 'INFO', h)
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        log_event('FILE_DELETED', event.src_path, 'INFO')
    
    def on_modified(self, event):
        if event.is_directory:
            return
        log_event('FILE_MODIFIED', event.src_path, 'INFO')
    
    def on_moved(self, event):
        if event.is_directory:
            return
        log_event('FILE_MOVED', f'{event.src_path} -> {event.dest_path}')

def start_file_watcher(stop_event):
    observer = Observer()
    handler = AkameHandler()

    if not HIGH_PRIORITY_PATHS:
        print('HIGH_PRIORITY_PATHS is empty, observer did not start.')
        observer.stop()
        return

    for path in HIGH_PRIORITY_PATHS:
        if path and os.path.exists(path):
            observer.schedule(handler, path, recursive = True)
    observer.start()
    while not stop_event.is_set():
        stop_event.wait(1)

    observer.stop()
    observer.join()

