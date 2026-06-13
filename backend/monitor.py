import os
import time
import hashlib
import threading
import getpass
import datetime
from collections import deque
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import db

class MonitorHandler(FileSystemEventHandler):

    def __init__(self, config, event_callback):
        super().__init__()
        self.config = config
        self.event_callback = event_callback
        self.recent_events = deque()
        self.lock = threading.Lock()

    def get_file_hash(self, file_path):
        if os.path.isdir(file_path):
            return None
        hash_sha256 = hashlib.sha256()
        try:
            time.sleep(0.05)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None

    def get_process_info(self, file_path):
        try:
            return ('python.exe', os.getpid())
        except Exception:
            return ('explorer.exe', 0)

    def is_path_in_list(self, path, path_list):
        norm_path = os.path.normpath(path).lower()
        for p in path_list:
            norm_p = os.path.normpath(p).lower()
            if norm_path.startswith(norm_p):
                return True
        return False

    def process_event(self, event_type, src_path, dest_path=None):
        if os.path.isdir(src_path) or (dest_path and os.path.isdir(dest_path)):
            return
        filename = os.path.basename(src_path)
        if filename.startswith('~') or filename.endswith('.tmp') or filename.startswith('.'):
            return
        username = getpass.getuser()
        proc_name, proc_pid = self.get_process_info(dest_path or src_path)
        self.config = db.get_settings()
        sensitive_paths = self.config.get('sensitive_paths', [])
        usb_paths = self.config.get('usb_paths', [])
        allowed_processes = self.config.get('allowed_processes', [])
        bulk_threshold = self.config.get('bulk_transfer_threshold', 10)
        bulk_window = self.config.get('bulk_transfer_window', 5)
        file_hash = self.get_file_hash(dest_path or src_path)
        is_sensitive = self.is_path_in_list(src_path, sensitive_paths)
        if dest_path:
            is_sensitive = is_sensitive or self.is_path_in_list(dest_path, sensitive_paths)
        if not is_sensitive and file_hash:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM file_events WHERE file_hash = ? AND is_sensitive = 1 LIMIT 1', (file_hash,))
                if cursor.fetchone():
                    is_sensitive = True
                conn.close()
            except Exception:
                pass
        event_id = db.log_file_event(event_type=event_type, src_path=src_path, dest_path=dest_path, file_hash=file_hash, process_name=proc_name, process_pid=proc_pid, username=username, is_sensitive=1 if is_sensitive else 0)
        event_record = {'id': event_id, 'timestamp': datetime.datetime.now().isoformat(), 'event_type': event_type, 'src_path': src_path, 'dest_path': dest_path, 'file_hash': file_hash, 'process_name': proc_name, 'process_pid': proc_pid, 'username': username, 'is_sensitive': is_sensitive}
        self.run_policy_checks(event_record, sensitive_paths, usb_paths, allowed_processes)
        self.check_bulk_transfers(event_type, src_path, bulk_threshold, bulk_window)
        if self.event_callback:
            self.event_callback(event_record)

    def run_policy_checks(self, record, sensitive_paths, usb_paths, allowed_processes):
        src_path = record['src_path']
        dest_path = record['dest_path']
        proc_name = record['process_name']
        file_name = os.path.basename(dest_path or src_path)
        if record['is_sensitive']:
            is_dest_usb = dest_path and self.is_path_in_list(dest_path, usb_paths)
            is_src_usb = self.is_path_in_list(src_path, usb_paths)
            if is_dest_usb or (record['event_type'] in ['created', 'modified'] and is_src_usb):
                alert_id = db.log_alert(severity='Critical', rule_name='Sensitive Exfiltration to USB', description=f"Sensitive file '{file_name}' transferred to removable storage path: {dest_path or src_path}.", src_path=src_path, dest_path=dest_path)
                self.trigger_alert_callback(alert_id, 'Critical', 'Sensitive Exfiltration to USB', f"Sensitive file '{file_name}' transferred to removable storage path.", src_path, dest_path)
            elif record['event_type'] == 'moved' and dest_path:
                is_src_sensitive = self.is_path_in_list(src_path, sensitive_paths)
                is_dest_sensitive = self.is_path_in_list(dest_path, sensitive_paths)
                if is_src_sensitive and (not is_dest_sensitive):
                    alert_id = db.log_alert(severity='Medium', rule_name='Sensitive File Exfiltration', description=f"Sensitive file '{file_name}' moved out of restricted folder to: {dest_path}.", src_path=src_path, dest_path=dest_path)
                    self.trigger_alert_callback(alert_id, 'Medium', 'Sensitive File Exfiltration', f"Sensitive file '{file_name}' moved out of restricted folder.", src_path, dest_path)
            if proc_name.lower() not in [p.lower() for p in allowed_processes] and proc_name != 'Unknown':
                alert_id = db.log_alert(severity='High', rule_name='Unauthorized Sensitive File Access', description=f"Process '{proc_name}' (PID: {record['process_pid']}) performed '{record['event_type']}' on sensitive file '{file_name}'.", src_path=src_path, dest_path=dest_path)
                self.trigger_alert_callback(alert_id, 'High', 'Unauthorized Sensitive File Access', f"Process '{proc_name}' accessed sensitive file '{file_name}'.", src_path, dest_path)
        if record['event_type'] == 'modified' and record['file_hash']:
            conn = db.get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT file_hash FROM file_events WHERE src_path = ? AND file_hash IS NOT NULL AND id < ? ORDER BY id DESC LIMIT 1', (src_path, record['id']))
            row = cursor.fetchone()
            conn.close()
            if row and row['file_hash'] != record['file_hash']:
                severity = 'High' if record['is_sensitive'] else 'Low'
                alert_id = db.log_alert(severity=severity, rule_name='Integrity Verification Mismatch', description=f"File hash mismatch detected for '{file_name}'. Original: {row['file_hash'][:8]}..., New: {record['file_hash'][:8]}... File has been modified.", src_path=src_path)
                self.trigger_alert_callback(alert_id, severity, 'Integrity Verification Mismatch', f"File hash mismatch detected for '{file_name}'. File has been modified.", src_path, None)

    def check_bulk_transfers(self, event_type, src_path, threshold, window):
        with self.lock:
            now = time.time()
            self.recent_events.append((now, src_path, event_type))
            while self.recent_events and now - self.recent_events[0][0] > window:
                self.recent_events.popleft()
            if len(self.recent_events) >= threshold:
                alert_id = db.log_alert(severity='High', rule_name='Bulk Transfer Detected', description=f'Suspicious activity: {len(self.recent_events)} file operations detected within {window} seconds.', src_path=os.path.dirname(src_path))
                self.trigger_alert_callback(alert_id, 'High', 'Bulk Transfer Detected', f'Suspicious activity: {len(self.recent_events)} file operations detected within {window} seconds.', os.path.dirname(src_path), None)
                self.recent_events.clear()

    def trigger_alert_callback(self, alert_id, severity, rule_name, description, src_path, dest_path):
        alert_record = {'id': alert_id, 'timestamp': datetime.datetime.now().isoformat(), 'severity': severity, 'rule_name': rule_name, 'description': description, 'src_path': src_path, 'dest_path': dest_path, 'resolved': 0, 'is_alert': True}
        if self.event_callback:
            self.event_callback(alert_record)

    def on_created(self, event):
        self.process_event('created', event.src_path)

    def on_modified(self, event):
        self.process_event('modified', event.src_path)

    def on_deleted(self, event):
        self.process_event('deleted', event.src_path)

    def on_moved(self, event):
        self.process_event('moved', event.src_path, event.dest_path)

class FileMonitor:

    def __init__(self, event_callback=None):
        self.event_callback = event_callback
        self.observer = None
        self.usb_thread = None
        self.running = False
        self.connected_drives = set()

    def start(self):
        db.init_db()
        config = db.get_settings()
        monitored_paths = config.get('monitored_paths', [])
        for path in monitored_paths:
            os.makedirs(path, exist_ok=True)
        self.observer = Observer()
        handler = MonitorHandler(config, self.event_callback)
        for path in monitored_paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=True)
                print(f'Monitoring directory: {path}')
        self.observer.start()
        self.running = True
        self.usb_thread = threading.Thread(target=self._monitor_usb_drives, daemon=True)
        self.usb_thread.start()

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        print('Monitoring service stopped.')

    def _monitor_usb_drives(self):
        try:
            self.connected_drives = {p.device for p in psutil.disk_partitions() if 'removable' in p.opts or 'cdrom' in p.opts}
        except Exception:
            self.connected_drives = set()
        while self.running:
            try:
                current_drives = {p.device for p in psutil.disk_partitions() if 'removable' in p.opts or 'cdrom' in p.opts}
                added = current_drives - self.connected_drives
                for drive in added:
                    alert_id = db.log_alert(severity='High', rule_name='Removable Drive Connected', description=f'Removable USB drive or external media detected at volume: {drive}', src_path=drive)
                    alert_record = {'id': alert_id, 'timestamp': datetime.datetime.now().isoformat(), 'severity': 'High', 'rule_name': 'Removable Drive Connected', 'description': f'Removable USB drive or external media detected at volume: {drive}', 'src_path': drive, 'dest_path': None, 'resolved': 0, 'is_alert': True}
                    if self.event_callback:
                        self.event_callback(alert_record)
                removed = self.connected_drives - current_drives
                for drive in removed:
                    alert_id = db.log_alert(severity='Medium', rule_name='Removable Drive Disconnected', description=f'Removable drive disconnected: {drive}', src_path=drive)
                    alert_record = {'id': alert_id, 'timestamp': datetime.datetime.now().isoformat(), 'severity': 'Medium', 'rule_name': 'Removable Drive Disconnected', 'description': f'Removable drive disconnected: {drive}', 'src_path': drive, 'dest_path': None, 'resolved': 0, 'is_alert': True}
                    if self.event_callback:
                        self.event_callback(alert_record)
                self.connected_drives = current_drives
            except Exception as e:
                print(f'Error checking disk partitions: {e}')
            time.sleep(3)
if __name__ == '__main__':

    def test_callback(record):
        print('\n--- NEW RECORD BROADCASTED ---')
        print(record)
    monitor = FileMonitor(event_callback=test_callback)
    monitor.start()
    try:
        print('File monitor is running. Press Ctrl+C to stop.')
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()