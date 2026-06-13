import sqlite3
import os
import json
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('\n    CREATE TABLE IF NOT EXISTS file_events (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        timestamp TEXT NOT NULL,\n        event_type TEXT NOT NULL,\n        src_path TEXT NOT NULL,\n        dest_path TEXT,\n        file_hash TEXT,\n        process_name TEXT,\n        process_pid INTEGER,\n        username TEXT,\n        is_sensitive INTEGER DEFAULT 0\n    )\n    ')
    cursor.execute('\n    CREATE TABLE IF NOT EXISTS alerts (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        timestamp TEXT NOT NULL,\n        severity TEXT NOT NULL,\n        rule_name TEXT NOT NULL,\n        description TEXT NOT NULL,\n        src_path TEXT,\n        dest_path TEXT,\n        resolved INTEGER DEFAULT 0\n    )\n    ')
    cursor.execute('\n    CREATE TABLE IF NOT EXISTS settings (\n        key TEXT PRIMARY KEY,\n        value TEXT NOT NULL\n    )\n    ')
    cursor.execute("SELECT 1 FROM settings WHERE key = 'monitor_config'")
    if not cursor.fetchone():
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sandbox_dir = os.path.join(base_dir, 'sandbox')
        default_config = {'monitored_paths': [os.path.join(sandbox_dir, 'source_dir'), os.path.join(sandbox_dir, 'sensitive_docs'), os.path.join(sandbox_dir, 'external_usb')], 'sensitive_paths': [os.path.join(sandbox_dir, 'sensitive_docs')], 'usb_paths': [os.path.join(sandbox_dir, 'external_usb')], 'allowed_processes': ['python.exe', 'pythonw.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe'], 'bulk_transfer_threshold': 10, 'bulk_transfer_window': 5}
        cursor.execute('INSERT INTO settings (key, value) VALUES (?, ?)', ('monitor_config', json.dumps(default_config)))
    conn.commit()
    conn.close()

def get_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'monitor_config'")
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row['value'])
    return {}

def update_settings(config):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('monitor_config', json.dumps(config)))
    conn.commit()
    conn.close()

def log_file_event(event_type, src_path, dest_path=None, file_hash=None, process_name='Unknown', process_pid=None, username='Unknown', is_sensitive=0):
    import datetime
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('\n    INSERT INTO file_events (timestamp, event_type, src_path, dest_path, file_hash, process_name, process_pid, username, is_sensitive)\n    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n    ', (timestamp, event_type, src_path, dest_path, file_hash, process_name, process_pid, username, is_sensitive))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def log_alert(severity, rule_name, description, src_path=None, dest_path=None):
    import datetime
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('\n    INSERT INTO alerts (timestamp, severity, rule_name, description, src_path, dest_path, resolved)\n    VALUES (?, ?, ?, ?, ?, ?, 0)\n    ', (timestamp, severity, rule_name, description, src_path, dest_path))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_all_events(limit=100, offset=0, search=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM file_events'
    params = []
    if search:
        query += ' WHERE src_path LIKE ? OR dest_path LIKE ? OR event_type LIKE ? OR process_name LIKE ?'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param, search_param])
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    count_query = 'SELECT COUNT(*) FROM file_events'
    count_params = []
    if search:
        count_query += ' WHERE src_path LIKE ? OR dest_path LIKE ? OR event_type LIKE ? OR process_name LIKE ?'
        count_params.extend([search_param, search_param, search_param, search_param])
    cursor.execute(count_query, tuple(count_params))
    total_count = cursor.fetchone()[0]
    conn.close()
    return ([dict(r) for r in rows], total_count)

def get_all_alerts(limit=50, show_resolved=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM alerts'
    params = []
    if not show_resolved:
        query += ' WHERE resolved = 0'
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def resolve_alert(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET resolved = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()

def clear_logs_and_alerts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM file_events')
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()
if __name__ == '__main__':
    init_db()
    print('Database initialized successfully at', DB_PATH)