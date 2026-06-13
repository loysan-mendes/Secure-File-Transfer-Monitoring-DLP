import os
import asyncio
import json
import shutil
import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import db
from monitor import FileMonitor
app = FastAPI(title='Secure File Transfer Monitoring System API')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

class ConnectionManager:

    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f'New client connected. Total clients: {len(self.active_connections)}')

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f'Client disconnected. Total clients: {len(self.active_connections)}')

    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                pass
manager = ConnectionManager()
monitor_instance = None
main_loop = None

def broadcast_event(record):
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(record), main_loop)

@app.on_event('startup')
async def startup_event():
    global monitor_instance, main_loop
    main_loop = asyncio.get_running_loop()
    db.init_db()
    setup_sandbox_directories()
    monitor_instance = FileMonitor(event_callback=broadcast_event)
    monitor_instance.start()
    print('FastAPI backend & File Monitor successfully initialized.')

@app.on_event('shutdown')
async def shutdown_event():
    global monitor_instance
    if monitor_instance:
        monitor_instance.stop()

def setup_sandbox_directories():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sandbox_dir = os.path.join(base_dir, 'sandbox')
    source_dir = os.path.join(sandbox_dir, 'source_dir')
    sensitive_docs = os.path.join(sandbox_dir, 'sensitive_docs')
    external_usb = os.path.join(sandbox_dir, 'external_usb')
    for folder in [source_dir, sensitive_docs, external_usb]:
        os.makedirs(folder, exist_ok=True)
    readme_path = os.path.join(sandbox_dir, 'README.txt')
    if not os.path.exists(readme_path):
        with open(readme_path, 'w') as f:
            f.write('Welcome to the Secure File Transfer Monitoring Sandbox!\nUse source_dir for standard modifications.\nUse sensitive_docs for restricted files.\nUse external_usb to simulate USB flash drives.\n')
    sensitive_file = os.path.join(sensitive_docs, 'confidential_financials.csv')
    if not os.path.exists(sensitive_file):
        with open(sensitive_file, 'w') as f:
            f.write('EmployeeID,Name,Salary,SSN\n101,John Doe,120000,999-12-3456\n102,Jane Smith,155000,999-23-4567\n')
    source_file = os.path.join(source_dir, 'public_announcement.txt')
    if not os.path.exists(source_file):
        with open(source_file, 'w') as f:
            f.write('The quarterly earnings call will take place tomorrow at 10 AM EST.\n')

class SettingsModel(BaseModel):
    monitored_paths: list[str]
    sensitive_paths: list[str]
    usb_paths: list[str]
    allowed_processes: list[str]
    bulk_transfer_threshold: int
    bulk_transfer_window: int

@app.get('/api/events')
def get_events(limit: int=50, offset: int=0, search: str=None):
    events, total = db.get_all_events(limit, offset, search)
    return {'events': events, 'total': total}

@app.get('/api/alerts')
def get_alerts(limit: int=50, show_resolved: bool=False):
    alerts = db.get_all_alerts(limit, show_resolved)
    return {'alerts': alerts}

@app.put('/api/alerts/{alert_id}/resolve')
def resolve_alert(alert_id: int):
    db.resolve_alert(alert_id)
    return {'status': 'success', 'message': f'Alert {alert_id} marked as resolved.'}

@app.get('/api/settings')
def get_settings():
    return db.get_settings()

@app.put('/api/settings')
def update_settings(settings: SettingsModel):
    db.update_settings(settings.model_dump())
    return {'status': 'success', 'message': 'Settings updated successfully.'}

@app.post('/api/settings/restore')
def restore_settings():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sandbox_dir = os.path.join(base_dir, 'sandbox')
    default_config = {'monitored_paths': [os.path.join(sandbox_dir, 'source_dir'), os.path.join(sandbox_dir, 'sensitive_docs'), os.path.join(sandbox_dir, 'external_usb')], 'sensitive_paths': [os.path.join(sandbox_dir, 'sensitive_docs')], 'usb_paths': [os.path.join(sandbox_dir, 'external_usb')], 'allowed_processes': ['python.exe', 'pythonw.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe'], 'bulk_transfer_threshold': 10, 'bulk_transfer_window': 5}
    db.update_settings(default_config)
    setup_sandbox_directories()
    return {'status': 'success', 'message': 'Default settings and sandbox folder structure restored.'}

@app.post('/api/logs/clear')
def clear_all_logs():
    db.clear_logs_and_alerts()
    return {'status': 'success', 'message': 'Logs and alerts cleared.'}

@app.get('/api/stats')
def get_statistics():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT event_type, COUNT(*) as count FROM file_events GROUP BY event_type')
    event_types = {row['event_type']: row['count'] for row in cursor.fetchall()}
    for et in ['created', 'modified', 'deleted', 'moved']:
        if et not in event_types:
            event_types[et] = 0
    cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
    alerts_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        if sev not in alerts_severity:
            alerts_severity[sev] = 0
    cursor.execute('SELECT process_name, COUNT(*) as count FROM file_events GROUP BY process_name ORDER BY count DESC LIMIT 5')
    top_processes = {row['process_name']: row['count'] for row in cursor.fetchall()}
    cursor.execute('SELECT is_sensitive, COUNT(*) as count FROM file_events GROUP BY is_sensitive')
    sensitivity = {str(row['is_sensitive']): row['count'] for row in cursor.fetchall()}
    sensitivity_stats = {'sensitive': sensitivity.get('1', 0), 'normal': sensitivity.get('0', 0)}
    cursor.execute("\n        SELECT strftime('%H:%M', timestamp) as time_group, COUNT(*) as count \n        FROM file_events \n        GROUP BY time_group \n        ORDER BY timestamp DESC \n        LIMIT 10\n    ")
    timeline_rows = cursor.fetchall()
    timeline = [{'time': r['time_group'], 'count': r['count']} for r in reversed(timeline_rows)]
    cursor.execute('SELECT COUNT(*) FROM file_events')
    total_events = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = 0')
    active_alerts = cursor.fetchone()[0]
    conn.close()
    return {'total_events': total_events, 'active_alerts': active_alerts, 'event_types': event_types, 'alerts_severity': alerts_severity, 'top_processes': top_processes, 'sensitivity': sensitivity_stats, 'timeline': timeline}

@app.post('/api/simulate/usb-connect')
async def simulate_usb_connect():
    alert_id = db.log_alert(severity='High', rule_name='Removable Drive Connected (Simulated)', description="USB drive connected: Volume 'E:\\' (Simulated)", src_path='E:\\')
    alert_record = {'id': alert_id, 'timestamp': datetime.datetime.now().isoformat(), 'severity': 'High', 'rule_name': 'Removable Drive Connected (Simulated)', 'description': "USB drive connected: Volume 'E:\\' (Simulated)", 'src_path': 'E:\\', 'dest_path': None, 'resolved': 0, 'is_alert': True}
    broadcast_event(alert_record)
    return {'status': 'success', 'message': 'Simulated USB connection event successfully.'}

@app.post('/api/simulate/unauthorized-access')
async def simulate_unauthorized_access():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_file = os.path.join(base_dir, 'sandbox', 'sensitive_docs', 'unauthorized_breach.txt')
    with open(target_file, 'w') as f:
        f.write('Unauthorized access payload test.\n')
    username = getpass.getuser()
    event_id = db.log_file_event(event_type='created', src_path=target_file, dest_path=None, file_hash=hashlib.sha256(b'Unauthorized access payload test.\n').hexdigest(), process_name='malware.exe', process_pid=9999, username=username, is_sensitive=1)
    event_record = {'id': event_id, 'timestamp': datetime.datetime.now().isoformat(), 'event_type': 'created', 'src_path': target_file, 'dest_path': None, 'file_hash': hashlib.sha256(b'Unauthorized access payload test.\n').hexdigest(), 'process_name': 'malware.exe', 'process_pid': 9999, 'username': username, 'is_sensitive': True}
    broadcast_event(event_record)
    alert_id = db.log_alert(severity='High', rule_name='Unauthorized Sensitive File Access', description=f"Process 'malware.exe' (PID: 9999) performed 'created' on sensitive file 'unauthorized_breach.txt'.", src_path=target_file)
    alert_record = {'id': alert_id, 'timestamp': datetime.datetime.now().isoformat(), 'severity': 'High', 'rule_name': 'Unauthorized Sensitive File Access', 'description': "Process 'malware.exe' (PID: 9999) performed 'created' on sensitive file 'unauthorized_breach.txt'.", 'src_path': target_file, 'dest_path': None, 'resolved': 0, 'is_alert': True}
    broadcast_event(alert_record)
    return {'status': 'success', 'message': 'Simulated unauthorized access threat successfully.'}

@app.post('/api/simulate/usb-exfiltration')
async def simulate_usb_exfiltration():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_file = os.path.join(base_dir, 'sandbox', 'sensitive_docs', 'confidential_financials.csv')
    dest_file = os.path.join(base_dir, 'sandbox', 'external_usb', 'copied_financials.csv')
    if os.path.exists(src_file):
        shutil.copy2(src_file, dest_file)
    return {'status': 'success', 'message': 'Copied confidential financials to simulated USB drive.'}

@app.post('/api/simulate/bulk-burst')
async def simulate_bulk_burst():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source_dir = os.path.join(base_dir, 'sandbox', 'source_dir')
    for i in range(12):
        file_path = os.path.join(source_dir, f'temp_bulk_file_{i}.tmp')
        with open(file_path, 'w') as f:
            f.write(f'Bulk data write line {i}\n')

    async def cleanup():
        await asyncio.sleep(2)
        for i in range(12):
            file_path = os.path.join(source_dir, f'temp_bulk_file_{i}.tmp')
            try:
                os.remove(file_path)
            except Exception:
                pass
    asyncio.create_task(cleanup())
    return {'status': 'success', 'message': 'Triggered 12 fast file creation events in the sandbox.'}

@app.post('/api/simulate/tampering')
async def simulate_tampering():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_file = os.path.join(base_dir, 'sandbox', 'sensitive_docs', 'confidential_financials.csv')
    if os.path.exists(target_file):
        with open(target_file, 'a') as f:
            f.write('199,HackedUser,9999999,000-00-0000\n')
        return {'status': 'success', 'message': 'Tampered with confidential_financials.csv to trigger Integrity Failure alert.'}
    else:
        raise HTTPException(status_code=404, detail='Sensitive source file confidential_financials.csv not found.')

@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=True)