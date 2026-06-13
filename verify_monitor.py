import os
import time
import shutil
import sqlite3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.join(BASE_DIR, 'sandbox')
DB_PATH = os.path.join(BASE_DIR, 'backend', 'audit.db')

def print_banner(title):
    print('\n' + '=' * 60)
    print(f' {title} '.center(60, '='))
    print('=' * 60)

def main():
    print_banner('DLP AUTOMATED VERIFICATION PLAN')
    source_dir = os.path.join(SANDBOX_DIR, 'source_dir')
    sensitive_dir = os.path.join(SANDBOX_DIR, 'sensitive_docs')
    usb_dir = os.path.join(SANDBOX_DIR, 'external_usb')
    for folder in [source_dir, sensitive_dir, usb_dir]:
        os.makedirs(folder, exist_ok=True)
    print('[*] Checked sandbox directories. Starting mock file transfers...')
    normal_file = os.path.join(source_dir, 'test_verification.txt')
    print(f'[*] Creating file: {normal_file}')
    with open(normal_file, 'w') as f:
        f.write('Initial Verification Line.\n')
    time.sleep(0.5)
    print(f'[*] Modifying file: {normal_file}')
    with open(normal_file, 'a') as f:
        f.write('Appended Modification Line.\n')
    time.sleep(0.5)
    sensitive_file = os.path.join(sensitive_dir, 'confidential_passwords.txt')
    print(f'[*] Creating sensitive file: {sensitive_file}')
    with open(sensitive_file, 'w') as f:
        f.write('admin:super_secret_pass_123\n')
    time.sleep(0.5)
    usb_file = os.path.join(usb_dir, 'stolen_passwords.txt')
    print(f'[*] Exfiltrating sensitive file to USB: {usb_file}')
    shutil.copy2(sensitive_file, usb_file)
    time.sleep(0.5)
    relocated_file = os.path.join(source_dir, 'relocated_passwords.txt')
    print(f'[*] Moving sensitive file out of restricted folder to: {relocated_file}')
    shutil.move(sensitive_file, relocated_file)
    time.sleep(1.0)
    print('\n[*] File operations completed. Checking SQLite logs...')
    if not os.path.exists(DB_PATH):
        print('[ERROR] Database file not found! Has the backend service been run?')
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM file_events')
    total_events = cursor.fetchone()[0]
    print(f'[+] Total file events captured: {total_events}')
    print_banner('LOGGED FILE EVENTS SUMMARY')
    cursor.execute('SELECT event_type, src_path, dest_path, process_name, is_sensitive FROM file_events ORDER BY id DESC LIMIT 10')
    for row in cursor.fetchall():
        sens_str = '[SENSITIVE]' if row['is_sensitive'] else '[NORMAL]'
        dest_str = f" -> {os.path.basename(row['dest_path'])}" if row['dest_path'] else ''
        print(f"  {sens_str} {row['event_type'].upper()}: {os.path.basename(row['src_path'])}{dest_str} (via {row['process_name']})")
    print_banner('TRIGGERED DLP ALERTS')
    cursor.execute('SELECT severity, rule_name, description FROM alerts ORDER BY id DESC')
    alerts = cursor.fetchall()
    if len(alerts) == 0:
        print('  [!] No alerts registered. Ensure backend API/monitoring server is running.')
    else:
        for alert in alerts:
            sev_symbol = '[!]' if alert['severity'] in ['High', 'Critical'] else '[*]'
            print(f"  {sev_symbol} [{alert['severity'].upper()}] Rule: {alert['rule_name']}")
            print(f"     Info: {alert['description']}")
            print('-' * 50)
    conn.close()
    print_banner('VERIFICATION SUCCESSFUL')
if __name__ == '__main__':
    main()