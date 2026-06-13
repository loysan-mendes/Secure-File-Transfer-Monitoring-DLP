import React, { useState, useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Bar, Pie } from 'react-chartjs-2';


ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);


const playAlertSound = (severity) => {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    
    osc.connect(gain);
    gain.connect(ctx.destination);
    
    if (severity === "Critical") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.4);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.45);
      osc.start();
      osc.stop(ctx.currentTime + 0.45);
    } else if (severity === "High") {
      osc.type = "square";
      osc.frequency.setValueAtTime(660, ctx.currentTime);
      osc.frequency.setValueAtTime(550, ctx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
      osc.start();
      osc.stop(ctx.currentTime + 0.3);
    } else {
      osc.type = "sine";
      osc.frequency.setValueAtTime(523, ctx.currentTime); 
      gain.gain.setValueAtTime(0.05, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    }
  } catch (e) {
    console.warn("Audio Context playback failed (user interaction required):", e);
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [settings, setSettings] = useState({
    monitored_paths: [],
    sensitive_paths: [],
    usb_paths: [],
    allowed_processes: [],
    bulk_transfer_threshold: 10,
    bulk_transfer_window: 5
  });
  const [stats, setStats] = useState({
    total_events: 0,
    active_alerts: 0,
    event_types: { created: 0, modified: 0, deleted: 0, moved: 0 },
    alerts_severity: { Low: 0, Medium: 0, High: 0, Critical: 0 },
    top_processes: {},
    sensitivity: { sensitive: 0, normal: 0 },
    timeline: []
  });
  const [wsConnected, setWsConnected] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [logPage, setLogPage] = useState(0);
  const [totalLogs, setTotalLogs] = useState(0);
  
  
  const [newMonitoredPath, setNewMonitoredPath] = useState('');
  const [newSensitivePath, setNewSensitivePath] = useState('');
  const [newUsbPath, setNewUsbPath] = useState('');
  const [newAllowedProcess, setNewAllowedProcess] = useState('');

  
  const [hashFileA, setHashFileA] = useState(null);
  const [hashFileB, setHashFileB] = useState(null);
  const [hashResultA, setHashResultA] = useState('');
  const [hashResultB, setHashResultB] = useState('');

  const wsRef = useRef(null);

  
  const fetchData = async () => {
    try {
      
      const statsRes = await fetch('http://127.0.0.1:8000/api/stats');
      if (statsRes.ok) setStats(await statsRes.json());

      
      const alertsRes = await fetch('http://127.0.0.1:8000/api/alerts');
      if (alertsRes.ok) {
        const data = await alertsRes.json();
        setAlerts(data.alerts);
      }

      
      fetchLogs();

      
      const settingsRes = await fetch('http://127.0.0.1:8000/api/settings');
      if (settingsRes.ok) setSettings(await settingsRes.json());
    } catch (e) {
      console.error("Error loading API data:", e);
    }
  };

  const fetchLogs = async () => {
    try {
      const url = `http://127.0.0.1:8000/api/events?limit=15&offset=${logPage * 15}${searchText ? `&search=${encodeURIComponent(searchText)}` : ''}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events);
        setTotalLogs(data.total);
      }
    } catch (e) {
      console.error("Error loading logs:", e);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [logPage, searchText]);

  
  useEffect(() => {
    fetchData();

    const connectWebSocket = () => {
      const ws = new WebSocket('ws://127.0.0.1:8000/ws');
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        console.log("WebSocket stream connected");
      };

      ws.onmessage = (event) => {
        const record = JSON.parse(event.data);
        console.log("WS Received: ", record);
        
        if (record.is_alert) {
          
          setAlerts(prev => [record, ...prev]);
          
          setToasts(prev => [{
            id: Date.now(),
            title: record.rule_name,
            desc: record.description,
            severity: record.severity
          }, ...prev].slice(0, 5));
          
          playAlertSound(record.severity);
          
          
          setTimeout(() => {
            setToasts(prev => prev.slice(0, prev.length - 1));
          }, 6000);
        } else {
          
          setEvents(prev => [record, ...prev].slice(0, 100));
        }
        
        refreshStats();
      };

      ws.onclose = () => {
        setWsConnected(false);
        console.log("WebSocket stream disconnected. Reconnecting in 3s...");
        setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
      };
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const refreshStats = async () => {
    try {
      const statsRes = await fetch('http://127.0.0.1:8000/api/stats');
      if (statsRes.ok) setStats(await statsRes.json());
    } catch (e) {}
  };

  
  const handleResolveAlert = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/alerts/${id}/resolve`, { method: 'PUT' });
      if (res.ok) {
        setAlerts(prev => prev.filter(a => a.id !== id));
        refreshStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm("Are you sure you want to clear all file logs and alert database entries?")) return;
    try {
      const res = await fetch('http://127.0.0.1:8000/api/logs/clear', { method: 'POST' });
      if (res.ok) {
        setEvents([]);
        setAlerts([]);
        fetchData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleRestoreDefaults = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/settings/restore', { method: 'POST' });
      if (res.ok) {
        alert("Monitored settings and sandbox default folders restored successfully!");
        fetchData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSaveSettings = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      if (res.ok) {
        alert("Configuration saved successfully!");
        fetchData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  
  const triggerSimulation = async (type) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/simulate/${type}`, { method: 'POST' });
      const data = await res.json();
      console.log(`Simulation [${type}] triggered:`, data.message);
    } catch (e) {
      alert(`Simulation failed: ${e.message}`);
    }
  };

  
  const handleFileDrop = async (e, side) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0] || e.target.files[0];
    if (!file) return;

    if (side === 'A') {
      setHashFileA(file);
      const hash = await calculateFileHash(file);
      setHashResultA(hash);
    } else {
      setHashFileB(file);
      const hash = await calculateFileHash(file);
      setHashResultB(hash);
    }
  };

  const calculateFileHash = (file) => {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const buffer = e.target.result;
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        resolve(hashHex);
      };
      reader.readAsArrayBuffer(file);
    });
  };

  
  const lineChartData = {
    labels: stats.timeline.map(t => t.time),
    datasets: [
      {
        label: 'File Operations',
        data: stats.timeline.map(t => t.count),
        fill: true,
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        borderColor: '#3b82f6',
        pointBackgroundColor: '#60a5fa',
        pointBorderColor: '#fff',
        tension: 0.4,
      },
    ],
  };

  const lineChartOptions = {
    responsive: true,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#111827',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        titleFont: { family: 'Outfit' },
        bodyFont: { family: 'Inter' }
      }
    },
    scales: {
      y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af' } },
      x: { grid: { display: false }, ticks: { color: '#9ca3af' } }
    }
  };

  const pieChartData = {
    labels: Object.keys(stats.event_types).map(k => k.toUpperCase()),
    datasets: [
      {
        data: Object.values(stats.event_types),
        backgroundColor: [
          '#10b981', 
          '#3b82f6', 
          '#ef4444', 
          '#8b5cf6', 
        ],
        borderWidth: 0,
      },
    ],
  };

  const pieChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#9ca3af',
          font: { family: 'Inter', size: 10 }
        }
      }
    }
  };

  const barChartData = {
    labels: Object.keys(stats.alerts_severity),
    datasets: [
      {
        data: Object.values(stats.alerts_severity),
        backgroundColor: [
          '#10b981', 
          '#f59e0b', 
          '#ef4444', 
          '#d97706', 
        ],
        borderRadius: 4
      }
    ]
  };

  const barChartOptions = {
    responsive: true,
    plugins: {
      legend: { display: false }
    },
    scales: {
      y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { precision: 0, color: '#9ca3af' } },
      x: { grid: { display: false }, ticks: { color: '#9ca3af' } }
    }
  };

  return (
    <div className="app-container">
      {}
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className="toast" style={{ borderColor: `var(--severity-${toast.severity})` }}>
            <div className="alert-icon">⚠️<div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{toast.desc}<div>
          <div>

      {}
      <div className="sidebar">
        <div className="brand">
          <div className="brand-icon">🛡️<span>
        <span> Dashboard
          <span> Activity Log
          <span> Active Alerts ({alerts.length})
          <span> Integrity Checker
          <span> Rules Engine Settings
          <div>

        <div className="sidebar-footer">
          <div className="flex align-center gap-8 mb-4">
            <span className={wsConnected ? "live-dot" : "offline-dot"}><span>
          <p>
        <div>

      {}
      <div className="main-content">
        
        {}
        <div className="flex justify-between align-center mb-4">
          <div>
            <h1>Secure File Monitoring System<p>
          <button>
            <button className="btn btn-danger" onClick={handleClearLogs}>🗑️ Clear DB Logs<div>
        <* Threat Simulator Control Panel *span>
            <div>
              <h4 style={{ color: '#fff' }}>Interactive Threat Simulator<p>
            <div>
          <div className="simulation-buttons">
            <button className="btn btn-secondary" onClick={() => triggerSimulation('usb-connect')}>🔌 Plug USB<button>
            <button className="btn btn-danger" onClick={() => triggerSimulation('usb-exfiltration')}>📤 Exfiltrate USB<button>
            <button className="btn btn-danger" onClick={() => triggerSimulation('tampering')}>✏️ Tamper File<div>
        <* Dynamic Views ** VIEW 1: DASHBOARD OVERVIEW ** Stat Cards Grid *span>
                  <span className="stat-value">{stats.total_events}<div>
                <div className="stat-icon icon-blue">📂<div>

              <div className="card stat-card">
                <div className="stat-info">
                  <span className="stat-label">Active Security Threats<span>
                <div>
              <span>
                  <span className="stat-value">{stats.sensitivity.sensitive}<div>
                <div className="stat-icon icon-purple">🔒<div>

              <div className="card stat-card">
                <div className="stat-info">
                  <span className="stat-label">Monitored Folders<span>
                <div>
              <div>

            {}
            <div className="grid-cols-3">
              <div className="card" style={{ gridColumn: 'span 2' }}>
                <div className="card-title">
                  <span>📈 File Transfer Activity Timeline<hour<div>
                <div style={{ height: '230px' }}>
                  {stats.timeline.length > 0 ? (
                    <Line data={lineChartData} options={lineChartOptions} div>
                  )}
                <div>

              <div className="card">
                <div className="card-title">📂 Event Distribution<>
                  ) : (
                    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                      No events logged yet.
                    <div>
              <div>

            <div className="grid-cols-2">
              <div className="card">
                <div className="card-title">⚡ Alert Severity Summary<>
                <div>

              <div className="card">
                <div className="card-title">🔍 Top Active Processes<span>
                        <span style={{ fontWeight: 'bold' }}>{count} edits<div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>No process history.<div>
              <div>

            {}
            <div className="card">
              <div className="card-title">
                <span>🚨 Recent Unresolved Violations<button>
              <span>
                        <span className="alert-rule">{alert.rule_name}<div>
                      <div className="alert-desc">{alert.description}<span>
                        {alert.src_path && <span>📂 Source: <span className="file-path">{alert.src_path}<span>}
                      <div>
                    <button className="btn btn-success" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={() => handleResolveAlert(alert.id)}>Resolve<div>
                ))}
                {alerts.length === 0 && (
                  <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    🟢 Clean Audit Status. No security alerts detected!
                  <div>
            <div>
        )}

        {}
        {activeTab === 'logs' && (
          <div className="card">
            <div className="card-title">
              <span>📋 Comprehensive Audit Logs<>
              <div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp<th>
                    <th>Sensitivity<th>
                    <th>Destination Path<th>
                    <th>SHA256 Hash<tr>
                <td>
                      <td>
                        <span className={`badge badge-${event.event_type}`}>{event.event_type}<td>
                      <td>
                        <span className={`badge ${event.is_sensitive ? 'badge-sensitive' : 'badge-normal'}`}>
                          {event.is_sensitive ? 'Sensitive' : 'Normal'}
                        <td>
                      <td>
                        <span className="file-path" title={event.src_path}>
                          {event.src_path.split('\\').pop() || event.src_path.split('span>
                      <').pop()}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>-</span>
                        )}
                      </td>
                      <td>
                        <span className="file-path" style={{ color: '#f59e0b' }} title={`PID: ${event.process_pid}`}>
                          {event.process_name}
                        </span>
                      </td>
                      <td>
                        {event.file_hash ? (
                          <span className="hash-text" title={event.file_hash}>{event.file_hash.substring(0, 12)}...</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {events.length === 0 && (
                    <tr>
                      <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        No logs recorded matching search criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex justify-between align-center mt-4">
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Showing page {logPage + 1} (Total {totalLogs} events)
              </span>
              <div className="flex gap-8">
                <button className="btn btn-secondary" style={{ padding: '6px 12px' }} disabled={logPage === 0} onClick={() => setLogPage(p => p - 1)}>◀ Prev</button>
                <button className="btn btn-secondary" style={{ padding: '6px 12px' }} disabled={(logPage + 1) * 15 >= totalLogs} onClick={() => setLogPage(p => p + 1)}>Next ▶</button>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 3: ACTIVE SECURITY ALERTS */}
        {activeTab === 'alerts' && (
          <div className="card">
            <div className="card-title">
              <span>🚨 Security Policy Violations</span>
              <span className="badge badge-sensitive">{alerts.length} Threats</span>
            </div>

            <div style={{ minHeight: '300px' }}>
              {alerts.map(alert => (
                <div key={alert.id} className={`alert-item border-${alert.severity}`} style={{ padding: '20px' }}>
                  <div className="alert-content">
                    <div className="alert-header">
                      <span className={`badge severity-${alert.severity}`} style={{ fontSize: '0.8rem' }}>{alert.severity}</span>
                      <h3 className="alert-rule" style={{ fontSize: '1.1rem' }}>{alert.rule_name}</h3>
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        ⏰ {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="alert-desc" style={{ fontSize: '0.95rem', margin: '8px 0 12px 0' }}>{alert.description}</p>
                    
                    <div className="flex flex-column gap-8">
                      {alert.src_path && (
                        <div style={{ fontSize: '0.85rem' }}>
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Source Path: </span>
                          <span className="file-path">{alert.src_path}</span>
                        </div>
                      )}
                      {alert.dest_path && (
                        <div style={{ fontSize: '0.85rem' }}>
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>Destination Path: </span>
                          <span className="file-path dest">{alert.dest_path}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <button className="btn btn-success" onClick={() => handleResolveAlert(alert.id)}>
                    ✔️ Dismiss Alert
                  </button>
                </div>
              ))}

              {alerts.length === 0 && (
                <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <span style={{ fontSize: '3rem', display: 'block', marginBottom: '16px' }}>🟢</span>
                  <h2>No Active System Threats</h2>
                  <p style={{ marginTop: '8px' }}>The monitoring logs represent zero policy violations or suspicious transfers.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 4: FILE INTEGRITY CHECKER */}
        {activeTab === 'integrity' && (
          <div className="grid-cols-2">
            
            {/* File 1 hasher */}
            <div className="card">
              <div className="card-title">🔑 File Identity A</div>
              <div 
                className="drag-drop-zone"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => handleFileDrop(e, 'A')}
              >
                <div className="drag-drop-icon">📄</div>
                <h4>Drag & Drop File A Here</h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>or click to browse</p>
                <input 
                  type="file" 
                  style={{ display: 'none' }} 
                  id="fileInputA" 
                  onChange={(e) => handleFileDrop(e, 'A')} 
                />
                <button className="btn btn-secondary" style={{ marginTop: '12px', padding: '6px 12px' }} onClick={() => document.getElementById('fileInputA').click()}>Browse File</button>
              </div>

              {hashFileA && (
                <div style={{ wordBreak: 'break-all' }}>
                  <div style={{ marginBottom: '8px' }}><span style={{ color: 'var(--text-secondary)' }}>Name:</span> <strong>{hashFileA.name}</strong></div>
                  <div style={{ marginBottom: '8px' }}><span style={{ color: 'var(--text-secondary)' }}>Size:</span> {Math.round(hashFileA.size / 1024)} KB</div>
                  <div><span style={{ color: 'var(--text-secondary)' }}>SHA256 Hash:</span></div>
                  <div className="file-path mt-4" style={{ display: 'block', padding: '10px' }}>{hashResultA}</div>
                </div>
              )}
            </div>

            {/* File 2 hasher */}
            <div className="card">
              <div className="card-title">🔑 File Identity B</div>
              <div 
                className="drag-drop-zone"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => handleFileDrop(e, 'B')}
              >
                <div className="drag-drop-icon">📄</div>
                <h4>Drag & Drop File B Here</h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>or click to browse</p>
                <input 
                  type="file" 
                  style={{ display: 'none' }} 
                  id="fileInputB" 
                  onChange={(e) => handleFileDrop(e, 'B')} 
                />
                <button className="btn btn-secondary" style={{ marginTop: '12px', padding: '6px 12px' }} onClick={() => document.getElementById('fileInputB').click()}>Browse File</button>
              </div>

              {hashFileB && (
                <div style={{ wordBreak: 'break-all' }}>
                  <div style={{ marginBottom: '8px' }}><span style={{ color: 'var(--text-secondary)' }}>Name:</span> <strong>{hashFileB.name}</strong></div>
                  <div style={{ marginBottom: '8px' }}><span style={{ color: 'var(--text-secondary)' }}>Size:</span> {Math.round(hashFileB.size / 1024)} KB</div>
                  <div><span style={{ color: 'var(--text-secondary)' }}>SHA256 Hash:</span></div>
                  <div className="file-path mt-4" style={{ display: 'block', padding: '10px' }}>{hashResultB}</div>
                </div>
              )}
            </div>

            {/* Integrity report outcome */}
            <div className="card" style={{ gridColumn: 'span 2' }}>
              <div className="card-title">🛡️ Integrity Analysis</div>
              {hashResultA && hashResultB ? (
                hashResultA === hashResultB ? (
                  <div style={{ padding: '20px', backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                    <span style={{ fontSize: '2rem' }}>✅</span>
                    <h2 style={{ color: '#10b981', marginTop: '10px' }}>Integrity Check Successful</h2>
                    <p style={{ marginTop: '6px' }}>Hashes match exactly. The files are identical and have not been tampered with or corrupted during transfer.</p>
                  </div>
                ) : (
                  <div style={{ padding: '20px', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                    <span style={{ fontSize: '2rem' }}>❌</span>
                    <h2 style={{ color: '#ef4444', marginTop: '10px' }}>Integrity Violation Detected</h2>
                    <p style={{ marginTop: '6px' }}>Hash signature mismatch. These files are not identical. Unauthorized edits, truncation, or malicious code injection has occurred!</p>
                  </div>
                )
              ) : (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '30px' }}>
                  Please load both File A and File B to execute the real-time cryptographic hash verification check.
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 5: CONFIGURATION & SETTINGS */}
        {activeTab === 'settings' && (
          <div className="card">
            <div className="card-title">
              <span>⚙️ DLP Rules Engine Configuration</span>
              <button className="btn btn-danger" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={handleRestoreDefaults}>Restore Defaults</button>
            </div>

            <div className="grid-cols-2 mt-4">
              <div>
                <h3>📁 Monitored Target Paths</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '12px' }}>Directories watched for all creations, modifications, moves, and deletions.</p>
                {settings.monitored_paths.map(path => (
                  <div key={path} className="config-item">
                    <span className="file-path">{path}</span>
                    <button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: '0.75rem' }} 
                      onClick={() => setSettings(prev => ({...prev, monitored_paths: prev.monitored_paths.filter(p => p !== path)}))}>Remove</button>
                  </div>
                ))}
                <div className="flex gap-8 mt-4">
                  <input type="text" placeholder="Folder path..." className="form-control" value={newMonitoredPath} onChange={e => setNewMonitoredPath(e.target.value)} />
                  <button className="btn btn-primary" onClick={() => { if(newMonitoredPath) { setSettings(prev => ({...prev, monitored_paths: [...prev.monitored_paths, newMonitoredPath]})); setNewMonitoredPath(''); } }}>Add</button>
                </div>
              </div>

              <div>
                <h3>🔒 Sensitive Folder Paths</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '12px' }}>Files inside these folders trigger High/Critical severity policy alerts if modified or copied.</p>
                {settings.sensitive_paths.map(path => (
                  <div key={path} className="config-item">
                    <span className="file-path">{path}</span>
                    <button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: '0.75rem' }} 
                      onClick={() => setSettings(prev => ({...prev, sensitive_paths: prev.sensitive_paths.filter(p => p !== path)}))}>Remove</button>
                  </div>
                ))}
                <div className="flex gap-8 mt-4">
                  <input type="text" placeholder="Sensitive folder path..." className="form-control" value={newSensitivePath} onChange={e => setNewSensitivePath(e.target.value)} />
                  <button className="btn btn-primary" onClick={() => { if(newSensitivePath) { setSettings(prev => ({...prev, sensitive_paths: [...prev.sensitive_paths, newSensitivePath]})); setNewSensitivePath(''); } }}>Add</button>
                </div>
              </div>

              <div>
                <h3>🔌 USB/External Drive Simulation Paths</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '12px' }}>Destination folders treated as external removable USB storage drives.</p>
                {settings.usb_paths.map(path => (
                  <div key={path} className="config-item">
                    <span className="file-path">{path}</span>
                    <button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: '0.75rem' }} 
                      onClick={() => setSettings(prev => ({...prev, usb_paths: prev.usb_paths.filter(p => p !== path)}))}>Remove</button>
                  </div>
                ))}
                <div className="flex gap-8 mt-4">
                  <input type="text" placeholder="USB folder path..." className="form-control" value={newUsbPath} onChange={e => setNewUsbPath(e.target.value)} />
                  <button className="btn btn-primary" onClick={() => { if(newUsbPath) { setSettings(prev => ({...prev, usb_paths: [...prev.usb_paths, newUsbPath]})); setNewUsbPath(''); } }}>Add</button>
                </div>
              </div>

              <div>
                <h3>🛡️ Allowed Process Whitelist</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '12px' }}>Processes authorized to write files. Unlisted processes editing sensitive files trigger alerts.</p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                  {settings.allowed_processes.map(proc => (
                    <span key={proc} className="badge badge-normal" style={{ padding: '6px 10px', textTransform: 'none', display: 'flex', gap: '8px', alignItems: 'center' }}>
                      {proc}
                      <span style={{ color: 'var(--severity-high)', cursor: 'pointer', fontWeight: 'bold' }} 
                        onClick={() => setSettings(prev => ({...prev, allowed_processes: prev.allowed_processes.filter(p => p !== proc)}))}>×</span>
                    </span>
                  ))}
                </div>
                <div className="flex gap-8">
                  <input type="text" placeholder="process.exe..." className="form-control" value={newAllowedProcess} onChange={e => setNewAllowedProcess(e.target.value)} />
                  <button className="btn btn-primary" onClick={() => { if(newAllowedProcess) { setSettings(prev => ({...prev, allowed_processes: [...prev.allowed_processes, newAllowedProcess]})); setNewAllowedProcess(''); } }}>Add</button>
                </div>
              </div>
            </div>

            <div className="grid-cols-2 mt-4" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
              <div className="form-group">
                <label>Bulk Operation Threshold (Max events)<>
              <label>
                <input type="number" className="form-control" value={settings.bulk_transfer_window} onChange={e => setSettings(prev => ({...prev, bulk_transfer_window: parseInt(e.target.value)}))} div>
            <button>
          <div>
    </div>
  );
}
