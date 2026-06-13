# Deployment Guide: Secure File Transfer Monitor & DLP

Because a Data Loss Prevention (DLP) system requires raw hardware access (to monitor physical disk partitions for USBs) and direct filesystem access to watch target directories, it cannot be fully hosted on sandboxed serverless cloud platforms (like Vercel, Netlify, or AWS Lambda). 

Instead, it should be deployed using one of the three following methods:

---

## Method 1: Desktop Client Executable (Recommended for Clients)
You can compile the Python backend and filesystem watcher into a single, standalone Windows `.exe` application that runs silently in the background on target client machines.

1. **Install PyInstaller**:
   ```bash
   pip install pyinstaller
   ```

2. **Compile the App**:
   Navigate to the `backend` directory and compile `main.py` (which starts both the web API and the filesystem monitoring threads):
   ```bash
   pyinstaller --onefile --noconsole --name "DlpAgent" main.py
   ```
   * `--onefile`: Bundles the Python interpreter and modules into a single executable.
   * `--noconsole`: Hides the command console window so the program runs silently.

3. **Distribute**:
   The compiled file will appear in the `backend/dist/DlpAgent.exe` directory. You can run this executable on client machines, configure it to run at Windows startup, or package it into an installer (e.g., using Inno Setup).

---

## Method 2: On-Premises Server Hosting (Nginx / PM2)
If you want to host the dashboard on a central corporate server to review alerts gathered from target shares:

### 1. Build and Host the React Frontend
1. Build the production build assets:
   ```bash
   cd frontend
   npm install
   npm run build
   ```
2. This creates a `dist/` directory containing static HTML, CSS, and JS.
3. Host this `dist/` folder using a standard web server (like **Nginx** or **IIS**).
   * **Nginx Configuration Snippet**:
     ```nginx
     server {
         listen 80;
         server_name dlp.local;

         location / {
             root /path/to/project4/frontend/dist;
             index index.html;
             try_files $uri /index.html;
         }

         # Proxy API and WebSocket traffic to the python backend
         location /api {
             proxy_pass http://127.0.0.1:8000;
         }
         location /ws {
             proxy_pass http://127.0.0.1:8000;
             proxy_http_version 1.1;
             proxy_set_header Upgrade $http_upgrade;
             proxy_set_header Connection "Upgrade";
         }
     }
     ```

### 2. Run the FastAPI Backend as a Daemon
To ensure the backend runs persistently as a system daemon, manage it using a process manager like **PM2** or **NSSM (Non-Sucking Service Manager)**:
```bash
# Using PM2
pm2 start uvicorn --name "dlp-backend" -- main:app --host 127.0.0.1 --port 8000
pm2 save
```

---

## Method 3: Running as a Persistent Windows Service
To prevent users from closing the command prompt or ending the process, you can configure the backend program to run as a persistent Windows Service.

1. Download **NSSM** (https://nssm.cc/).
2. Run the NSSM configuration window:
   ```cmd
   nssm install DlpAgentService
   ```
3. Set the configuration details in the popup:
   * **Path**: Select your Python executable (e.g. `C:\Users\...\python.exe`).
   * **Startup directory**: Path to your `backend/` folder.
   * **Arguments**: `main.py`
4. Click **Install service**. You can now manage it (Start/Stop) through the native Windows Services panel (`services.msc`).
