# SOC L1 Python SIEM Lab

A beginner-friendly local training project demonstrating event ingestion, simple detection rules, SQLite storage, and a Flask dashboard.

## Requirements
- Windows 10/11
- Python 3.10+ (recommended: Python 3.11 or 3.12)
- VS Code

## Setup (PowerShell terminal in VS Code)
1. Extract the ZIP file.
2. In VS Code, choose **File → Open Folder** and open `soc-l1-siem`.
3. Open **Terminal → New Terminal**. Confirm the terminal is inside the project folder.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt in VS Code instead:
   ```bat
   .venv\Scripts\activate.bat
   ```
   Or run Python without activating the environment:
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

5. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Start the web app:
   ```powershell
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser.
8. Click **Import sample logs**. The sample dataset includes five simulated failed logons from the same user/IP, which should create a HIGH alert, plus a simulated security-log-cleared event.

## Optional Windows Security Event Log collection
1. Install optional dependencies:
   ```powershell
   python -m pip install -r requirements-windows.txt
   ```
2. Close the app with `Ctrl+C`.
3. Reopen VS Code as Administrator if access is denied, then activate the environment and run `python app.py`.
4. Click **Collect Windows logs**. It attempts to read up to 200 recent Security log records and retains event IDs 4624, 4625, and 1102 where present.
5. Event fields and collection success depend on Windows audit configuration and permissions. The Windows collector is a learning example, not a production-grade parser.

## Detection rules
- **Repeated Failed Logons**: five or more Event ID 4625 (or sample `failed_login`) events for the same username/source IP within five minutes. Severity: HIGH.
- **Security Log Cleared**: Event ID 1102 (or sample `security_log_cleared`). Severity: HIGH.
- Event ID 4624 represents a successful logon and is retained as context but does not itself trigger an alert.

## Reset the lab
Stop the server with `Ctrl+C`. To reset stored data, delete `soc_lab.db` from the project folder, then restart `python app.py`. The database is recreated automatically.

## Safety and limitations
- Sample logs are synthetic and do not represent real incidents.
- The app binds to `127.0.0.1` so it is intended for local use only.
- This is a portfolio/learning project, not a replacement for an enterprise SIEM.
- Do not expose the Flask development server to the public internet.
- Windows log collection is optional; the sample dataset works without administrator rights.
