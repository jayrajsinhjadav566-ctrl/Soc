from flask import Flask, render_template, request, redirect, url_for, flash
from database import init_db, get_connection, set_alert_status
from collector import import_sample_logs, collect_windows_security_events

app = Flask(__name__)
app.secret_key = "change-this-local-lab-secret"
init_db()

@app.route("/")
def dashboard():
    status = request.args.get("status", "all")
    severity = request.args.get("severity", "all")
    conn = get_connection()
    query = """
        SELECT a.*, e.timestamp, e.event_id, e.username, e.source_ip, e.message
        FROM alerts a JOIN events e ON e.id = a.event_id_ref
        WHERE 1=1
    """
    params = []
    if status != "all":
        query += " AND a.status = ?"
        params.append(status)
    if severity != "all":
        query += " AND a.severity = ?"
        params.append(severity.upper())
    query += " ORDER BY a.created_at DESC LIMIT 100"
    alerts = conn.execute(query, params).fetchall()
    events = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT 20"
    ).fetchall()
    counts = {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "open": conn.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'").fetchone()[0],
        "high": conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND status='Open'").fetchone()[0],
    }
    conn.close()
    return render_template("dashboard.html", alerts=alerts, events=events,
                           counts=counts, status=status, severity=severity)

@app.post("/import-samples")
def import_samples():
    count = import_sample_logs()
    flash(f"Imported {count} new sample event(s). Detection rules were applied.", "success")
    return redirect(url_for("dashboard"))

@app.post("/collect-windows")
def collect_windows():
    try:
        count = collect_windows_security_events()
        flash(f"Collected {count} Windows Security event(s).", "success")
    except Exception as exc:
        flash(f"Windows log collection failed: {exc}. Try running VS Code as Administrator; sample mode still works.", "error")
    return redirect(url_for("dashboard"))

@app.post("/alert/<int:alert_id>/status")
def update_status(alert_id):
    new_status = request.form.get("status", "Open")
    if new_status not in {"Open", "Investigating", "Closed"}:
        new_status = "Open"
    set_alert_status(alert_id, new_status)
    flash(f"Alert #{alert_id} status updated to {new_status}.", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    # Local-only by design: do not expose this training dashboard to the internet.
    app.run(host="127.0.0.1", port=5000, debug=True)
