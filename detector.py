from datetime import datetime, timedelta
from database import get_connection

FAILED_LOGON_IDS = {"4625", "failed_login"}
SUSPICIOUS_IDS = {"1102", "security_log_cleared"}

def run_detection_for_event(event_id):
    """Apply simple, explainable training rules to one saved event."""
    with get_connection() as conn:
        event = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if not event:
            return
        eid = str(event["event_id"])
        if eid in FAILED_LOGON_IDS:
            # Five failures from the same source IP/user in a rolling 5-minute window.
            try:
                current = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                current = datetime.now()
            cutoff = (current - timedelta(minutes=5)).isoformat()
            failures = conn.execute("""
                SELECT COUNT(*) FROM events
                WHERE event_id IN ('4625','failed_login')
                  AND source_ip=? AND username=? AND timestamp >= ? AND timestamp <= ?
            """, (event["source_ip"], event["username"], cutoff, event["timestamp"])).fetchone()[0]
            if failures >= 5:
                conn.execute("""
                    INSERT OR IGNORE INTO alerts
                    (event_id_ref, rule_name, severity, description)
                    VALUES (?, ?, ?, ?)
                """, (event_id, "Repeated Failed Logons", "HIGH",
                      f"{failures} failed logons for user '{event['username']}' from {event['source_ip']} within 5 minutes. Verify whether this is expected."))
        if eid in SUSPICIOUS_IDS:
            conn.execute("""
                INSERT OR IGNORE INTO alerts
                (event_id_ref, rule_name, severity, description)
                VALUES (?, ?, ?, ?)
            """, (event_id, "Security Log Cleared", "HIGH",
                  "A security-log-cleared event was observed. Confirm authorization and review surrounding events."))

def run_detection_for_all():
    with get_connection() as conn:
        ids = [row[0] for row in conn.execute("SELECT id FROM events ORDER BY timestamp, id").fetchall()]
    for event_id in ids:
        run_detection_for_event(event_id)
