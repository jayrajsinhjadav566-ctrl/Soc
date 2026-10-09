import json
from pathlib import Path
from database import get_connection
from detector import run_detection_for_event, run_detection_for_all

ROOT = Path(__file__).resolve().parent
SAMPLE_FILE = ROOT / "logs" / "sample_events.json"

def save_event(item, source="sample"):
    required = ("timestamp", "event_id", "message")
    if any(not item.get(key) for key in required):
        return None
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO events
            (timestamp, event_id, username, source_ip, message, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (str(item["timestamp"]), str(item["event_id"]),
              str(item.get("username", "")), str(item.get("source_ip", "")),
              str(item["message"]), source))
        if cursor.rowcount == 1:
            return cursor.lastrowid
        row = conn.execute("""
            SELECT id FROM events WHERE timestamp=? AND event_id=? AND username=?
              AND source_ip=? AND message=?
        """, (str(item["timestamp"]), str(item["event_id"]),
              str(item.get("username", "")), str(item.get("source_ip", "")),
              str(item["message"]))).fetchone()
        return row["id"] if row else None

def import_sample_logs():
    with SAMPLE_FILE.open("r", encoding="utf-8") as handle:
        items = json.load(handle)
    new_count = 0
    for item in items:
        with get_connection() as conn:
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        save_event(item, "sample")
        with get_connection() as conn:
            after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        new_count += int(after > before)
    run_detection_for_all()
    return new_count

def collect_windows_security_events(limit=200):
    """Optional Windows collector. Requires pywin32 and permission to read Security log."""
    try:
        import win32evtlog
    except ImportError as exc:
        raise RuntimeError("pywin32 is not installed. Run: pip install pywin32") from exc

    server = "localhost"
    log_type = "Security"
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog(server, log_type)
    collected = 0
    try:
        records = []
        while len(records) < limit:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            records.extend(batch)
        for record in records[:limit]:
            event_id = str(record.EventID & 0xFFFF)
            if event_id not in {"4624", "4625", "1102"}:
                continue
            inserts = record.StringInserts or []
            username = str(inserts[5]) if event_id == "4625" and len(inserts) > 5 else ""
            source_ip = ""
            if event_id == "4625" and len(inserts) > 19:
                source_ip = str(inserts[19])
            ts = record.TimeGenerated.Format()
            item = {
                "timestamp": ts,
                "event_id": event_id,
                "username": username,
                "source_ip": source_ip,
                "message": f"Windows Security event {event_id}; computer={record.ComputerName}; record={record.RecordNumber}"
            }
            event_pk = save_event(item, "windows")
            if event_pk:
                collected += 1
        run_detection_for_all()
    finally:
        win32evtlog.CloseEventLog(handle)
    return collected
