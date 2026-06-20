import sqlite3

db_path = "backend/phantom.db"
conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("UPDATE scan_sessions SET status = 'error' WHERE status = 'running'")
conn.commit()
print("Stuck scans cleared.")
conn.close()
