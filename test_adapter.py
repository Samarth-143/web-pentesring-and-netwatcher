import sys, os, re
os.environ.setdefault('SUPABASE_URL', 'test')
os.environ.setdefault('SUPABASE_KEY', 'test')
sys.path.insert(0, 'phantom/backend')
from app.supabase_db import _parse_sql_where

# Test 1: table prefix
where = "users.username = 'admin'"
filters = _parse_sql_where(where)
print("Test 1:", filters)

# Test 2: IN clause
where2 = "scan_sessions.overall_risk IN ('HIGH', 'CRITICAL')"
filters2 = _parse_sql_where(where2)
print("Test 2:", filters2)

# Test 3: timestamp
where3 = "scan_sessions.created_at >= TIMESTAMP '2026-06-21 00:00:00'"
filters3 = _parse_sql_where(where3)
print("Test 3:", filters3)

# Test 4: multiple AND
where4 = "scan_sessions.id = 5 AND scan_sessions.user_id = 1"
filters4 = _parse_sql_where(where4)
print("Test 4:", filters4)

# Test 5: is null
where5 = "users.email IS NULL"
filters5 = _parse_sql_where(where5)
print("Test 5:", filters5)
