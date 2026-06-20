"""
Supabase REST API Database Adapter — v2 (robust)

Uses SQLAlchemy's SQL compilation to convert queries to Supabase REST API calls.
Falls back gracefully on HF free tier where outbound port 5432 is blocked.
"""
import os
import re
import json
import logging
import datetime
import httpx
from typing import Any, Optional
from urllib.parse import quote

logger = logging.getLogger("phantom.supabase_db")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

_TABLE_MAP = {
    "users": "users",
    "scan_sessions": "scan_sessions",
    "scan_results": "scan_results",
    "alerts": "alerts",
    "scan_reports": "scan_reports",
}


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return self._rows

    def one(self):
        if len(self._rows) == 1:
            return self._rows[0]
        raise ValueError(f"Expected 1 row, got {len(self._rows)}")

    def one_or_none(self):
        if len(self._rows) == 1:
            return self._rows[0]
        if not self._rows:
            return None
        raise ValueError(f"Expected 0 or 1 rows, got {len(self._rows)}")


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)

    def scalar_one(self):
        if not self._rows:
            return 0
        row = self._rows[0]
        if isinstance(row, dict) and "count" in row:
            return int(row["count"])
        if isinstance(row, (list, tuple)):
            return row[0]
        return row

    def all(self):
        return self._rows


class ModelProxy:
    """Dict wrapper that behaves like an ORM model with attribute access."""
    def __init__(self, data: dict, model_class=None):
        object.__setattr__(self, "_data", dict(data))
        object.__setattr__(self, "_model_class", model_class)
        object.__setattr__(self, "_dirty", set())

    def __getattr__(self, name):
        data = object.__getattribute__(self, "_data")
        if name in data:
            return data[name]
        raise AttributeError(name)

    def __setattr__(self, name, value):
        data = object.__getattribute__(self, "_data")
        dirty = object.__setattr__
        data[name] = value
        object.__getattribute__(self, "_dirty").add(name)

    def _get_table_name(self):
        mc = object.__getattribute__(self, "_model_class")
        if mc:
            return _TABLE_MAP.get(mc.__name__) or getattr(mc, "__tablename__", None)
        return None

    def _to_dict(self):
        return dict(object.__getattribute__(self, "_data"))


def _extract_table_from_stmt(stmt) -> Optional[str]:
    """Extract the primary table name from a SQLAlchemy select statement."""
    # Method 1: froms
    try:
        for from_clause in stmt.froms:
            name = getattr(from_clause, "name", None)
            if name:
                return name
            # Subquery or alias
            if hasattr(from_clause, "element"):
                name = getattr(from_clause.element, "name", None)
                if name:
                    return name
    except Exception:
        pass

    # Method 2: compile to SQL and regex-extract table
    try:
        from sqlalchemy.dialects import postgresql
        compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
        sql_str = str(compiled)
        # FROM table_name or INTO table_name or UPDATE table_name or DELETE FROM table_name
        m = re.search(r'\bFROM\s+(\w+)', sql_str, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r'\bINTO\s+(\w+)', sql_str, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r'\bUPDATE\s+(\w+)', sql_str, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass

    return None


def _compile_to_sql(stmt) -> str:
    """Compile a SQLAlchemy statement to a raw SQL string."""
    from sqlalchemy.dialects import postgresql
    try:
        compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
        return str(compiled)
    except Exception:
        return str(stmt)


def _parse_sql_where(sql_where: str) -> list:
    """Parse a SQL WHERE clause into PostgREST filter tuples."""
    filters = []

    # Pattern: column = 'value' / column = N / column IS NULL / column IS NOT NULL
    # Also: column IN (...) / column >= val / column <= val / column > val / column < val
    # Also: column LIKE 'pattern'

    # Split on AND (simple — doesn't handle OR, but we don't use OR in our queries)
    parts = re.split(r'\bAND\b', sql_where, flags=re.IGNORECASE)

    for part in parts:
        part = part.strip().strip('()')

        # IS NULL
        m = re.match(r'(\w+)\s+IS\s+NULL', part, re.IGNORECASE)
        if m:
            filters.append(("is.null", m.group(1), None))
            continue

        # IS NOT NULL
        m = re.match(r'(\w+)\s+IS\s+NOT\s+NULL', part, re.IGNORECASE)
        if m:
            filters.append(("not.is.null", m.group(1), None))
            continue

        # IN (val1, val2, ...)
        m = re.match(r'(\w+)\s+IN\s*\((.+)\)', part, re.IGNORECASE)
        if m:
            col = m.group(1)
            vals_str = m.group(2)
            vals = [v.strip().strip("'\"") for v in vals_str.split(',')]
            filters.append(("in", col, vals))
            continue

        # Comparison operators
        for op_pattern, op_name in [
            (r'>=', "gte"),
            (r'<=', "lte"),
            (r'!=', "neq"),
            (r'<>', "neq"),
            (r'>(?!=)', "gt"),
            (r'<(?!=)', "lt"),
            (r'LIKE', "like"),
            (r'=', "eq"),
        ]:
            m = re.match(rf'(\w+)\s*{op_pattern}\s*(.+)', part, re.IGNORECASE)
            if m:
                col = m.group(1)
                val_str = m.group(2).strip()

                # Parse value
                if val_str.upper() == 'NULL':
                    if op_name == "eq":
                        filters.append(("is.null", col, None))
                    else:
                        filters.append(("not.is.null", col, None))
                elif val_str.startswith("'") and val_str.endswith("'"):
                    val = val_str[1:-1]
                    # Handle timestamp values
                    if 'T' in val and ':' in val:
                        try:
                            val = datetime.datetime.fromisoformat(val.replace('+00', '+00:00')).isoformat()
                        except Exception:
                            pass
                    filters.append((op_name, col, val))
                elif val_str.startswith("TIMESTAMP"):
                    # TIMESTAMP 'value'
                    inner = val_str.replace("TIMESTAMP", "").strip().strip("'\"")
                    try:
                        val = datetime.datetime.fromisoformat(inner.replace('+00', '+00:00')).isoformat()
                    except Exception:
                        val = inner
                    filters.append((op_name, col, val))
                else:
                    # Numeric or boolean
                    if val_str.lower() == 'true':
                        val = True
                    elif val_str.lower() == 'false':
                        val = False
                    else:
                        try:
                            val = int(val_str)
                        except ValueError:
                            try:
                                val = float(val_str)
                            except ValueError:
                                val = val_str.strip("'\"")
                    filters.append((op_name, col, val))
                break

    return filters


def _parse_order_from_sql(sql: str) -> list:
    """Extract ORDER BY from compiled SQL."""
    orders = []
    m = re.search(r'ORDER\s+BY\s+(.+?)(?:\s+LIMIT\s|\s+OFFSET\s|$)', sql, re.IGNORECASE)
    if m:
        order_part = m.group(1)
        for item in order_part.split(','):
            item = item.strip()
            if item.upper().endswith(' DESC'):
                orders.append((item[:-5].strip(), True))
            elif item.upper().endswith(' ASC'):
                orders.append((item[:-4].strip(), False))
            else:
                orders.append((item, False))
    return orders


class SupabaseSession:
    """
    Async session that translates SQLAlchemy select() to Supabase REST API calls.
    Also handles insert/update/delete via REST.
    """

    def __init__(self):
        self._pending_inserts = []
        self._pending_updates = []
        self._pending_deletes = []
        self._client = httpx.AsyncClient(
            base_url=SUPABASE_URL,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
            timeout=30.0,
        )

    async def close(self):
        await self._client.aclose()

    async def execute(self, stmt) -> _Result:
        """Execute a SQLAlchemy select() and translate to Supabase REST."""
        sql = _compile_to_sql(stmt)
        table = _extract_table_from_stmt(stmt)

        if not table:
            raise ValueError(f"Could not determine table from SQL: {sql}")

        logger.debug(f"REST execute: {sql}")

        # Detect COUNT query
        is_count = bool(re.search(r'\bCOUNT\s*\(', sql, re.IGNORECASE))

        # Detect GROUP BY
        group_match = re.search(r'GROUP\s+BY\s+(.+?)(?:\s+ORDER\s|\s+LIMIT\s|$)', sql, re.IGNORECASE)
        is_group = bool(group_match)

        # Extract WHERE clause
        where_match = re.search(r'WHERE\s+(.+?)(?:\s+GROUP\s|\s+ORDER\s|\s+LIMIT\s|\s+OFFSET\s|$)', sql, re.IGNORECASE)
        where_sql = where_match.group(1) if where_match else None

        # Extract ORDER BY
        orders = _parse_order_from_sql(sql)

        # Extract LIMIT/OFFSET
        limit_match = re.search(r'LIMIT\s+(\d+)', sql, re.IGNORECASE)
        offset_match = re.search(r'OFFSET\s+(\d+)', sql, re.IGNORECASE)
        limit = int(limit_match.group(1)) if limit_match else None
        offset = int(offset_match.group(1)) if offset_match else None

        # Build Supabase REST params
        params = {}
        headers = {}

        # WHERE filters
        if where_sql:
            filters = _parse_sql_where(where_sql)
            for op, col, val in filters:
                if op == "eq":
                    params[col] = f"eq.{val}"
                elif op == "neq":
                    params[col] = f"not.eq.{val}"
                elif op == "gt":
                    params[col] = f"gt.{val}"
                elif op == "gte":
                    params[col] = f"gte.{val}"
                elif op == "lt":
                    params[col] = f"lt.{val}"
                elif op == "lte":
                    params[col] = f"lte.{val}"
                elif op == "like":
                    params[col] = f"like.{val}"
                elif op == "in":
                    # PostgREST: or=(col.eq.v1,col.eq.v2)
                    or_parts = [f"{col}.eq.{v}" for v in val]
                    params["or"] = ",".join(or_parts)
                elif op == "is.null":
                    params[col] = "is.null"
                elif op == "not.is.null":
                    params[col] = "not.is.null"

        # ORDER BY
        if orders:
            order_parts = []
            for col, desc in orders:
                order_parts.append(f"{col}.{'desc' if desc else 'asc'}")
            params["order"] = ",".join(order_parts)

        # Pagination via Range header
        if limit is not None:
            start = offset or 0
            end = start + limit - 1
            headers["Range"] = f"{start}-{end}"
            headers["Prefer"] = "count=exact"

        try:
            response = await self._client.get(f"/rest/v1/{table}", params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"REST {e.response.status_code}: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"REST error: {e}")
            raise

        # Handle GROUP BY: aggregate client-side
        if is_group and group_match:
            group_cols_raw = group_match.group(1).strip()
            group_cols = [c.strip().split('.')[-1] for c in group_cols_raw.split(',')]
            from collections import Counter
            counter = Counter()
            for row in data:
                key = tuple(row.get(c) for c in group_cols)
                counter[key] += 1
            result_rows = [(list(k), v) if len(k) > 1 else (k[0], v) for k, v in counter.items()]
            return _Result(result_rows)

        # Handle COUNT
        if is_count:
            content_range = response.headers.get("content-range", "")
            if "/" in content_range:
                total = content_range.split("/")[-1]
                if total == "*":
                    total = len(data)
                else:
                    total = int(total)
            else:
                total = len(data)
            return _Result([{"count": total}])

        # Wrap in ModelProxy
        model_class = None
        for name, tbl in _TABLE_MAP.items():
            if tbl == table:
                from app import models
                model_class = getattr(models, name, None)
                break

        wrapped = [ModelProxy(row, model_class) for row in data]
        return _Result(wrapped)

    async def get(self, model_class, pk_value) -> Optional[ModelProxy]:
        """Fetch a single record by primary key."""
        table = _TABLE_MAP.get(model_class.__name__) or getattr(model_class, "__tablename__", None)
        if not table:
            raise ValueError(f"Unknown model: {model_class}")

        try:
            response = await self._client.get(
                f"/rest/v1/{table}",
                params={"id": f"eq.{pk_value}", "select": "*"},
            )
            response.raise_for_status()
            data = response.json()
            if data:
                return ModelProxy(data[0], model_class)
            return None
        except Exception as e:
            logger.error(f"REST get error: {e}")
            raise

    async def add(self, obj):
        """Stage an insert."""
        self._pending_inserts.append(obj)

    async def delete(self, obj):
        """Stage a delete with manual cascade."""
        table = obj._get_table_name()
        data = obj._to_dict()
        pk_val = data.get("id")

        # Manual cascade for scan_sessions
        if pk_val is not None and table == "scan_sessions":
            try:
                await self._client.delete("/rest/v1/scan_results", params={"session_id": f"eq.{pk_val}"})
                await self._client.delete("/rest/v1/alerts", params={"session_id": f"eq.{pk_val}"})
            except Exception as e:
                logger.warning(f"Cascade delete warning: {e}")

        # Manual cascade for users
        if pk_val is not None and table == "users":
            try:
                sessions_resp = await self._client.get(
                    "/rest/v1/scan_sessions",
                    params={"user_id": f"eq.{pk_val}", "select": "id"},
                )
                if sessions_resp.status_code == 200:
                    for s in sessions_resp.json():
                        sid = s.get("id")
                        if sid:
                            await self._client.delete("/rest/v1/scan_results", params={"session_id": f"eq.{sid}"})
                            await self._client.delete("/rest/v1/alerts", params={"session_id": f"eq.{sid}"})
                    await self._client.delete("/rest/v1/scan_sessions", params={"user_id": f"eq.{pk_val}"})
                await self._client.delete("/rest/v1/scan_reports", params={"user_id": f"eq.{pk_val}"})
            except Exception as e:
                logger.warning(f"Cascade delete warning: {e}")

        self._pending_deletes.append(obj)

    async def commit(self):
        """Flush all pending operations via REST."""
        for obj in self._pending_inserts:
            table = obj._get_table_name()
            data = obj._to_dict()
            try:
                resp = await self._client.post(
                    f"/rest/v1/{table}",
                    json=data,
                    headers={"Prefer": "return=representation"},
                )
                resp.raise_for_status()
                result = resp.json()
                if result:
                    obj_data = object.__getattribute__(obj, "_data")
                    obj_data.update(result[0])
            except httpx.HTTPStatusError as e:
                logger.error(f"REST insert {table}: {e.response.status_code} - {e.response.text}")
                raise
            except Exception as e:
                logger.error(f"REST insert {table}: {e}")
                raise
        self._pending_inserts.clear()

        for obj in self._pending_deletes:
            table = obj._get_table_name()
            data = obj._to_dict()
            pk_val = data.get("id")
            if pk_val is not None:
                try:
                    await self._client.delete(f"/rest/v1/{table}", params={"id": f"eq.{pk_val}"})
                except Exception as e:
                    logger.error(f"REST delete {table}: {e}")
                    raise
        self._pending_deletes.clear()

        for obj in self._pending_updates:
            table = obj._get_table_name()
            data = obj._to_dict()
            pk_val = data.get("id")
            dirty = object.__getattribute__(obj, "_dirty")
            if pk_val is not None and dirty:
                update_data = {k: v for k, v in data.items() if k in dirty and k != "id"}
                try:
                    await self._client.patch(
                        f"/rest/v1/{table}",
                        params={"id": f"eq.{pk_val}"},
                        json=update_data,
                    )
                except Exception as e:
                    logger.error(f"REST update {table}: {e}")
                    raise
        self._pending_updates.clear()

    async def refresh(self, obj):
        """Re-fetch an object to get auto-generated values."""
        table = obj._get_table_name()
        data = obj._to_dict()
        pk_val = data.get("id")
        if pk_val is None:
            return
        try:
            resp = await self._client.get(
                f"/rest/v1/{table}",
                params={"id": f"eq.{pk_val}", "select": "*"},
            )
            resp.raise_for_status()
            result = resp.json()
            if result:
                obj_data = object.__getattribute__(obj, "_data")
                obj_data.update(result[0])
        except Exception as e:
            logger.error(f"REST refresh: {e}")


# Singleton
_session: Optional[SupabaseSession] = None


async def get_supabase_session() -> SupabaseSession:
    global _session
    if _session is None:
        _session = SupabaseSession()
    return _session


async def close_supabase_session():
    global _session
    if _session:
        await _session.close()
        _session = None
