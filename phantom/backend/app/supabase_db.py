"""
Supabase REST API Database Adapter

Provides a SQLAlchemy-session-like interface using Supabase's REST API (PostgREST)
over HTTPS (port 443). Works on HuggingFace free tier where outbound port 5432 is blocked.
"""
import os
import json
import logging
import datetime
from typing import Any, Optional, List
import httpx

logger = logging.getLogger("phantom.supabase_db")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Table name mapping (SQLAlchemy model class -> Supabase table name)
_TABLE_MAP = {
    "User": "users",
    "ScanSession": "scan_sessions",
    "ScanResult": "scan_results",
    "Alert": "alerts",
    "ScanReport": "scan_reports",
}

# Column mapping (field name -> column name) for tables with different names
# In our case, all field names match column names, so this is identity
_PK_MAP = {
    "users": "id",
    "scan_sessions": "id",
    "scan_results": "id",
    "alerts": "id",
    "scan_reports": "id",
}


class _Scalars:
    """Mimics SQLAlchemy Result.scalars()"""
    def __init__(self, rows: list):
        self._rows = rows

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return self._rows

    def one(self):
        if len(self._rows) == 1:
            return self._rows[0]
        if len(self._rows) == 0:
            raise ValueError("No rows returned")
        raise ValueError("Multiple rows returned")

    def one_or_none(self):
        if len(self._rows) == 1:
            return self._rows[0]
        if len(self._rows) == 0:
            return None
        raise ValueError("Multiple rows returned")


class _Result:
    """Mimics SQLAlchemy Result"""
    def __init__(self, rows: list):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)

    def scalar_one(self):
        if len(self._rows) == 1:
            row = self._rows[0]
            # func.count returns a dict with 'count' key
            if isinstance(row, dict) and "count" in row:
                return row["count"]
            # If it's a tuple/list, return the first element
            if isinstance(row, (list, tuple)):
                return row[0]
            return row
        if len(self._rows) == 0:
            return 0
        raise ValueError("Multiple rows returned")

    def all(self):
        return self._rows


class _ModelProxy:
    """Wraps a dict to behave like an ORM model instance with attribute access."""
    def __init__(self, data: dict, model_class=None):
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "_model_class", model_class)
        object.__setattr__(self, "_dirty", set())

    def __getattr__(self, name):
        data = object.__getattribute__(self, "_data")
        if name in data:
            return data[name]
        raise AttributeError(f"Column '{name}' not found")

    def __setattr__(self, name, value):
        data = object.__getattribute__(self, "_data")
        dirty = object.__getattribute__(self, "_dirty")
        data[name] = value
        dirty.add(name)

    def _get_table_name(self):
        model_class = object.__getattribute__(self, "_model_class")
        if model_class:
            return _TABLE_MAP.get(model_class.__name__, model_class.__tablename__)
        return None

    def _to_dict(self):
        return dict(object.__getattribute__(self, "_data"))


class _GroupByAggregator:
    """Handles GROUP BY queries by fetching all data and aggregating in Python."""
    
    @staticmethod
    def aggregate(table: str, rows: list, group_cols: list, count_col: str = None) -> list:
        """
        Group rows by group_cols and count them.
        Returns list of tuples like (group_val, count).
        """
        from collections import Counter
        
        # Build group keys
        groups = Counter()
        for row in rows:
            if isinstance(row, dict):
                key = tuple(row.get(col) for col in group_cols)
            else:
                key = tuple(getattr(row, col, None) for col in group_cols)
            groups[key] += 1
        
        # Convert to list of tuples
        result = []
        for key, count in groups.items():
            if len(key) == 1:
                result.append((key[0], count))
            else:
                result.append((*key, count))
        
        return result


class _SelectParser:
    """Parses SQLAlchemy select() statements and converts to REST API parameters."""
    
    @staticmethod
    def parse(stmt) -> dict:
        """
        Returns:
            table: str - table name
            columns: list - column names (or ['*'])
            filters: list of (op, col, val) tuples
            order: list of (col, desc) tuples
            limit: int or None
            offset: int or None
            is_count: bool
            is_group: bool
            group_cols: list
        """
        result = {
            "table": None,
            "columns": ["*"],
            "filters": [],
            "order": [],
            "limit": None,
            "offset": None,
            "is_count": False,
            "count_column": None,
            "is_group": False,
            "group_cols": [],
            "in_filter": None,
        }
        
        # Extract from the statement's columns
        if hasattr(stmt, "columns"):
            for col in stmt.columns:
                col_str = str(col)
                # Handle func.count
                if "count(" in col_str.lower():
                    result["is_count"] = True
                    result["count_column"] = col_str
                else:
                    # Extract just the column name
                    if "." in col_str:
                        col_name = col_str.split(".")[-1]
                    else:
                        col_name = col_str
                    result["columns"].append(col_name)
        
        # Extract table from FROM clause
        if hasattr(stmt, "froms") and stmt.froms:
            from_table = stmt.froms[0]
            table_name = getattr(from_table, "name", None)
            if table_name:
                result["table"] = table_name
        
        # Extract where clauses
        if hasattr(stmt, "whereclause") and stmt.whereclause is not None:
            _parse_where(stmt.whereclause, result)
        
        # Extract order by
        if hasattr(stmt, "order_by_clauses"):
            for order_clause in stmt.order_by_clauses:
                _parse_order(order_clause, result)
        
        # Extract limit/offset
        if hasattr(stmt, "_limit") and stmt._limit is not None:
            result["limit"] = stmt._limit
        if hasattr(stmt, "_offset") and stmt._offset is not None:
            result["offset"] = stmt._offset
            
        # Extract group by
        if hasattr(stmt, "group_by") and stmt.group_by:
            result["is_group"] = True
            for g in stmt.group_by:
                g_str = str(g)
                if "." in g_str:
                    g_str = g_str.split(".")[-1]
                result["group_cols"].append(g_str)
        
        return result


def _parse_where(clause, result):
    """Recursively parse WHERE clause."""
    from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList, Grouping
    from sqlalchemy import and_, or_, not_
    
    if isinstance(clause, BooleanClauseList):
        # Handle AND/OR
        if hasattr(clause, "operator") and hasattr(clause.operator, "__name__"):
            op_name = clause.operator.__name__
        else:
            op_name = "and"
        
        for sub in clause.clauses:
            _parse_where(sub, result)
        return
    
    if isinstance(clause, Grouping):
        _parse_where(clause.element, result)
        return
    
    if isinstance(clause, BinaryExpression):
        left = str(clause.left)
        right = clause.right
        operator_type = clause.operator
        
        # Extract column name
        if "." in left:
            col = left.split(".")[-1]
        else:
            col = left
        
        # Get the value
        if hasattr(right, "value"):
            val = right.value
        elif hasattr(right, "element") and hasattr(right.element, "value"):
            val = right.element.value
        else:
            val = str(right)
            try:
                val = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Determine operator
        from sqlalchemy.operators import eq_op, ne_op, lt_op, le_op, gt_op, ge_op, in_op, like_op, notin_op
        
        op_map = {
            eq_op: "eq",
            ne_op: "neq",  # PostgREST doesn't support neq directly, we'll handle it
            lt_op: "lt",
            le_op: "lte",
            gt_op: "gt",
            ge_op: "gte",
            in_op: "in",
            like_op: "like",
            notin_op: "notin",
        }
        
        op_name = op_map.get(operator_type, "eq")
        
        if op_name == "in":
            result["in_filter"] = (col, val)
        else:
            result["filters"].append((op_name, col, val))


def _parse_order(clause, result):
    """Parse ORDER BY clause."""
    from sqlalchemy.sql.elements import UnaryExpression
    from sqlalchemy import desc as sa_desc, asc as sa_asc
    
    if isinstance(clause, UnaryExpression):
        col_str = str(clause.element)
        if "." in col_str:
            col_str = col_str.split(".")[-1]
        desc = clause.operator.__name__ == "desc_op" if hasattr(clause.operator, "__name__") else False
        result["order"].append((col_str, desc))
    else:
        col_str = str(clause)
        if "." in col_str:
            col_str = col_str.split(".")[-1]
        result["order"].append((col_str, False))


class SupabaseSession:
    """
    Mimics SQLAlchemy AsyncSession using Supabase REST API.
    
    Supports:
    - execute(select(Model).where(...))
    - add(obj)
    - commit()
    - refresh(obj)
    - get(Model, pk)
    - delete(obj)
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
        """Execute a SQLAlchemy select statement via Supabase REST API."""
        parsed = _SelectParser.parse(stmt)
        
        if not parsed["table"]:
            raise ValueError("Could not determine table name from statement")
        
        table = parsed["table"]
        
        # Build query parameters
        params = {}
        
        # Select columns
        if parsed["columns"] and parsed["columns"] != ["*"]:
            params["select"] = ",".join(parsed["columns"])
        
        # Apply filters
        for op, col, val in parsed["filters"]:
            if op == "eq":
                params[col] = f"eq.{val}"
            elif op == "neq":
                # PostgREST: use not.eq
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
        
        # Handle IN filter
        if parsed["in_filter"]:
            col, vals = parsed["in_filter"]
            if isinstance(vals, (list, tuple)):
                params["or"] = ",".join(f"{col}.eq.{v}" for v in vals)
        
        # Order
        if parsed["order"]:
            order_parts = []
            for col, desc in parsed["order"]:
                order_parts.append(f"{col}.{'desc' if desc else 'asc'}")
            params["order"] = ",".join(order_parts)
        
        # Pagination
        if parsed["limit"] is not None:
            # Supabase uses Range header for pagination
            offset = parsed["offset"] or 0
            end = offset + parsed["limit"] - 1
            
            # For count queries, we need a different approach
            if parsed["is_count"]:
                params["select"] = "id"
            
            headers = {
                "Range": f"{offset}-{end}",
                "Prefer": "count=exact",
            }
        else:
            headers = {}
        
        try:
            response = await self._client.get(f"/rest/v1/{table}", params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            # Handle group by queries
            if parsed["is_group"] and parsed["group_cols"]:
                # Fetch all data (remove limit/offset for aggregation)
                agg_result = _GroupByAggregator.aggregate(
                    table, data, parsed["group_cols"]
                )
                return _Result(agg_result)
            
            # Handle count queries
            if parsed["is_count"]:
                # Get total count from Content-Range header
                content_range = response.headers.get("content-range", "")
                if "/" in content_range:
                    total = int(content_range.split("/")[-1])
                else:
                    total = len(data)
                return _Result([{"count": total}])
            
            # Wrap results in model proxies
            # Try to infer model class from table name
            model_class = None
            for name, tbl in _TABLE_MAP.items():
                if tbl == table:
                    model_class = name
                    break
            
            wrapped = [_ModelProxy(row) for row in data]
            return _Result(wrapped)
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Supabase REST error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Supabase REST error: {e}")
            raise
    
    async def get(self, model_class, pk_value) -> Optional[_ModelProxy]:
        """Fetch a single record by primary key."""
        table = _TABLE_MAP.get(model_class.__name__, getattr(model_class, "__tablename__", None))
        if not table:
            raise ValueError(f"Unknown model: {model_class}")
        
        pk_col = _PK_MAP.get(table, "id")
        
        try:
            response = await self._client.get(
                f"/rest/v1/{table}",
                params={pk_col: f"eq.{pk_value}", "select": "*"},
            )
            response.raise_for_status()
            data = response.json()
            
            if data:
                return _ModelProxy(data[0], model_class)
            return None
            
        except Exception as e:
            logger.error(f"Supabase get error: {e}")
            raise
    
    async def add(self, obj):
        """Stage an insert (actual insert happens on commit)."""
        self._pending_inserts.append(obj)
    
    async def delete(self, obj):
        """Stage a delete (actual delete happens on commit).
        
        Handles cascade deletes manually since REST API doesn't support CASCADE.
        When deleting a ScanSession, also deletes child ScanResults and Alerts.
        """
        # Get table name to check for cascade
        table = obj._get_table_name()
        data = obj._to_dict()
        pk_val = data.get("id")
        
        if pk_val is not None and table == "scan_sessions":
            # Manual cascade: delete children first
            try:
                # Delete scan_results for this session
                await self._client.delete(
                    "/rest/v1/scan_results",
                    params={"session_id": f"eq.{pk_val}"},
                )
                # Delete alerts for this session
                await self._client.delete(
                    "/rest/v1/alerts",
                    params={"session_id": f"eq.{pk_val}"},
                )
            except Exception as e:
                logger.warning(f"Cascade delete warning: {e}")
        
        if pk_val is not None and table == "users":
            # Manual cascade: delete user's children
            try:
                # Delete user's scan_sessions (which cascades to results/alerts)
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
                # Delete user's reports
                await self._client.delete("/rest/v1/scan_reports", params={"user_id": f"eq.{pk_val}"})
            except Exception as e:
                logger.warning(f"Cascade delete warning: {e}")
        
        self._pending_deletes.append(obj)
    
    async def commit(self):
        """Flush all pending inserts, updates, and deletes."""
        # Process inserts
        for obj in self._pending_inserts:
            table = obj._get_table_name()
            if not table:
                model_class = object.__getattribute__(obj, "_model_class")
                table = _TABLE_MAP.get(model_class.__name__, getattr(model_class, "__tablename__", None))
            
            data = obj._to_dict()
            
            # Remove None values (let Supabase use defaults)
            # Actually, send all fields to be safe
            try:
                response = await self._client.post(
                    f"/rest/v1/{table}",
                    json=data,
                    headers={"Prefer": "return=representation"},
                )
                response.raise_for_status()
                result = response.json()
                
                # Update the object with returned data (including generated id, etc.)
                if result and len(result) > 0:
                    returned = result[0]
                    obj_data = object.__getattribute__(obj, "_data")
                    for k, v in returned.items():
                        if k not in obj_data or obj_data[k] is None:
                            obj_data[k] = v
                    
            except httpx.HTTPStatusError as e:
                logger.error(f"Supabase insert error on {table}: {e.response.status_code} - {e.response.text}")
                raise
            except Exception as e:
                logger.error(f"Supabase insert error on {table}: {e}")
                raise
        
        self._pending_inserts.clear()
        
        # Process deletes
        for obj in self._pending_deletes:
            table = obj._get_table_name()
            if not table:
                model_class = object.__getattribute__(obj, "_model_class")
                table = _TABLE_MAP.get(model_class.__name__, getattr(model_class, "__tablename__", None))
            
            data = obj._to_dict()
            pk_val = data.get("id")
            
            if pk_val is not None:
                try:
                    response = await self._client.delete(
                        f"/rest/v1/{table}",
                        params={"id": f"eq.{pk_val}"},
                    )
                    response.raise_for_status()
                except Exception as e:
                    logger.error(f"Supabase delete error on {table}: {e}")
                    raise
        
        self._pending_deletes.clear()
        
        # Process updates (objects that were modified after being loaded)
        for obj in self._pending_updates:
            table = obj._get_table_name()
            data = obj._to_dict()
            pk_val = data.get("id")
            
            if pk_val is not None:
                # Only send dirty fields
                dirty = object.__getattribute__(obj, "_dirty")
                if dirty:
                    update_data = {k: v for k, v in data.items() if k in dirty and k != "id"}
                    try:
                        response = await self._client.patch(
                            f"/rest/v1/{table}",
                            params={"id": f"eq.{pk_val}"},
                            json=update_data,
                        )
                        response.raise_for_status()
                    except Exception as e:
                        logger.error(f"Supabase update error on {table}: {e}")
                        raise
        
        self._pending_updates.clear()
    
    async def refresh(self, obj):
        """Re-fetch an object from the database to get auto-generated values."""
        table = obj._get_table_name()
        data = obj._to_dict()
        pk_val = data.get("id")
        
        if pk_val is None:
            return
        
        try:
            response = await self._client.get(
                f"/rest/v1/{table}",
                params={"id": f"eq.{pk_val}", "select": "*"},
            )
            response.raise_for_status()
            result = response.json()
            
            if result:
                obj_data = object.__getattribute__(obj, "_data")
                obj_data.update(result[0])
                
        except Exception as e:
            logger.error(f"Supabase refresh error: {e}")
    
    def track_update(self, obj):
        """Mark an object for update tracking (call after modifying attributes)."""
        if obj not in self._pending_updates:
            self._pending_updates.append(obj)


class SupabaseResult:
    """Helper for select queries that returns SupabaseSession."""
    pass


# Module-level session instance (will be initialized on startup)
_session: Optional[SupabaseSession] = None


async def get_supabase_session() -> SupabaseSession:
    """Get the Supabase session singleton."""
    global _session
    if _session is None:
        _session = SupabaseSession()
    return _session


async def close_supabase_session():
    """Close the Supabase session."""
    global _session
    if _session:
        await _session.close()
        _session = None
