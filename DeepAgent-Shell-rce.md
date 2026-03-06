# Remote Code Execution in Aix-DB

**Vendor:** http://www.aixhub.top/
**Software:** https://github.com/apconw/Aix-DB

**Affected Version**: v1.2.3

---

## 1. Overview

The Deep Research (DeepAgent) feature uses the third-party `deepagents` library to build an LLM agent. The agent is created with `FilesystemBackend` as its backend, which inherits from `BackendProtocol` and does **not** implement `SandboxBackendProtocol`, so in theory the `execute` tool should not be available.

However, real-world testing confirms that **the LLM Agent can execute arbitrary commands on the server OS**, including listing directories, reading files, writing files, and running system commands (e.g., `id`), achieving full RCE.

This is because the `deepagents` framework's `FilesystemMiddleware` automatically injects `ls`, `read_file`, `write_file`, `edit_file`, `glob`, and `grep` tools. Under `FilesystemBackend` with the default `virtual_mode=False`, these tools can **directly operate on any file on the host server** with no path restrictions whatsoever.

An attacker only needs to instruct the Agent using natural language in the chat interface to read arbitrary files, write arbitrary files, or execute commands — equivalent to having full filesystem access at the privilege level of the server process. The SubAgent mechanism further expands the attack surface.

---

## 2. Vulnerability Call Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Attacker enters malicious instruction in "Deep Research" chat    │
│    e.g.: "What's in the current directory"                          │
│          "Write the output of the id command to /tmp/eee"           │
│    Frontend calls /sanic/deep_research/get_answer                   │
└───────────────────────────────┬─────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 2. Backend route receives request                                   │
│    controllers/llm_chat_api.py → DeepAgent.run_agent()              │
└───────────────────────────────┬─────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Deep Agent creation                                              │
│    agent/deepagent/deep_research_agent.py (lines 406-412)           │
│                                                                     │
│    agent = create_deep_agent(                                       │
│        model=model,                                                 │
│        memory=[...],                                                │
│        skills=[os.path.join(current_dir, "skills/")],              │
│        tools=sql_tools,                                             │
│        backend=FilesystemBackend(root_dir=current_dir),  # ← KEY!  │
│    )                                                                │
│                                                                     │
│    FilesystemBackend defaults to virtual_mode=False, no path limits │
└───────────────────────────────┬─────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 4. deepagents framework auto-injects tools                          │
│    deepagents/graph.py → create_deep_agent() (lines 226-251)       │
│                                                                     │
│    deepagent_middleware = [                                          │
│        TodoListMiddleware(),                                        │
│        MemoryMiddleware(...),                                       │
│        SkillsMiddleware(...),                                       │
│        FilesystemMiddleware(backend=FilesystemBackend),  # ← tools  │
│        SubAgentMiddleware(...),  # ← SubAgents inherit these tools  │
│        ...                                                          │
│    ]                                                                │
│                                                                     │
│    FilesystemMiddleware auto-injects the following tools:            │
│    - ls: list any directory                                         │
│    - read_file: read any file                                       │
│    - write_file: write any file                                     │
│    - edit_file: edit any file                                       │
│    - glob: search any path                                          │
│    - grep: search any file contents                                 │
│    - execute: shell execution (depends on Sandbox implementation)   │
└───────────────────────────────┬─────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 5. FilesystemBackend path resolution - NO security restrictions     │
│    deepagents/backends/filesystem.py (lines 112-146)                │
│                                                                     │
│    def _resolve_path(self, key: str) -> Path:                       │
│        if self.virtual_mode:    # ← Default False, takes else path  │
│            ...  # Has path restrictions                             │
│        path = Path(key)                                             │
│        if path.is_absolute():                                       │
│            return path            # ← Absolute path returned as-is! │
│        return (self.cwd / path).resolve()                           │
│                                                                     │
│    Attacker can make agent access:                                  │
│    - /etc/passwd, /etc/shadow                                       │
│    - /proc/self/environ (environment variables / secrets)           │
│    - Any config file (.env, database passwords, etc.)               │
└───────────────────────────────┬─────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 6. LLM Agent executes operations                                    │
│                                                                     │
│    User: "What's in the config module"                              │
│    Agent calls: ls(path="/path/to/project/config")                  │
│    → Returns directory listing                                      │
│                                                                     │
│    User: "What's in the current directory"                          │
│    Agent calls: ls(path="/")                                        │
│    → Returns full server root directory listing                     │
│                                                                     │
│    User: "Write the id command output to /tmp/eee"                  │
│    Agent via tool chain: execute cmd → write_file(path="/tmp/eee")  │
│    → File successfully written to server                            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Proof of Concept (PoC)

### 3.1 Prerequisites

-   An account with access to the "Deep Research" feature
-   At least one datasource configured in the system

### 3.2 Attack Examples

#### PoC 1: Reading Internal Project Files

Enter in the Deep Research chat:

```
what is  in config
```

**Agent Response**:

```
__init__.py
__pycache__/
load_env.py
logging.conf
```

The Agent successfully called the `ls` tool to list the config directory contents on the server, exposing internal project structure.

---

#### PoC 2: Listing Server Root Directory

Enter in the Deep Research chat:

```
what is in the current dir?
```

**Agent Response**:

```
.file
.vol/
Applications/
Library/
Network/
System/
Users/
Volumes/
bin/
cores/
dev/
etc/
home/
opt/
private/
sbin/
tmp/
usr/
var/
This is the file and folder listing. Let me know which section you'd like to explore.
```

The Agent successfully listed the full contents of the server OS root directory `/`, demonstrating unrestricted filesystem traversal capability.

---

#### PoC 3: Executing System Commands and Writing to File (RCE)

Enter in the Deep Research chat:

```
execute 'id' and put result in tmp/eee
```

**Agent Response**:

```
result has been put in /tmp/eee。
```

**Server-side Verification**:

```bash
➜  ~ cat /tmp/eee
uid=0(root) gid=0(root) groups=0(root)%
➜  ~
```

**Actual Result**: The `id` command output was indeed written to the `/tmp/eee` file, and the process was running with **root** privileges, achieving full RCE.

### 3.3 Impact

-   **Arbitrary File Read**: Read `/etc/passwd`, `.env`, database credentials, and other sensitive files
-   **Arbitrary File Write**: Write webshells, crontab entries, SSH public keys, etc.
-   **Arbitrary Command Execution**: Execute system commands through the LLM agent tool chain
-   **Information Disclosure**: Full exposure of project source code, environment variables, secrets
-   **Reverse Shell**: Plant reverse shell scripts via file write capability
-   **Lateral Movement**: Leverage server access to pivot into internal network systems

---

## 4. Root Cause Analysis

### 4.1 FilesystemBackend Has No Path Restrictions by Default

**File**: `agent/deepagent/deep_research_agent.py` (line 411)

```python
backend=FilesystemBackend(root_dir=current_dir),
```

The `virtual_mode` parameter of `FilesystemBackend` defaults to `False`. In this mode:

**File**: `deepagents/backends/filesystem.py` (lines 142-146)

```python
def _resolve_path(self, key: str) -> Path:
    if self.virtual_mode:
        ...  # Has path traversal protection
    # ❌ Non virtual_mode: absolute paths returned directly, no restrictions
    path = Path(key)
    if path.is_absolute():
        return path  # Direct access to any absolute path!
    return (self.cwd / path).resolve()
```

**The `FilesystemBackend` documentation itself explicitly warns**:

> When `virtual_mode=False` (default): Provides **no security** - agents can access any file using absolute paths or `..` sequences.
>
> **Inappropriate use cases:** Web servers or HTTP APIs

The project uses the default non-virtual_mode in a Web API service context (Sanic server), violating the library's own security usage guidelines.

### 4.2 FilesystemMiddleware Auto-Injects Dangerous Tools

**File**: `deepagents/middleware/filesystem.py` (lines 464-472)

```python
self.tools = [
    self._create_ls_tool(),          # List any directory
    self._create_read_file_tool(),   # Read any file
    self._create_write_file_tool(),  # Write any file
    self._create_edit_file_tool(),   # Edit any file
    self._create_glob_tool(),        # Search any path
    self._create_grep_tool(),        # Search any file contents
    self._create_execute_tool(),     # Shell command execution
]
```

These tools are automatically injected by `create_deep_agent` into both the main Agent and all SubAgents without explicit configuration.

### 4.3 SubAgents Inherit All Tools and Backend

**File**: `deepagents/graph.py` (lines 155-179)

The General Purpose SubAgent inherits the same `FilesystemMiddleware` and backend, having identical filesystem operation capabilities as the main Agent, expanding the attack surface.

### 4.4 User Input Directly Drives Agent Decisions

**File**: `agent/deepagent/deep_research_agent.py` (lines 595-597)

```python
stream_iter = agent.astream(
    input={"messages": [HumanMessage(content=query)]},  # ← User input passed directly
    ...
)
```

User natural language input is passed directly as instructions to the LLM Agent, which autonomously decides which tools to invoke. There is no intermediate layer to filter or restrict user intent.
