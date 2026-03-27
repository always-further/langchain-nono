<div align="center">
<img src="assets/logo.png" alt="nono logo" width="500"/>


OS-enforced sandbox backend for [LangChain Deep Agents](https://github.com/langchain-ai/deepagents) using [nono](https://github.com/always-further/nono).

Run Langchain DeepAgents with python native, kernel-enforced sandboxing.

</div>

## Installation

```bash
pip install langchain-nono
```

## Usage

```python
import json

from deepagents import create_deep_agent
from langchain_nono import NonoSandbox
from nono_py import ProxyConfig, RouteConfig

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    proxy_config=ProxyConfig(
        allowed_hosts=["api.openai.com"],
        routes=[
            RouteConfig(
                prefix="/openai",
                upstream="https://api.openai.com",
                credential_key="openai-key",
            )
        ],
    ),
    block_network=True,
)

agent = create_deep_agent(
    backend=sandbox,
    system_prompt="You are a coding assistant.",
)
```

## Configuration

```python
sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",     # Required: read-write access
    allow_read=["/data/models"],            # Additional read-only paths
    allow_readwrite=["/tmp/scratch"],        # Additional read-write paths
    policy_json=json.dumps({                # Optional: nono policy JSON
        "groups": {
            "project_rw": {
                "description": "RW access to a project directory",
                "allow": {"readwrite": ["/tmp/agent-workspace"]}
            }
        }
    }),
    policy_groups=["project_rw"],           # Groups to resolve from policy_json
    proxy_config=ProxyConfig(               # Optional: host filtering + credential injection
        allowed_hosts=["api.openai.com"],
    ),
    snapshot_session_dir="/tmp/nono-session",  # Optional: enable snapshots + rollback
    block_network=True,                     # Block outbound network (default)
    timeout=300,                            # Default command timeout in seconds
)
```

## Network Filtering

Pass `proxy_config=ProxyConfig(...)` to start the nono proxy when the sandbox is
created. `execute()` automatically receives the proxy environment variables, so
host filtering and credential injection apply to sandboxed child processes
without extra wiring in the caller.

```python
from nono_py import InjectMode, ProxyConfig, RouteConfig

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    proxy_config=ProxyConfig(
        allowed_hosts=["api.openai.com"],
        routes=[
            RouteConfig(
                prefix="/openai",
                upstream="https://api.openai.com",
                credential_key="openai-key",
                inject_mode=InjectMode.HEADER,
            )
        ],
    ),
    block_network=True,
)

events = sandbox.drain_network_audit_events()
sandbox.shutdown_proxy()
```

## Snapshots

Pass `snapshot_session_dir=...` to enable content-addressable snapshots and
rollback for the sandbox workspace.

```python
from nono_py import ExclusionConfig

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    snapshot_session_dir="/tmp/nono-session",
    snapshot_exclusion=ExclusionConfig(exclude_patterns=["node_modules"]),
)

baseline = sandbox.create_snapshot_baseline()
manifest, changes = sandbox.create_snapshot_incremental()
restored = sandbox.restore_snapshot(0)
```

## Examples

Inline policy for an agent that can write in its workspace, read a reference folder,
and is denied access to a sibling secrets folder because that path is never granted:

```bash
python examples/01_policy_inline.py
```

Policy loaded from a JSON file with the same workspace/reference split, plus an
explicit `deny.access` rule for the secrets folder on macOS:

```bash
python examples/02_policy_from_file.py
```

Policy-aware `upload_files()` and `download_files()` with user-facing error
messages instead of raw backend error codes:

```bash
python examples/03_policy_file_transfer.py
```

The matching policy document is:

```text
examples/policy_example.json
```

## How it works

Each `execute()` call:

1. Forks the current process
2. Applies OS-level sandbox restrictions in the child (Landlock or Seatbelt)
3. Exec's the command
4. Captures stdout/stderr and waits for exit

The parent process remains unsandboxed and can call `execute()` repeatedly. Sandbox restrictions are enforced by the kernel and cannot be bypassed from userspace.

## Platform support

| Platform | Mechanism | Minimum version |
|----------|-----------|-----------------|
| Linux    | Landlock LSM | Kernel 5.13+ |
| macOS    | Seatbelt | macOS 10.15+ |
