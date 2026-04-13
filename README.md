<div align="center">
<img src="https://raw.githubusercontent.com/always-further/langchain-nono/main/assets/logo.png" alt="nono logo" width="500"/>


OS-enforced sandbox backend for [LangChain Deep Agents](https://github.com/langchain-ai/deepagents) using [nono](https://github.com/always-further/nono).

Kernel-level sandboxing, network filtering, policy-based access control, credential injection, and filesystem snapshots — all native Python, no containers required.

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
from langchain_nono import InjectMode, NonoSandbox, ProxyConfig, RouteConfig

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

Or resolve proxy config from a policy file:

```python
proxy_config = NonoSandbox.resolve_proxy_from_policy(
    policy_json, ["proxy_web_demo"]
)
```

## Credential Injection

The proxy can transparently swap phantom tokens for real API credentials,
so sandboxed code never sees real keys. Real credentials are loaded from
the host's OS keyring; only phantom tokens enter the sandbox.

```python
from langchain_nono import InjectMode, NonoSandbox, ProxyConfig, RouteConfig

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    proxy_config=ProxyConfig(
        allowed_hosts=["api.openai.com"],
        routes=[
            RouteConfig(
                prefix="/openai",
                upstream="https://api.openai.com",
                credential_key="openai-key",       # OS keyring lookup
                inject_mode=InjectMode.HEADER,
                inject_header="Authorization",
                credential_format="Bearer {}",
            )
        ],
    ),
    block_network=True,
)

# The child sees OPENAI_API_KEY=<phantom> and OPENAI_BASE_URL=http://127.0.0.1:<port>/openai
# The proxy swaps the phantom token for the real key on outbound requests.
result = sandbox.execute("curl $OPENAI_BASE_URL/v1/models -H 'Authorization: Bearer $OPENAI_API_KEY'")
```

Injection modes: `HEADER`, `QUERY_PARAM`, `BASIC_AUTH`, `URL_PATH`.

## Snapshots

Pass `snapshot_session_dir=...` to enable content-addressable snapshots and
rollback for the sandbox workspace.

```python
from langchain_nono import ExclusionConfig, NonoSandbox, SessionMetadata

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    snapshot_session_dir="/tmp/nono-session",
    snapshot_exclusion=ExclusionConfig(exclude_patterns=["node_modules"]),
)

baseline = sandbox.create_snapshot_baseline()
manifest, changes = sandbox.create_snapshot_incremental()
diff = sandbox.compute_restore_diff(0)        # dry-run preview
restored = sandbox.restore_snapshot(0)         # actual rollback
```

### Session Metadata

Save audit trails with Merkle roots and network events:

```python
meta = SessionMetadata(
    session_id="my-session",
    command=["bash", "-c", "echo hello"],
    tracked_paths=["/tmp/agent-workspace"],
)
meta.add_merkle_root(baseline.merkle_root)
sandbox.save_session_metadata(meta)

# Later, load from disk:
loaded = NonoSandbox.load_session_metadata("/tmp/nono-session")
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

Proxy basics -- starting a proxy, running commands, draining audit events:

```bash
python examples/04_proxy_basics.py
```

API key protection via proxy credential injection with phantom token swapping:

```bash
python examples/05_credential_injection.py
```

Policy-based proxy configuration resolved from JSON groups:

```bash
python examples/06_policy_proxy.py
```

Filesystem snapshots with dry-run diff and rollback:

```bash
python examples/07_snapshot_rollback.py
```

Full supervisor flow combining proxy, snapshots, and session metadata:

```bash
python examples/08_proxy_with_snapshots.py
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
