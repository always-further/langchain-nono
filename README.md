<div align="center">
<img src="https://raw.githubusercontent.com/nolabs-ai/langchain-nono/main/assets/logo.png" alt="nono logo" width="500"/>


OS-enforced sandbox backend for [LangChain Deep Agents](https://github.com/langchain-ai/deepagents) using [nono](https://github.com/always-further/nono).

Kernel-level sandboxing, network filtering, policy-based access control, credential injection, and filesystem snapshots — all native Python, no containers required.

</div>

## Installation

```bash
pip install langchain-nono
```

## Usage

```python
import uuid
from pathlib import Path

from langchain_anthropic import ChatAnthropic
from deepagents import create_deep_agent
from langchain_nono import NonoSandbox

thread_id = str(uuid.uuid4())
working_dir = Path("/tmp/agent-sandboxes") / thread_id
working_dir.mkdir(parents=True, exist_ok=True)

sandbox = NonoSandbox(
    working_dir=str(working_dir),
    virtual_workspace_root=True,
)

agent = create_deep_agent(
    backend=sandbox,
    model=ChatAnthropic(model_name="claude-sonnet-4-6"),
    system_prompt="You are a coding assistant with sandbox access.",
)

result = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": "Create a hello world Python script and run it",
            }
        ]
    },
    config={"configurable": {"thread_id": thread_id}},
)
print(result["messages"][-1].content)
```

`virtual_workspace_root=True` lets Deep Agents use absolute tool paths such as
`/hello.py` while `langchain-nono` stores the file under the concrete per-thread
workspace, for example `/tmp/agent-sandboxes/<thread-id>/hello.py`.

## Configuration

```python
sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",     # Required: read-write access
    virtual_workspace_root=True,            # Map /file.py to working_dir/file.py for Deep Agents
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
import shlex

from langchain_nono import NonoSandbox, ProxyConfig

sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
    block_network=True,
)

request_script = """
import urllib.request

with urllib.request.urlopen("https://example.com", timeout=30) as response:
    print(response.status)
"""
result = sandbox.execute(f"python3 -c {shlex.quote(request_script)}")
print(result.exit_code)

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

The proxy can inject real API credentials on outbound requests, so
sandboxed code never sees real keys. Real credentials can be loaded from
host-side sources such as `env://OPENAI_API_KEY`. When `env_var` is configured
on a route, the sandboxed child receives a route-scoped phantom token in that
variable; the proxy swaps that phantom token for the real credential before
forwarding upstream.

When proxy mode is enabled, `langchain-nono` uses nono-py's proxy-only
network mode so sandboxed code can connect only to the local proxy port;
all direct outbound network access remains blocked.

```python
import shlex

from langchain_nono import InjectMode, NonoSandbox, ProxyConfig, RouteConfig


sandbox = NonoSandbox(
    working_dir="/tmp/agent-workspace",
    proxy_config=ProxyConfig(
        allowed_hosts=["api.openai.com"],
        routes=[
            RouteConfig(
                prefix="/openai",
                upstream="https://api.openai.com",
                credential_key="env://OPENAI_API_KEY",  # Host env lookup
                inject_mode=InjectMode.HEADER,
                inject_header="Authorization",
                credential_format="Bearer {}",
                env_var="OPENAI_API_KEY",          # Phantom token env var
            )
        ],
    ),
    block_network=True,
)

try:
    # The child sees OPENAI_API_KEY=<phantom> and OPENAI_BASE_URL=http://127.0.0.1:<port>/openai.
    # The proxy swaps the phantom token for the real key on outbound requests.
    request_script = """
import os
import urllib.request

request = urllib.request.Request(
    os.environ["OPENAI_BASE_URL"] + "/v1/models",
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(response.read().decode())
"""
    result = sandbox.execute(f"python3 -c {shlex.quote(request_script)}")
    print(result.output)
finally:
    sandbox.shutdown_proxy()
```

Injection modes: `HEADER`, `QUERY_PARAM`, `BASIC_AUTH`, `URL_PATH`.

## Snapshots

Pass `snapshot_session_dir=...` to enable content-addressable snapshots and
rollback for the sandbox workspace.

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from langchain_nono import ExclusionConfig, NonoSandbox


def print_changes(title, changes):
    print(title)
    for change in changes:
        print(f"  - {change.change_type}: {Path(change.path).name}")


with (
    TemporaryDirectory(prefix="agent-workspace-") as workspace,
    TemporaryDirectory(prefix="nono-session-") as session_dir,
):
    sandbox = NonoSandbox(
        working_dir=workspace,
        snapshot_session_dir=session_dir,
        snapshot_exclusion=ExclusionConfig(exclude_patterns=["node_modules"]),
    )

    sandbox.execute("printf 'version 1\n' > app.txt")
    baseline = sandbox.create_snapshot_baseline()
    print("Baseline snapshot")
    print(f"  app.txt contains: {sandbox.execute('cat app.txt').output.strip()!r}")

    sandbox.execute("printf 'version 2\n' > app.txt")
    sandbox.execute("printf 'generated\n' > output.txt")
    manifest, changes = sandbox.create_snapshot_incremental()

    print("\nAgent changed the workspace")
    print(f"  app.txt now contains: {sandbox.execute('cat app.txt').output.strip()!r}")
    print_changes("Snapshot detected:", changes)
    print(f"  Merkle root changed: {baseline.merkle_root != manifest.merkle_root}")

    diff = sandbox.compute_restore_diff(0)
    print_changes("\nDry-run restore preview:", diff)

    restored = sandbox.restore_snapshot(0)
    print(f"\nRestored baseline by applying {len(restored)} change(s)")
    print(f"  app.txt contains: {sandbox.execute('cat app.txt').output.strip()!r}")
    print(
        "  output.txt:",
        sandbox.execute("test -e output.txt && echo exists || echo removed").output.strip(),
    )
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

API key protection via proxy credential injection without exposing the API key:

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
