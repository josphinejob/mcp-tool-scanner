# MCP Tool Scanner

A security scanner for MCP (Model Context Protocol) server tool schemas.

It detects three documented MCP attack classes and produces a hash-pinned registry of approved tool schemas so you can verify that nothing changed between sessions.

---

## Why this exists

When you add an MCP server to your AI host (Claude, Cursor, Kiro, or any MCP-compatible host), you approve it once. Then you trust it indefinitely. But that trust is misplaced, because:

- The server is a running process with access to whatever you gave it: your filesystem, your API keys, your credentials.
- The tool descriptions the server sends to the AI are under the server author's control, not yours.
- Those descriptions can change silently after your initial approval.
- You have no way to know, because the tool list is re-fetched on every session.

This is not theoretical. Three specific attack classes exist:

**Rug pull:** the server changes a tool's description after you approved it. The AI reads the new description as trusted input and acts on it. You see nothing different in your config.

**Hidden character injection:** zero-width Unicode characters, right-to-left overrides, or byte-order marks are embedded in tool descriptions. They are invisible to a human reviewer but readable by the AI. A tool description that looks benign on screen can contain a hidden instruction to exfiltrate data or override prior instructions.

**Cross-server shadowing:** one server's tool description references another server's tool name. This can redirect the AI's tool selection away from the intended server to one controlled by the attacker. It works across servers in the same session because the AI sees all tool descriptions together.

This scanner addresses all three.

---

## What it does

On every scan it:

1. Connects to each configured MCP server and fetches its tool list
2. Runs static checks on every string field in every tool schema
3. Computes a SHA-256 hash of each tool's full schema
4. Compares hashes against a pin registry of previously approved schemas
5. Flags any tool whose schema changed, contains suspicious content, or has never been reviewed
6. Writes a status file with current issues and an append-only transition log

The pin registry records the last approved state of every tool on every server. Once a tool is pinned as clean, subsequent sessions only alert you if something actually changed.

---

## Detection checks

### Hard findings (tool blocked)

A hard finding blocks the tool unconditionally. No bypass in automated mode.

| Check | What it detects |
|-------|----------------|
| Hidden characters | Zero-width space `\u200b`, zero-width non-joiner `\u200c`, zero-width joiner `\u200d`, byte-order mark `\ufeff`, right-to-left override `\u202e` in any schema field |
| Whitespace runs | Ten or more consecutive whitespace characters in any schema field |
| Invalid UTF-8 | Bytes that are not valid UTF-8 in any field |
| Serialisation failure | Tool schema cannot be hashed (circular reference, encoding error) |

### Soft findings (tool usable, review recommended)

A soft finding surfaces a warning but does not block the tool. Run `--approve` after reviewing to silence it on future scans.

| Check | What it detects |
|-------|----------------|
| Injection keywords | Case-insensitive match against: `system`, `override`, `ignore previous`, `ignore all prior`, `you are now`, `emergency`, `before responding`, `mandatory`, `credentials`, `token`, `history`, `password`, `auth`, `session` |
| Non-ASCII characters | Any Unicode codepoint above 127 in any string field |
| Cross-server shadowing | Any tool name from another server (already in the registry) appearing word-boundary-delimited in any string field |
| Structural anomaly | Any tool whose description is more than 3× the median description length across all tools on the same server |

The keywords `session` and `token` have higher false-positive rates; they appear in legitimate tool descriptions ("creates a session", "returns an auth token"). They are intentionally soft, not hard, so you can approve them on first connect without being blocked.

### Hash change

If a tool's schema hash differs from the pinned value, the tool is blocked and the diff is recorded. You must re-approve after reviewing the change.

---

## Requirements

- Python 3.8+
- No external dependencies for the scanner core or tests
- `mcp` Python SDK required only if you connect to live servers (`pip install mcp`)

---

## Installation

```bash
git clone https://github.com/josphinejob/mcp-tool-scanner.git
cd mcp-tool-scanner
# no pip install needed for the core (pure stdlib)
```

To connect to live MCP servers:

```bash
pip install mcp
```

---

## Quickstart

**1. Point it at your mcp.json config**

Your MCP config lists the servers you have connected. It looks like this:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@some/mcp-server"],
      "env": {
        "API_TOKEN": "your-token-here"
      }
    }
  }
}
```

**2. Run a scan**

```bash
python3 mcp_scan.py --config path/to/mcp.json
```

On first run, every tool is treated as a new connection. Clean tools are auto-approved (`approved_by: "auto"`). Tools with soft findings are flagged as `pending_approval`, usable but waiting for your sign-off.

**3. Read a flagged tool's full description**

Before approving anything, read the actual text the scanner flagged:

```bash
python3 mcp_scan.py --config mcp.json --show-schema my-server my-tool
```

This prints the full `description` and `inputSchema` for that tool as returned live from the server. Read-only, no writes.

**4. Approve legitimate soft findings**

```bash
# One tool
python3 mcp_scan.py --config mcp.json --approve my-server my-tool

# Multiple tools on the same server
python3 mcp_scan.py --config mcp.json --approve my-server tool-one tool-two tool-three
```

This records `approved_by: "user"` in the pin registry for each named tool. The finding is silenced on all future scans unless the schema changes.

**5. Check current issues**

```bash
python3 mcp_scan.py --config mcp.json --log
```

Prints the Current Issues table, showing only tools and servers with an active non-clean status.

---

## CLI reference

```
python3 mcp_scan.py [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config PATH` | Path to mcp.json (default: `./mcp.json`) |
| `--format text\|markdown\|json` | Output format (default: `text`) |
| `--output PATH` | Write report to file. Required when `--format` is not `text`. |
| `--log` | Print the Current Issues table from `.mcp-scan-status.md` |
| `--force` | Proceed past hard findings and write them to the registry after deliberate review. CLI only, no equivalent in automated mode. |
| `--approve SERVER TOOL [TOOL ...]` | Record explicit user approval for one or more soft-finding tools. All named tools must be on the same server. All names are validated before any write; an unknown name fails the whole command without partial writes. |
| `--show-schema SERVER TOOL` | Print a tool's full description and inputSchema from the live server. Read-only, no registry or status file writes. |
| `--server NAME` | Scan a single named server only instead of all servers in the config |

---

## State files

The scanner writes three files to the same directory as your config file.

### `.mcp-pins.json` (pin registry)

Records the last approved schema hash for every tool on every server.

```json
{
  "my-server": {
    "server_version": "1.2.0",
    "protocol_version": "2026-07-28",
    "scanned_at": "2026-09-01T10:00:00+10:00",
    "tools": {
      "search_items": {
        "hash": "sha256:a3f1c2d8...",
        "last_seen": "2026-09-01",
        "approved_by": "auto"
      },
      "create_item": {
        "hash": "sha256:d8e4b1f2...",
        "last_seen": "2026-09-01",
        "approved_by": "user"
      }
    }
  }
}
```

`approved_by: "auto"`: clean tool, auto-approved on first scan.
`approved_by: "user"`: soft finding was reviewed and approved via `--approve`.
No `approved_by`: tool has a soft finding that has not yet been approved.

If the registry file is missing, it is created on first write. If it contains invalid JSON, it is renamed to `.mcp-pins.json.bak` and a fresh registry is created; all servers are treated as first-connect.

### `.mcp-scan-status.md` (current issues)

Human-readable Markdown table. Rewritten once per scan after all servers are processed. One row per server/tool with an active non-clean status.

```markdown
## Current Issues
| Server    | Tool         | Status           | Since               | Last Checked        |
|-----------|--------------|------------------|---------------------|---------------------|
| my-server | search_items | pending_approval | 2026-09-01 10:00:00 | 2026-09-01 10:00:00 |
```

| Status | Meaning | Tool usable? |
|--------|---------|-------------|
| `pending_approval` | Soft finding detected. Tool works, but scanner wants your sign-off. | Yes |
| `blocked` | Hard finding or hash change. Tool unavailable this session. | No |
| `unreachable` | Server could not be contacted. | Unknown |
| `tool_removed` | Tool was in the registry but no longer present on the server. | N/A |

Rows update in place on repeat scans; same status only refreshes `Last Checked`. Rows are removed when the issue resolves (tool approved, server comes back online).

### `.mcp-scan-history.md` (transition log)

Append-only. One line written only when a genuine status transition occurs (new issue, status change, or resolution). Stable pending tools with unchanged hashes write nothing.

```
2026-09-01 10:00:00 — my-server/search_items: pending_approval (non-ascii)
2026-09-01 11:30:00 — my-server/search_items: pending_approval → clean
```

---

## Example output

**Clean scan (all tools approved):**

```
MCP Scanner Report
============================================================
Generated: 2026-09-29T10:00:00+10:00

Server: notion  version: 1.0.0  event: first_connect
Scanned: 2026-09-29T10:00:00+10:00

  CLEAN:
    [search_pages]  sha256:a3f1c2d8e5b7...
    [get_page_content]  sha256:c2d4f6a8b1e3...
    [create_page]  sha256:d8e4b1f2c3a5...
    [append_blocks]  sha256:f1a3c5e7d2b4...
```

**Scan with a soft finding (tool usable, review pending):**

```
MCP Scanner Report
============================================================
Generated: 2026-09-29T11:00:00+10:00

Server: my-server  version: 2.1.0  event: first_connect
Scanned: 2026-09-29T11:00:00+10:00

  SOFT (review):
    [run_command]  sha256:b4d6f8a2c1e3...
      SOFT: injection-keyword — keyword "session" found in field (description)

  CLEAN:
    [list_resources]  sha256:e3c1a5f7b2d4...
```

**Scan with a hard finding (tool blocked):**

```
MCP Scanner Report
============================================================
Generated: 2026-09-29T12:00:00+10:00

Server: untrusted-server  version: 0.9.1  event: first_connect
Scanned: 2026-09-29T12:00:00+10:00

  HARD (blocked):
    [transfer_data]  sha256:7f3a1b5d2e8c...
      HARD: hidden-char — hidden character U+200B found in field (description)
```

The corresponding `.mcp-scan-status.md` after the hard finding:

```markdown
## Current Issues

| Server           | Tool          | Status  | Since               | Last Checked        |
|------------------|---------------|---------|---------------------|---------------------|
| untrusted-server | transfer_data | blocked | 2026-09-29 12:00:00 | 2026-09-29 12:00:00 |
```

---

## Sign-off report

For security reviews or team audits, generate a Markdown report:

```bash
python3 mcp_scan.py --config mcp.json --format markdown --output mcp-security-report.md
```

Or JSON for machine processing:

```bash
python3 mcp_scan.py --config mcp.json --format json --output mcp-security-report.json
```

---

## Integrating into an automated session hook

The scanner is designed to run as a pre-session hook in any MCP host that supports hooks. The core logic lives entirely in `mcp_scanner.py`; the CLI (`mcp_scan.py`) is a thin wrapper around it.

To build a hook for your host, import `mcp_scanner` directly:

```python
from pathlib import Path
import mcp_scanner

registry = mcp_scanner.load_registry(Path(".mcp-pins.json"))
event_type, tool_results = mcp_scanner.compare_server(
    server_name, server_version, tools, registry
)

for result in tool_results:
    has_hard = any(f.severity == "hard" for f in result.findings)
    if has_hard:
        # block this tool
        pass
```

The hook decision model:

| Condition | Recommended action |
|-----------|-------------------|
| Hard finding on any tool | Block that tool; session proceeds for other tools |
| Soft finding on any tool | Session proceeds; surface finding in message; require `--approve` to silence |
| Registry write failure | Block all tools from that server (no baseline = no safe proceed) |
| Server unreachable | Log and skip; do not block other servers |

`--force` is intentionally CLI-only. In automated hook mode, hard findings always block; there is no bypass path in the automated guard.

---

## What this does not detect

The scanner inspects only the schemas returned over the MCP protocol. It cannot detect:

- **Code-only changes:** when a server version bumps but no schema changed, the scanner surfaces the version change but cannot determine whether the server's implementation is safe. Schema scanning cannot see the code behind a tool.
- **Novel obfuscation:** static pattern matching has a finite boundary. Techniques not matching the defined patterns are outside scope.
- **Server binary integrity:** for hosted or managed MCP endpoints (Jira, GitHub, AWS, etc.), only the schema returned over the protocol is inspectable. The server binary or package is not.
- **First-scan forward references:** when multiple servers are processed in the same session and the first server's schema references a tool name from a server not yet processed, that shadowing reference is not detected in that session. It becomes detectable on the next scan when both servers are in the registry.
- **Semantic intent:** whether a description is contextually manipulative is not assessed. Only structural and lexical patterns are checked.

---

## Running the tests

```bash
pip install pytest
python3 -m pytest tests/ -v
```

89 unit tests covering all detection logic, registry management, and status file behaviour. No external dependencies, no network calls, no MCP server required.

---

## Related writing

This tool was built alongside a three-part blog series on MCP security:

- [What I learnt building an MCP server](https://medium.com/@tojosphine): the builder's perspective on trust and what pasting a config block actually means
- [MCP tool poisoning and supply chain risks](https://medium.com/@tojosphine): the attack surface this tool is designed to address
- [MCP credentials: what not to put in your config file](https://medium.com/@tojosphine): credential handling and the shell profile pattern
