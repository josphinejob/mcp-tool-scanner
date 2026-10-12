#!/usr/bin/env python3
"""
MCP Scanner CLI — manual inspection, approval, and sign-off tool.

Scans MCP server tool schemas for security anomalies, manages the pin
registry, and produces audit reports.

Usage:
    python3 mcp_scan.py [OPTIONS]

Options:
    --config PATH         Path to mcp.json listing the servers to scan
                          (default: mcp.json in the current directory)
    --format FORMAT       Output format: text (default), markdown, json
    --output PATH         Write report to file (required if --format is not text)
    --log                 Print the Current Issues table from the status file
    --force               Proceed past hard findings (CLI only)
    --approve SERVER TOOL [TOOL ...]
                          Record explicit user approval for soft-finding tools
    --show-schema SERVER TOOL
                          Print a tool's full description and inputSchema
                          (read-only — no writes)
    --server NAME         Scan a single named server only

Quickstart:
    # Run a scan against all servers in mcp.json
    python3 mcp_scan.py --config path/to/mcp.json

    # Read a tool's full text before approving
    python3 mcp_scan.py --config mcp.json --show-schema my-server my-tool

    # Approve a soft-flagged tool
    python3 mcp_scan.py --config mcp.json --approve my-server my-tool

    # Generate a Markdown sign-off report
    python3 mcp_scan.py --config mcp.json --format markdown --output report.md

State files written to the same directory as the config file:
    .mcp-pins.json         — pin registry (approved schema hashes)
    .mcp-scan-status.md    — current issues table (rewritten each scan)
    .mcp-scan-history.md   — append-only transition log
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Import core scanner module from same directory as this script
# ---------------------------------------------------------------------------
import importlib.util as _ilu

_SCRIPT_DIR = Path(__file__).resolve().parent
_spec = _ilu.spec_from_file_location(
    "_mcp_scanner_module", str(_SCRIPT_DIR / "mcp_scanner.py")
)
mcp_scanner = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(mcp_scanner)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def _state_paths(config_path: Path):
    """Return (pin_registry, status_md, history_md) paths relative to config dir."""
    base = config_path.resolve().parent
    return (
        base / ".mcp-pins.json",
        base / ".mcp-scan-status.md",
        base / ".mcp-scan-history.md",
    )


def _load_mcp_config(config_path: Path) -> Optional[dict]:
    if not config_path.exists():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error: could not parse config file {config_path}: {exc}", file=sys.stderr)
        return None


def _fetch_server_tools(server_name: str, server_config: dict) -> tuple:
    """
    Connect to an MCP server and fetch its tool list.

    Returns (server_version, protocol_version, tools) on success.
    Returns (None, None, None) if the server is unreachable.

    Merges current process environment with any env block in the server config
    so servers that need env-injected credentials (e.g. API tokens) receive them.
    """
    try:
        import mcp.client.stdio as mcp_stdio
        import asyncio
        from mcp import ClientSession, StdioServerParameters

        async def _fetch():
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            if not command:
                return None, None, None
            merged_env = {**os.environ, **server_config.get("env", {})}
            params = StdioServerParameters(command=command, args=args, env=merged_env)
            async with mcp_stdio.stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    info = await session.initialize()
                    version = (
                        getattr(info.serverInfo, "version", "")
                        if info and info.serverInfo else ""
                    )
                    protocol_version = getattr(info, "protocolVersion", None) or "unknown"
                    result = await session.list_tools()
                    tools = [
                        {
                            "name": t.name,
                            "description": t.description or "",
                            "inputSchema": t.inputSchema or {},
                        }
                        for t in (result.tools or [])
                    ]
                    return version, protocol_version, tools

        return asyncio.run(_fetch())

    except Exception:  # noqa: BLE001
        return None, None, None


# ---------------------------------------------------------------------------
# --approve
# ---------------------------------------------------------------------------

def cmd_approve(config_path: Path, server: str, tools: List[str]) -> int:
    pin_registry, status_md, history_md = _state_paths(config_path)
    registry = mcp_scanner.load_registry(pin_registry)

    if server not in registry:
        print(
            f"Error: server '{server}' not found in registry. "
            f"Run a scan first: python3 {Path(__file__).name} --config {config_path}",
            file=sys.stderr,
        )
        return 1

    tools_entry = registry[server].get("tools", {})
    unknown = [t for t in tools if t not in tools_entry]
    if unknown:
        print(
            f"Error: tool(s) not found for server '{server}': {', '.join(unknown)}. "
            f"Known tools: {', '.join(tools_entry.keys()) or 'none'}",
            file=sys.stderr,
        )
        return 1

    for tool in tools:
        registry[server]["tools"][tool]["approved_by"] = "user"

    try:
        mcp_scanner.write_registry(pin_registry, registry)
    except OSError as exc:
        print(f"Error: could not write registry: {exc}", file=sys.stderr)
        return 1

    timestamp = mcp_scanner.now_readable()
    issues = mcp_scanner._parse_status_md(status_md)
    history_lines = []
    for tool in tools:
        line = mcp_scanner.apply_scan_result(issues, server, tool, "approved", [], timestamp)
        if line:
            history_lines.append(line)
        print(f"Approved: {server}/{tool}")

    mcp_scanner.render_status_md(status_md, issues, timestamp)
    for line in history_lines:
        mcp_scanner.append_history(history_md, line)

    print(f"Registry updated — {len(tools)} tool(s) approved.")
    return 0


# ---------------------------------------------------------------------------
# --show-schema
# ---------------------------------------------------------------------------

def cmd_show_schema(config_path: Path, server: str, tool: str) -> int:
    config = _load_mcp_config(config_path)
    if config is None:
        return 1

    servers = config.get("mcpServers", config)
    if not isinstance(servers, dict) or server not in servers:
        print(f"Error: server '{server}' not found in config.", file=sys.stderr)
        return 1

    _, _, tools = _fetch_server_tools(server, servers[server])
    if tools is None:
        print(f"Error: server '{server}' is unreachable.", file=sys.stderr)
        return 1

    match = next((t for t in tools if t.get("name") == tool), None)
    if match is None:
        available = ", ".join(sorted(t.get("name", "") for t in tools)) or "none"
        print(
            f"Error: tool '{tool}' not found on server '{server}'. "
            f"Available tools: {available}",
            file=sys.stderr,
        )
        return 1

    print(f"Server: {server}")
    print(f"Tool:   {tool}")
    print()
    print("Description:")
    print(match.get("description", "") or "(no description)")
    print()
    print("Input schema:")
    print(json.dumps(match.get("inputSchema", {}), indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# --log
# ---------------------------------------------------------------------------

def cmd_log(config_path: Path) -> int:
    _, status_md, history_md = _state_paths(config_path)

    if not status_md.exists():
        print("No active issues.")
        print(f"(Transition history: {history_md})")
        return 0

    text = status_md.read_text(encoding="utf-8")
    lines = text.splitlines()

    start = next((i for i, l in enumerate(lines) if l.strip() == "## Current Issues"), None)
    if start is None:
        print("No active issues.")
        return 0

    end = next(
        (i for i, l in enumerate(lines) if i > start and l.strip().startswith("## ")),
        None,
    )
    section = lines[start:end] if end else lines[start:]
    while section and not section[-1].strip():
        section.pop()

    print("\n".join(section))
    print(f"\n(Transition history: {history_md})")
    return 0


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _scan_servers(config_path: Path, server_filter: Optional[str], force: bool) -> Optional[list]:
    config = _load_mcp_config(config_path)
    if config is None:
        return None

    pin_registry, status_md, history_md = _state_paths(config_path)
    registry = mcp_scanner.load_registry(pin_registry)

    servers = config.get("mcpServers", config)
    if not isinstance(servers, dict):
        servers = {}

    if server_filter:
        if server_filter not in servers:
            print(f"Error: server '{server_filter}' not found in config.", file=sys.stderr)
            return None
        servers = {server_filter: servers[server_filter]}

    issues = mcp_scanner._parse_status_md(status_md)
    history_lines: list = []
    reports = []

    for server_name, server_config in servers.items():
        if not isinstance(server_config, dict):
            continue
        if server_config.get("disabled") is True:
            continue

        scanned_at = mcp_scanner.now_readable()
        server_version, protocol_version, tools = _fetch_server_tools(server_name, server_config)

        if tools is None:
            reports.append({
                "server": server_name,
                "server_version": "unknown",
                "protocol_version": "unknown",
                "scanned_at": scanned_at,
                "event": "unreachable",
                "tools": [],
            })
            line = mcp_scanner.apply_scan_result(issues, server_name, "", "unreachable", [], scanned_at)
            if line:
                history_lines.append(line)
            continue

        server_version = server_version or ""
        protocol_version = protocol_version or "unknown"
        event_type, tool_results = mcp_scanner.compare_server(server_name, server_version, tools, registry)

        existing_entry = registry.get(server_name, {})
        existing_tools = existing_entry.get("tools", {})
        server_registry_entry: dict = {
            "server_version": server_version,
            "protocol_version": protocol_version,
            "scanned_at": scanned_at,
            "tools": dict(existing_tools),
        }

        for result in tool_results:
            if result.action == "tool_removed":
                if result.tool_name in server_registry_entry["tools"]:
                    server_registry_entry["tools"][result.tool_name]["status"] = "removed"
            elif result.action not in ("blocked",) or force:
                existing_tool_entry = existing_tools.get(result.tool_name, {})
                tool_entry: dict = {"hash": result.hash, "last_seen": scanned_at[:10]}
                if result.action == "pinned":
                    tool_entry["approved_by"] = "auto"
                elif existing_tool_entry.get("approved_by"):
                    tool_entry["approved_by"] = existing_tool_entry["approved_by"]
                server_registry_entry["tools"][result.tool_name] = tool_entry

            findings_dicts = [
                {"field": f.field, "severity": f.severity, "pattern": f.pattern, "detail": f.detail}
                for f in result.findings
            ]
            detail = ""
            if event_type == "hash_changed":
                old_hash = existing_tools.get(result.tool_name, {}).get("hash", "")
                if old_hash:
                    detail = f"hash changed from {old_hash[:19]}... to {result.hash[:19]}..."

            line = mcp_scanner.apply_scan_result(
                issues, server_name, result.tool_name, result.action, findings_dicts, scanned_at, detail
            )
            if line:
                history_lines.append(line)

        registry[server_name] = server_registry_entry
        try:
            mcp_scanner.write_registry(pin_registry, registry)
        except OSError as exc:
            print(f"Error: registry write failed for '{server_name}': {exc}", file=sys.stderr)

        tool_reports = []
        for result in tool_results:
            has_hard = any(f.severity == "hard" for f in result.findings)
            has_soft = any(f.severity == "soft" for f in result.findings)
            tool_reports.append({
                "tool_name": result.tool_name,
                "hash": result.hash,
                "severity_group": "hard" if has_hard else ("soft" if has_soft else "clean"),
                "action": result.action,
                "findings": findings_dicts,
            })

        reports.append({
            "server": server_name,
            "server_version": server_version,
            "protocol_version": protocol_version,
            "scanned_at": scanned_at,
            "event": event_type,
            "tools": tool_reports,
        })

    mcp_scanner.render_status_md(status_md, issues, mcp_scanner.now_readable())
    for line in history_lines:
        mcp_scanner.append_history(history_md, line)

    return reports


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def _format_text(reports: list) -> str:
    lines = ["MCP Scanner Report", "=" * 60, f"Generated: {_now_iso()}", ""]
    for r in reports:
        lines.append(f"Server: {r['server']}  version: {r['server_version']}  event: {r['event']}")
        lines.append(f"Scanned: {r['scanned_at']}")
        if not r["tools"]:
            lines.append("  No tools found or server unreachable.")
        else:
            for group, label in [("hard", "HARD (blocked)"), ("soft", "SOFT (review)"), ("clean", "CLEAN")]:
                subset = [t for t in r["tools"] if t["severity_group"] == group]
                if subset:
                    lines.append(f"\n  {label}:")
                    for t in subset:
                        lines.append(f"    [{t['tool_name']}]  {t['hash']}")
                        for f in t["findings"]:
                            lines.append(f"      {f['severity'].upper()}: {f['pattern']} — {f['detail']}")
        lines.append("")
    return "\n".join(lines)


def _format_markdown(reports: list) -> str:
    lines = ["# MCP Scanner Security Report", "", f"**Generated:** {_now_iso()}", ""]
    for r in reports:
        lines += [
            f"## {r['server']}",
            f"- **Version:** {r['server_version']}",
            f"- **Protocol version:** {r.get('protocol_version', 'unknown')}",
            f"- **Event:** {r['event']}",
            f"- **Scanned at:** {r['scanned_at']}",
            "",
        ]
        if not r["tools"]:
            lines += ["No tools found or server unreachable.", ""]
            continue
        for group, heading in [("hard", "Hard Findings"), ("soft", "Soft Findings"), ("clean", "Clean Tools")]:
            subset = [t for t in r["tools"] if t["severity_group"] == group]
            if not subset:
                continue
            lines += [f"### {heading}", ""]
            if group == "clean":
                lines += ["| Tool | Hash |", "|------|------|"]
                for t in subset:
                    lines.append(f"| `{t['tool_name']}` | `{t['hash']}` |")
            else:
                lines += ["| Tool | Hash | Finding |", "|------|------|---------|"]
                for t in subset:
                    for f in t["findings"]:
                        lines.append(
                            f"| `{t['tool_name']}` | `{t['hash'][:16]}...` "
                            f"| **{f['pattern']}** — {f['detail']} (`{f['field']}`) |"
                        )
            lines.append("")
    return "\n".join(lines)


def _format_json(reports: list) -> str:
    return json.dumps({"generated_at": _now_iso(), "reports": reports}, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp_scan.py",
        description="MCP Scanner — scan MCP server tool schemas for security anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", type=Path, default=Path("mcp.json"),
                        metavar="PATH", help="Path to mcp.json (default: ./mcp.json)")
    parser.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument("--output", type=Path, default=None, metavar="PATH")
    parser.add_argument("--log", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--approve", nargs="+", metavar="ARG",
                        help="SERVER TOOL [TOOL ...] — approve soft-finding tools")
    parser.add_argument("--show-schema", nargs=2, metavar=("SERVER", "TOOL"))
    parser.add_argument("--server", metavar="NAME", default=None)

    args = parser.parse_args()

    if args.log:
        return cmd_log(args.config)

    if args.show_schema:
        return cmd_show_schema(args.config, args.show_schema[0], args.show_schema[1])

    if args.approve:
        if len(args.approve) < 2:
            print("Error: --approve requires SERVER and at least one TOOL.", file=sys.stderr)
            return 1
        return cmd_approve(args.config, args.approve[0], args.approve[1:])

    if args.format != "text" and args.output is None:
        print(f"Error: --output is required when --format is '{args.format}'.", file=sys.stderr)
        return 1

    reports = _scan_servers(args.config, args.server, args.force)
    if reports is None:
        return 1

    if args.format == "text":
        print(_format_text(reports))
    else:
        text = _format_markdown(reports) if args.format == "markdown" else _format_json(reports)
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
            print(f"Report written to {args.output}")
        except OSError as exc:
            print(f"Error: could not write report: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
