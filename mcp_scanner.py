"""
MCP Scanner — Core Module
=========================
Pure stdlib implementation (Python 3.8+). No external dependencies.

This module provides all detection logic, hashing, pin registry management,
and status-file maintenance for the MCP security scanner.

Business rule functions (pure, no I/O):
    hash_schema, extract_string_fields, check_hidden_chars, check_whitespace_runs,
    check_keywords, check_non_ascii, check_invalid_utf8, check_structural_anomaly,
    check_shadowing, scan_tool, compare_server

Action functions (side effects):
    load_registry, write_registry, render_status_md, append_history

Status files at workspace root:

  .mcp-scan-status.md — Current Issues table only.
    Rewritten once per session after all servers are processed (batch write).
    Callers accumulate all scan results in memory across all servers and tools,
    then call render_status_md() once with the complete issues dict.
    Contains: reference line pointing to scripts/docs/mcp-scan.md + ## Current Issues table.
    Legend (status values, columns, approve instructions) lives in scripts/docs/mcp-scan.md.

  .mcp-scan-history.md — append-only transitions.
    One line appended only on a genuine status transition (new issue, status
    change, or resolution). Never rewritten. Stable pending_approval tools
    with an unchanged hash produce zero writes to this file per session.
"""

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single scanner finding for one field in a tool schema."""
    field: str          # which schema field triggered (e.g. "description", "name")
    severity: str       # "hard" | "soft"
    pattern: str        # which check matched (e.g. "hidden-char", "keyword:system")
    detail: str         # specific matched value or error message


@dataclass
class ToolScanResult:
    """Scan result for a single tool on a single server."""
    server: str
    tool_name: str
    hash: str           # "sha256:<hex>" of full canonicalised schema JSON
    findings: List[Finding] = field(default_factory=list)
    action: str = "pending_approval"
    # action: "pinned" | "blocked" | "approved" | "unchanged" | "pending_approval"
    # "tool_removed" is used when a previously-pinned tool disappears


@dataclass
class ScanReport:
    """Aggregated scan result for a single server."""
    server: str
    server_version: str
    protocol_version: str   # from serverInfo initialize handshake (e.g. "2026-07-28")
    scanned_at: str         # ISO 8601 with timezone
    tools: List[ToolScanResult] = field(default_factory=list)
    event: str = "first_connect"
    # event: "first_connect" | "version_changed" | "hash_changed" |
    #        "new_tool" | "unchanged" | "unreachable" | "tool_removed"


# ---------------------------------------------------------------------------
# Hidden characters and whitespace run constants
# ---------------------------------------------------------------------------

# Zero-width / invisible Unicode characters (S3-1)
_HIDDEN_CHARS = (
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # BOM
    "\u202e",  # right-to-left override
)

# Injection keywords (S3-2) — order matters: longer patterns before substrings
_KEYWORDS = [
    "ignore previous",
    "ignore all prior",
    "you are now",
    "before responding",
    "system",
    "override",
    "emergency",
    "mandatory",
    "credentials",
    "history",
    "password",
    "session",
    "token",
    "auth",
]

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def hash_schema(tool: dict) -> str:
    """
    Return a stable SHA-256 hash of the full tool schema dict.

    json.dumps with sort_keys=True, ensure_ascii=False makes the hash
    stable regardless of key order in the server response, while preserving
    non-ASCII characters so they contribute to the hash (detectable by S3-3).
    """
    canonical = json.dumps(tool, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# String field extraction
# ---------------------------------------------------------------------------

_MAX_DEPTH = 10

# JSON Schema keywords whose values are legitimately non-string by the JSON
# Schema spec itself (numbers, booleans, or type-dependent defaults). These
# are structural schema keywords, not descriptive content — flagging them as
# "unexpected-type" was a false positive on every tool with a typed
# constraint or default, independent of any actual anomaly in the schema.
_NON_STRING_SCHEMA_KEYWORDS = frozenset({
    "default",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
    "multipleOf",
    "additionalProperties",
    "uniqueItems",
    "required",
    "readOnly",
    "writeOnly",
    "deprecated",
    "nullable",
})


def extract_string_fields(
    schema: dict,
    _path: str = "",
    _depth: int = 0,
) -> List[Tuple[str, str]]:
    """
    Recursively walk a schema dict and return (field_path, value) for all
    string leaves.

    Non-string leaves where a string is expected (e.g. numeric description)
    produce a soft-finding entry encoded as a tuple:
        ("__finding__:<path>", "<type_name>")
    The caller (scan_tool) unwraps these into actual Finding objects.

    Keys in _NON_STRING_SCHEMA_KEYWORDS are skipped entirely — these are
    JSON Schema keywords defined by the spec to hold non-string values
    (numbers, booleans), so a non-string value there is correct, not a
    finding. Only keys outside this list (e.g. "description", "name", or
    an unrecognised custom key) are checked for unexpected type.

    Stops recursion at depth 10 (design Decision 13) — returns a soft-finding
    entry for the truncated path to signal that deeper content was not inspected.

    Lists are iterated; list items that are strings are included with a
    "[<index>]" suffix on the path. Non-string list items are recursed into
    when they are dicts, or soft-finding-reported when they are primitives.
    """
    results: List[Tuple[str, str]] = []

    if _depth > _MAX_DEPTH:
        # Depth guard — signal truncation as a soft finding
        results.append((f"__finding__:{_path}", "depth_exceeded"))
        return results

    if not isinstance(schema, dict):
        return results

    for key, value in schema.items():
        path = f"{_path}.{key}" if _path else key

        if isinstance(value, str):
            results.append((path, value))
        elif isinstance(value, dict):
            results.extend(
                extract_string_fields(value, _path=path, _depth=_depth + 1)
            )
        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_path = f"{path}[{i}]"
                if isinstance(item, str):
                    results.append((item_path, item))
                elif isinstance(item, dict):
                    results.extend(
                        extract_string_fields(item, _path=item_path, _depth=_depth + 1)
                    )
                elif key not in _NON_STRING_SCHEMA_KEYWORDS:
                    # Non-string, non-dict list item at an unexpected key
                    results.append((f"__finding__:{item_path}", type(item).__name__))
        elif key in _NON_STRING_SCHEMA_KEYWORDS:
            # Legitimate non-string JSON Schema keyword — not a finding
            continue
        else:
            # Non-string, non-dict, non-list value at an unrecognised key —
            # e.g. a numeric "description" — genuinely unexpected (S3-7).
            results.append((f"__finding__:{path}", type(value).__name__))

    return results


# ---------------------------------------------------------------------------
# Individual check functions (all pure — no I/O)
# ---------------------------------------------------------------------------


def check_hidden_chars(field_path: str, value: str) -> List[Finding]:
    """
    Detect zero-width and invisible Unicode characters in value (S3-1 — hard finding).
    """
    findings = []
    for char in _HIDDEN_CHARS:
        if char in value:
            findings.append(Finding(
                field=field_path,
                severity="hard",
                pattern="hidden-char",
                detail=f"hidden character U+{ord(char):04X} found in field",
            ))
    return findings


def check_whitespace_runs(field_path: str, value: str) -> List[Finding]:
    """
    Detect runs of 10+ consecutive whitespace characters in value (S3-1 — hard finding).
    """
    findings = []
    if re.search(r"\s{10,}", value):
        findings.append(Finding(
            field=field_path,
            severity="hard",
            pattern="whitespace-run",
            detail="10 or more consecutive whitespace characters detected",
        ))
    return findings


def check_keywords(field_path: str, value: str) -> List[Finding]:
    """
    Detect injection-related keyword patterns in value (S3-2 — soft finding).
    Returns one finding per distinct keyword matched.
    """
    findings = []
    seen_patterns: set = set()
    lower_value = value.lower()
    for keyword in _KEYWORDS:
        if keyword in lower_value and keyword not in seen_patterns:
            pos = lower_value.find(keyword)
            findings.append(Finding(
                field=field_path,
                severity="soft",
                pattern=f"keyword:{keyword}",
                detail=f"matched '{keyword}' at position {pos}",
            ))
            seen_patterns.add(keyword)
    return findings


def check_non_ascii(field_path: str, value: str) -> List[Finding]:
    """
    Detect non-ASCII characters in value (S3-3 — soft finding).
    """
    non_ascii = {c for c in value if ord(c) > 127}
    if non_ascii:
        chars_repr = ", ".join(
            f"U+{ord(c):04X}" for c in sorted(non_ascii, key=ord)
        )
        return [Finding(
            field=field_path,
            severity="soft",
            pattern="non-ascii",
            detail=f"non-ASCII characters detected: {chars_repr}",
        )]
    return []


def check_invalid_utf8(field_path: str, raw_bytes: bytes) -> List[Finding]:
    """
    Detect invalid UTF-8 bytes in raw_bytes (S3-7 — hard finding).
    Returns finding with the byte offset of the first invalid sequence.
    """
    try:
        raw_bytes.decode("utf-8")
        return []
    except UnicodeDecodeError as exc:
        return [Finding(
            field=field_path,
            severity="hard",
            pattern="invalid-utf8",
            detail=f"invalid UTF-8 sequence at byte offset {exc.start}",
        )]


def check_structural_anomaly(tools: list) -> List[Finding]:
    """
    Flag any tool whose description length exceeds 3× the median description
    length across all tools on the server (S3-6 — soft finding).

    Returns an empty list for a single-tool list (no comparison possible)
    and for an empty list.
    """
    if len(tools) < 2:
        return []

    descriptions = [
        str(t.get("description", "")) for t in tools
        if isinstance(t, dict)
    ]
    if not descriptions:
        return []

    lengths = [len(d) for d in descriptions]
    sorted_lengths = sorted(lengths)
    n = len(sorted_lengths)
    mid = n // 2
    if n % 2 == 1:
        median_len = sorted_lengths[mid]
    else:
        median_len = (sorted_lengths[mid - 1] + sorted_lengths[mid]) / 2

    threshold = 3 * median_len
    findings = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        desc = str(tool.get("description", ""))
        if len(desc) > threshold:
            tool_name = tool.get("name", "<unknown>")
            findings.append(Finding(
                field="description",
                severity="soft",
                pattern="structural-anomaly",
                detail=(
                    f"tool '{tool_name}' description length {len(desc)} "
                    f"exceeds 3× median ({int(threshold)})"
                ),
            ))
    return findings


def check_shadowing(
    field_path: str,
    value: str,
    registry: dict,
    current_server: str,
) -> List[Finding]:
    """
    Detect cross-server tool shadowing: check whether any tool name from another
    server already present in the registry appears in value using word-boundary
    exact match, case-insensitive (S3-4 — soft finding).

    Word-boundary match prevents partial matches (e.g. "search" inside
    "search_issues" does NOT trigger for tool name "search").
    """
    findings = []
    for server_name, server_data in registry.items():
        if server_name == current_server:
            # Do not check a server against its own tool names
            continue
        if not isinstance(server_data, dict):
            continue
        tools_in_registry = server_data.get("tools", {})
        if not isinstance(tools_in_registry, dict):
            continue
        for tool_name in tools_in_registry:
            if not tool_name:
                continue
            # Word-boundary delimited, case-insensitive exact match
            pattern = r"\b" + re.escape(tool_name) + r"\b"
            if re.search(pattern, value, re.IGNORECASE):
                findings.append(Finding(
                    field=field_path,
                    severity="soft",
                    pattern=f"shadowing:{tool_name}",
                    detail=(
                        f"tool name '{tool_name}' from server '{server_name}' "
                        f"found in field '{field_path}'"
                    ),
                ))
    return findings


# ---------------------------------------------------------------------------
# scan_tool — aggregates all checks for one tool
# ---------------------------------------------------------------------------


def scan_tool(
    tool: dict,
    server: str,
    registry: dict,
) -> ToolScanResult:
    """
    Run all static checks on a single tool schema and return a ToolScanResult.

    Pure function — no I/O.

    Handles serialisation failure (JSON circular reference, encoding error)
    as a hard finding per S3-7 — returns a blocked ToolScanResult with no hash.
    """
    tool_name = tool.get("name", "<unknown>") if isinstance(tool, dict) else "<unknown>"

    # 1. Attempt to compute hash — serialisation failure is a hard finding
    try:
        tool_hash = hash_schema(tool)
    except (TypeError, ValueError) as exc:
        return ToolScanResult(
            server=server,
            tool_name=tool_name,
            hash="",
            findings=[Finding(
                field="<schema>",
                severity="hard",
                pattern="serialisation-failure",
                detail=f"JSON serialisation failed: {exc}",
            )],
            action="blocked",
        )

    findings: List[Finding] = []

    # 2. Extract all string fields — depth-guarded recursive walk
    string_fields = extract_string_fields(tool)

    # 3. Run per-field checks
    for path, value in string_fields:
        if path.startswith("__finding__:"):
            # Non-string leaf or depth exceeded — emit soft finding
            actual_path = path[len("__finding__:"):]
            if value == "depth_exceeded":
                findings.append(Finding(
                    field=actual_path,
                    severity="soft",
                    pattern="depth-exceeded",
                    detail=f"schema nesting exceeded max depth ({_MAX_DEPTH}); deeper content not inspected",
                ))
            else:
                findings.append(Finding(
                    field=actual_path,
                    severity="soft",
                    pattern="unexpected-type",
                    detail=f"unexpected type '{value}' where string expected",
                ))
            continue

        # Hard checks (hidden chars, whitespace runs, invalid UTF-8 — S3-7)
        findings.extend(check_hidden_chars(path, value))
        findings.extend(check_whitespace_runs(path, value))
        # check_invalid_utf8 operates on raw bytes — encode the already-decoded
        # Python str back to bytes using latin-1 (preserves surrogate/mojibake
        # byte values that survived JSON parsing as lone surrogates).
        # For well-formed Python strings this never raises; surrogateescaped bytes
        # are the primary target here.
        try:
            raw = value.encode("latin-1")
        except (UnicodeEncodeError, UnicodeDecodeError):
            raw = value.encode("utf-8", errors="surrogateescape")
        findings.extend(check_invalid_utf8(path, raw))

        # Soft checks
        findings.extend(check_keywords(path, value))
        findings.extend(check_non_ascii(path, value))
        findings.extend(check_shadowing(path, value, registry, server))

    # 4. Determine action from findings
    has_hard = any(f.severity == "hard" for f in findings)
    if has_hard:
        action = "blocked"
    elif findings:
        action = "pending_approval"
    else:
        action = "pinned"

    return ToolScanResult(
        server=server,
        tool_name=tool_name,
        hash=tool_hash,
        findings=findings,
        action=action,
    )


# ---------------------------------------------------------------------------
# Pin registry — action functions (I/O)
# ---------------------------------------------------------------------------


def load_registry(path: Path) -> dict:
    """
    Load the pin registry from path.

    Returns {} if the file does not exist.
    On invalid JSON: renames corrupt file to <path>.bak (overwriting any existing .bak),
    logs error to stderr, returns {}.
    """
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, ValueError) as exc:
        bak_path = path.with_suffix(".json.bak")
        try:
            path.rename(bak_path)
        except OSError as rename_err:
            # If rename fails, try copy-then-delete
            try:
                import shutil
                shutil.copy2(str(path), str(bak_path))
                path.unlink()
            except OSError:
                pass
            print(
                f"[mcp_scanner] Warning: could not rename corrupt registry to .bak: {rename_err}",
                file=sys.stderr,
            )
        print(
            f"[mcp_scanner] Error: registry file {path} contained invalid JSON ({exc}). "
            f"Renamed to {bak_path}. Treating all servers as first-connect.",
            file=sys.stderr,
        )
        return {}


def write_registry(path: Path, registry: dict) -> None:
    """
    Serialise registry to JSON and write to path.

    Creates the parent directory if it does not exist.
    Raises OSError on failure — the caller handles this per S1-2
    (block all tools from that server for the session).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2, ensure_ascii=False)
        fh.write("\n")  # trailing newline for clean diffs


_CURRENT_ISSUES_HEADING = "## Current Issues"
_CURRENT_ISSUES_TABLE_HEADER = "| Server | Tool | Status | Since | Last Checked |"
_CURRENT_ISSUES_TABLE_SEP = "|--------|------|--------|-------|--------------|"

# Legend moved to scripts/docs/mcp-scan.md § Status File Legend — not re-embedded on every write.
_STATUS_MD_LEGEND_REF = "_Legend: scripts/docs/mcp-scan.md § Status File Legend_"


def _parse_status_md(path: Path) -> Dict[Tuple[str, str], dict]:
    """
    Parse an existing status Markdown file and return issues dict only.

    Returns a dict keyed by (server, tool) -> {"status", "since", "last_checked"}.
    Returns {} if the file does not exist or cannot be parsed.
    Tool is "" (empty string) for server-level issues (e.g. "unreachable").

    History is no longer stored in the status file — it lives in
    .mcp-scan-history.md (append-only). This parser only handles the
    ## Current Issues table.
    """
    issues: Dict[Tuple[str, str], dict] = {}

    if not path.exists():
        return issues

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return issues

    lines = text.splitlines()
    in_issues = False
    for line in lines:
        stripped = line.strip()
        if stripped == _CURRENT_ISSUES_HEADING:
            in_issues = True
            continue
        if in_issues:
            # Stop at any new ## heading
            if stripped.startswith("## ") and stripped != _CURRENT_ISSUES_HEADING:
                break
            if not stripped.startswith("|") or stripped in (
                _CURRENT_ISSUES_TABLE_HEADER,
                _CURRENT_ISSUES_TABLE_SEP,
            ):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if len(cells) != 5:
                continue
            server, tool, status, since, last_checked = cells
            # Normalise the em-dash placeholder back to empty string
            tool = "" if tool == "—" else tool
            issues[(server, tool)] = {
                "status": status,
                "since": since,
                "last_checked": last_checked,
            }

    return issues


def render_status_md(
    path: Path,
    issues: Dict[Tuple[str, str], dict],
    timestamp: str,
) -> None:
    """
    Write the full Current Issues table (with legend) to path.

    Called once per session by the caller after ALL servers have been processed
    and the complete issues dict has been assembled in memory. Never called
    once-per-tool.

    issues: dict keyed by (server, tool) -> {"status", "since", "last_checked"}
    timestamp: readable timestamp for the "Generated" header line.

    On write failure, logs to stderr and returns without raising — status
    file failures must not block a session.
    """
    lines: List[str] = []
    lines.append("# MCP Scanner — Current Issues")
    lines.append("")
    lines.append(f"_Last updated: {timestamp}_")
    lines.append("")
    lines.append(_STATUS_MD_LEGEND_REF)
    lines.append("")
    lines.append(_CURRENT_ISSUES_HEADING)
    lines.append("")

    if issues:
        lines.append(_CURRENT_ISSUES_TABLE_HEADER)
        lines.append(_CURRENT_ISSUES_TABLE_SEP)
        # Stable order: sort by server, then tool
        for (server, tool), data in sorted(issues.items()):
            lines.append(
                f"| {server} | {tool or '—'} | {data['status']} | "
                f"{data['since']} | {data['last_checked']} |"
            )
    else:
        lines.append("_No active issues._")

    content = "\n".join(lines) + "\n"

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(
            f"[mcp_scanner] Error: could not write status file {path}: {exc}",
            file=sys.stderr,
        )


def append_history(path: Path, line: str) -> None:
    """
    Append one transition line to the append-only history file.

    Called only when a genuine status transition occurs (new issue, status
    change, or resolution). For stable pending_approval tools with an
    unchanged hash, the caller makes zero calls to this function per session.

    The file is created on first call. Each call writes exactly one line
    followed by a newline — it never rewrites existing content.

    On write failure, logs to stderr and returns without raising — history
    file failures must not block a session.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(
            f"[mcp_scanner] Error: could not append to history file {path}: {exc}",
            file=sys.stderr,
        )


def _summarise_findings(findings: list) -> str:
    """Build a short human-readable summary from a list of Finding-like dicts."""
    if not findings:
        return ""
    parts = []
    for f in findings[:2]:
        pattern = f.get("pattern", "?") if isinstance(f, dict) else getattr(f, "pattern", "?")
        parts.append(pattern)
    summary = ", ".join(parts)
    if len(findings) > 2:
        summary += f" (+{len(findings) - 2} more)"
    return summary


# Actions that represent a resolved/clean state — no active issue to show
_CLEAN_ACTIONS = frozenset({"pinned", "approved"})
# Actions that represent steady, uninteresting state — no write to either file
_QUIET_ACTIONS = frozenset({"unchanged"})


def apply_scan_result(
    issues: Dict[Tuple[str, str], dict],
    server: str,
    tool: str,
    action: str,
    findings: list,
    timestamp: str,
    detail: str = "",
) -> Optional[str]:
    """
    Apply one scan result to the in-memory issues dict (mutated in place).

    Returns a history line string if a genuine transition occurred, or None
    if the result is quiet (unchanged, or same-status update).

    Callers accumulate the returned history lines and pass each to
    append_history() after all servers are processed.

    server  — server name
    tool    — tool name (empty string "" for server-level events)
    action  — result action string ("pending_approval", "blocked",
               "unreachable", "tool_removed", "pinned", "approved",
               "unchanged")
    findings — list of Finding or Finding-like dicts (used for summary)
    timestamp — readable timestamp string
    detail  — optional override for the history line detail text; if empty,
               a summary is built from findings

    Behaviour:
      - action in _QUIET_ACTIONS ("unchanged"): no-op, issues dict untouched.
      - action in _CLEAN_ACTIONS with no findings ("pinned", "approved"):
          if a prior issue exists → remove row + return history transition line
          if no prior issue → no-op (nothing to record)
      - otherwise (new issue or status update):
          if same status as current row → update last_checked only, no history line
          if new or different status → add/update row + return history line
    """
    if action in _QUIET_ACTIONS:
        return None

    key = (server, tool)
    is_clean = action in _CLEAN_ACTIONS and not findings

    previous = issues.get(key)
    previous_status = previous["status"] if previous else None
    tool_label = ("/" + tool) if tool else ""

    if is_clean:
        if previous is not None:
            del issues[key]
            return (
                f"{timestamp} — {server}{tool_label}: {previous_status} → clean"
            )
        return None  # already clean, nothing to record

    # Active issue — add or update
    detail_str = detail or _summarise_findings(findings)
    status_label = action

    if previous_status == status_label:
        # Same status — refresh Last Checked only, no history line
        issues[key]["last_checked"] = timestamp
        return None

    # New issue or status change
    issues[key] = {
        "status": status_label,
        "since": timestamp,
        "last_checked": timestamp,
    }
    transition = f"{previous_status} → " if previous_status else ""
    detail_part = f" ({detail_str})" if detail_str else ""
    return (
        f"{timestamp} — {server}{tool_label}: {transition}{status_label}{detail_part}"
    )


# ---------------------------------------------------------------------------
# compare_server — compares live tool list against registry
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string with timezone offset."""
    return datetime.now(timezone.utc).astimezone().isoformat()


def now_readable() -> str:
    """Return current local time as a readable 'YYYY-MM-DD HH:MM:SS' string."""
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _apply_structural_anomaly(
    tools: list, results: List["ToolScanResult"], registry: Optional[dict] = None,
    server: Optional[str] = None,
) -> None:
    """
    Run check_structural_anomaly on the full tool list and attach any findings
    to the matching ToolScanResult in-place (S3-6).

    Structural anomaly is a cross-tool check — it cannot be run inside scan_tool
    because scan_tool sees only one tool at a time. This helper is called at each
    compare_server return point after the per-tool results are built.

    registry/server (optional): if provided, a tool already recorded with
    approved_by in the registry is left as-is (its action is not upgraded to
    pending_approval) — an explicit approval should not be silently
    re-flagged on every subsequent scan. Without registry/server (e.g. a
    first-connect scan with no prior registry entry), the finding is applied
    unconditionally as before.
    """
    anomaly_findings = check_structural_anomaly(tools)
    if not anomaly_findings:
        return

    # Index results by tool name for O(1) lookup
    results_by_name = {r.tool_name: r for r in results}

    for finding in anomaly_findings:
        # finding.detail contains "tool '<name>' description length ..."
        # Extract the tool name from the detail string (reliable — we wrote the format)
        # Pattern: tool '<name>' description length ...
        m = re.search(r"tool '([^']+)'", finding.detail)
        if m:
            tool_name = m.group(1)
            result = results_by_name.get(tool_name)
            if result is not None:
                # Skip re-flagging a tool that already has an explicit
                # approval recorded in the registry — otherwise this
                # cross-tool check silently undoes the approval-preserving
                # logic in compare_server's hash-comparison branch below.
                already_approved = False
                if registry is not None and server is not None:
                    server_entry = registry.get(server, {})
                    tool_entry = server_entry.get("tools", {}).get(tool_name, {})
                    already_approved = bool(tool_entry.get("approved_by"))

                if already_approved:
                    continue

                result.findings.append(finding)
                # Upgrade action from "pinned"/"unchanged" to "pending_approval"
                # if the tool was previously clean (hard findings are unaffected)
                if result.action not in ("blocked", "tool_removed"):
                    result.action = "pending_approval"


def compare_server(
    server: str,
    server_version: str,
    tools: list,
    registry: dict,
) -> Tuple[str, List[ToolScanResult]]:
    """
    Compare the live tool list for a server against the pin registry.

    Returns (event_type, list[ToolScanResult]).

    Note on protocol_version (design Decision 16): the server's advertised
    protocolVersion is captured by the caller (hook/CLI) from the initialize
    response and written by the caller into the registry entry and each log
    entry. It is deliberately NOT a parameter here — compare_server neither
    writes the registry nor the log, and protocol_version has no effect on
    comparison or blocking logic, so accepting it would be a dead parameter.

    event_type is one of:
        "first_connect"   — server not in registry
        "version_changed" — server in registry but version differs
        "hash_changed"    — version same but one or more tool hashes changed
        "new_tool"        — version same but a new tool name appeared
        "tool_removed"    — a previously pinned tool is absent from live list
        "unchanged"       — version same and all hashes match

    Registry is read-only here — the caller writes the registry after this
    function returns (before processing the next server).
    """
    server_entry = registry.get(server)
    live_tool_names = {t.get("name") for t in tools if isinstance(t, dict)}

    # --- First connect ---
    if server_entry is None:
        results = [scan_tool(t, server, registry) for t in tools if isinstance(t, dict)]
        _apply_structural_anomaly(tools, results)
        return "first_connect", results

    pinned_version = server_entry.get("server_version", "")
    pinned_tools: dict = server_entry.get("tools", {})

    # --- Tool removed detection (S2-1) ---
    removed_results: List[ToolScanResult] = []
    for pinned_name, pinned_data in pinned_tools.items():
        if pinned_data.get("status") == "removed":
            # Already marked removed in a previous session — skip
            continue
        if pinned_name not in live_tool_names:
            removed_results.append(ToolScanResult(
                server=server,
                tool_name=pinned_name,
                hash=pinned_data.get("hash", ""),
                findings=[Finding(
                    field="<registry>",
                    severity="soft",
                    pattern="tool-removed",
                    detail=f"tool '{pinned_name}' was in the pin registry but is no longer present on the server",
                )],
                action="tool_removed",
            ))

    # --- Version changed (S2-2) ---
    if server_version != pinned_version:
        results = [scan_tool(t, server, registry) for t in tools if isinstance(t, dict)]
        combined = removed_results + results
        _apply_structural_anomaly(tools, combined)
        return "version_changed", combined

    # --- Hash comparison — check each live tool (S2-3, S2-4) ---
    has_hash_changed = False
    has_new_tool = False
    mixed_results: List[ToolScanResult] = list(removed_results)

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name")
        if tool_name not in pinned_tools:
            # New tool (S2-4)
            has_new_tool = True
            result = scan_tool(tool, server, registry)
            mixed_results.append(result)
        else:
            # Known tool — check hash
            live_hash = hash_schema(tool)
            pinned_hash = pinned_tools[tool_name].get("hash", "")
            if live_hash != pinned_hash:
                has_hash_changed = True
                result = scan_tool(tool, server, registry)
                # Override action to reflect hash-change context
                result.action = "blocked"
                mixed_results.append(result)
            else:
                # Hash unchanged. If this tool was previously pinned with
                # findings but never explicitly approved (approved_by unset),
                # keep surfacing it as pending_approval instead of going
                # silent — S6-2 requires soft findings to stay pending until
                # explicit approval; a stable hash alone does not constitute
                # approval. Re-run scan_tool to recompute the findings for
                # display (cheap — pure function, no I/O).
                pinned_tool_data = pinned_tools[tool_name]
                if pinned_tool_data.get("approved_by"):
                    # Explicitly approved — safe to go fully quiet (S2-1)
                    mixed_results.append(ToolScanResult(
                        server=server,
                        tool_name=tool_name,
                        hash=live_hash,
                        findings=[],
                        action="unchanged",
                    ))
                else:
                    result = scan_tool(tool, server, registry)
                    if result.findings:
                        # Still has findings and never approved — keep pending
                        result.action = "pending_approval"
                        mixed_results.append(result)
                    else:
                        # No findings at all (e.g. auto-pinned clean tool) — quiet
                        mixed_results.append(ToolScanResult(
                            server=server,
                            tool_name=tool_name,
                            hash=live_hash,
                            findings=[],
                            action="unchanged",
                        ))

    if has_hash_changed:
        event = "hash_changed"
    elif has_new_tool:
        event = "new_tool"
    elif removed_results:
        event = "tool_removed"
    else:
        event = "unchanged"

    _apply_structural_anomaly(tools, mixed_results, registry=registry, server=server)
    return event, mixed_results
