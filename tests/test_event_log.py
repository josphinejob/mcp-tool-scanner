"""
Status file and history file tests — render_status_md, append_history,
apply_scan_result.

Replaces tests for the old update_status_md function (redesigned 2026-08-11:
split into two files + batch write pattern).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "_mcp_scanner", str(Path(__file__).resolve().parents[1] / "mcp_scanner.py")
)
mcp_scanner = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(mcp_scanner)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pending_entry() -> dict:
    return {
        "server": "notion",
        "tool": "search_pages",
        "action": "pending_approval",
        "findings": [{"field": "description", "severity": "soft",
                      "pattern": "non-ascii", "detail": "U+2014"}],
    }

TS1 = "2026-08-10 01:22:44"
TS2 = "2026-08-10 02:00:00"


# ---------------------------------------------------------------------------
# apply_scan_result — transition logic
# ---------------------------------------------------------------------------

class TestApplyScanResult:

    def test_new_issue_adds_row_returns_history_line(self):
        issues = {}
        e = _pending_entry()
        line = mcp_scanner.apply_scan_result(
            issues, e["server"], e["tool"], e["action"], e["findings"], TS1,
        )
        assert ("notion", "search_pages") in issues
        assert issues[("notion", "search_pages")]["status"] == "pending_approval"
        assert line is not None
        assert "notion" in line
        assert "pending_approval" in line
        assert TS1 in line

    def test_same_status_updates_last_checked_only_no_history_line(self):
        issues = {}
        e = _pending_entry()
        mcp_scanner.apply_scan_result(
            issues, e["server"], e["tool"], e["action"], e["findings"], TS1,
        )
        line = mcp_scanner.apply_scan_result(
            issues, e["server"], e["tool"], e["action"], e["findings"], TS2,
        )
        assert line is None
        assert issues[("notion", "search_pages")]["last_checked"] == TS2
        assert issues[("notion", "search_pages")]["since"] == TS1

    def test_unchanged_action_is_no_op(self):
        issues = {}
        line = mcp_scanner.apply_scan_result(
            issues, "notion", "search_pages", "unchanged", [], TS1,
        )
        assert line is None
        assert issues == {}

    def test_clean_action_removes_existing_issue_and_returns_history_line(self):
        issues = {}
        # Seed an existing issue
        mcp_scanner.apply_scan_result(
            issues, "notion", "search_pages", "pending_approval",
            [{"field": "d", "severity": "soft", "pattern": "non-ascii", "detail": "x"}],
            TS1,
        )
        line = mcp_scanner.apply_scan_result(
            issues, "notion", "search_pages", "approved", [], TS2,
        )
        assert ("notion", "search_pages") not in issues
        assert line is not None
        assert "→ clean" in line

    def test_clean_action_no_prior_issue_is_no_op(self):
        issues = {}
        line = mcp_scanner.apply_scan_result(
            issues, "notion", "search_pages", "approved", [], TS1,
        )
        assert line is None
        assert issues == {}

    def test_status_change_returns_transition_line(self):
        issues = {}
        mcp_scanner.apply_scan_result(
            issues, "s", "t", "pending_approval",
            [{"field": "d", "severity": "soft", "pattern": "p", "detail": "x"}], TS1,
        )
        line = mcp_scanner.apply_scan_result(
            issues, "s", "t", "blocked",
            [{"field": "d", "severity": "hard", "pattern": "hidden-char", "detail": "x"}], TS2,
        )
        assert line is not None
        assert "pending_approval → blocked" in line

    def test_server_level_entry_empty_tool_string(self):
        issues = {}
        line = mcp_scanner.apply_scan_result(
            issues, "notion", "", "unreachable", [], TS1,
        )
        assert ("notion", "") in issues
        assert line is not None
        assert "unreachable" in line


# ---------------------------------------------------------------------------
# render_status_md
# ---------------------------------------------------------------------------

class TestRenderStatusMd:

    def test_creates_file_with_current_issues_heading(self, tmp_path):
        path = tmp_path / ".mcp-scan-status.md"
        issues = {("notion", "search_pages"): {
            "status": "pending_approval", "since": TS1, "last_checked": TS1
        }}
        mcp_scanner.render_status_md(path, issues, TS1)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "## Current Issues" in content
        assert "notion" in content
        assert "search_pages" in content
        assert "pending_approval" in content

    def test_empty_issues_writes_no_active_issues_message(self, tmp_path):
        path = tmp_path / ".mcp-scan-status.md"
        mcp_scanner.render_status_md(path, {}, TS1)
        content = path.read_text(encoding="utf-8")
        assert "## Current Issues" in content
        assert "_No active issues._" in content

    def test_write_failure_logs_to_stderr_does_not_raise(self, tmp_path, capsys):
        readonly_dir = tmp_path / "ro"
        readonly_dir.mkdir()
        os.chmod(str(readonly_dir), 0o444)
        path = readonly_dir / ".mcp-scan-status.md"
        try:
            mcp_scanner.render_status_md(path, {}, TS1)
            captured = capsys.readouterr()
            assert "error" in captured.err.lower()
        finally:
            os.chmod(str(readonly_dir), 0o755)

    def test_server_level_issue_renders_em_dash_for_tool(self, tmp_path):
        path = tmp_path / ".mcp-scan-status.md"
        issues = {("notion", ""): {
            "status": "unreachable", "since": TS1, "last_checked": TS1
        }}
        mcp_scanner.render_status_md(path, issues, TS1)
        content = path.read_text(encoding="utf-8")
        assert "notion" in content
        assert "unreachable" in content
        # Empty tool should render as em-dash in the table
        assert "—" in content


# ---------------------------------------------------------------------------
# append_history
# ---------------------------------------------------------------------------

class TestAppendHistory:

    def test_creates_file_on_first_call(self, tmp_path):
        path = tmp_path / ".mcp-scan-history.md"
        mcp_scanner.append_history(path, "2026-08-10 01:22:44 — notion/search_pages: pending_approval")
        assert path.exists()
        assert "notion" in path.read_text(encoding="utf-8")

    def test_subsequent_calls_append_not_overwrite(self, tmp_path):
        path = tmp_path / ".mcp-scan-history.md"
        mcp_scanner.append_history(path, "line 1")
        mcp_scanner.append_history(path, "line 2")
        content = path.read_text(encoding="utf-8")
        assert "line 1" in content
        assert "line 2" in content
        # Both lines must be present (not overwritten)
        assert content.index("line 1") < content.index("line 2")

    def test_no_write_when_not_called(self, tmp_path):
        path = tmp_path / ".mcp-scan-history.md"
        # Simply never calling append_history means no file is created
        assert not path.exists()

    def test_write_failure_logs_to_stderr_does_not_raise(self, tmp_path, capsys):
        readonly_dir = tmp_path / "ro"
        readonly_dir.mkdir()
        os.chmod(str(readonly_dir), 0o444)
        path = readonly_dir / ".mcp-scan-history.md"
        try:
            mcp_scanner.append_history(path, "line")
            captured = capsys.readouterr()
            assert "error" in captured.err.lower()
        finally:
            os.chmod(str(readonly_dir), 0o755)


# ---------------------------------------------------------------------------
# _parse_status_md — reads Current Issues only
# ---------------------------------------------------------------------------

class TestParseStatusMd:

    def test_round_trip_through_render_and_parse(self, tmp_path):
        path = tmp_path / ".mcp-scan-status.md"
        original_issues = {
            ("server-a", "tool1"): {"status": "pending_approval", "since": TS1, "last_checked": TS2},
            ("server-b", ""): {"status": "unreachable", "since": TS1, "last_checked": TS1},
        }
        mcp_scanner.render_status_md(path, original_issues, TS2)
        parsed = mcp_scanner._parse_status_md(path)
        assert parsed == original_issues

    def test_returns_empty_dict_when_file_missing(self, tmp_path):
        path = tmp_path / "nonexistent.md"
        assert mcp_scanner._parse_status_md(path) == {}
