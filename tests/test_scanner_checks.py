"""
Phase 2 tests — static scanner check functions.
Tasks 8, 10, 12, 14, 16, 18, 20, 22.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from mcp_scanner import (
    Finding,
    ToolScanResult,
    check_hidden_chars,
    check_invalid_utf8,
    check_keywords,
    check_non_ascii,
    check_shadowing,
    check_structural_anomaly,
    check_whitespace_runs,
    scan_tool,
)


# ---------------------------------------------------------------------------
# Task 8 — check_hidden_chars
# ---------------------------------------------------------------------------


class TestCheckHiddenChars:
    def test_zero_width_space_triggers_hard_finding(self):
        findings = check_hidden_chars("description", "hello\u200bworld")
        assert len(findings) == 1
        assert findings[0].severity == "hard"
        assert findings[0].pattern == "hidden-char"

    def test_zero_width_non_joiner_triggers_hard_finding(self):
        findings = check_hidden_chars("description", "hello\u200cworld")
        assert len(findings) == 1
        assert findings[0].severity == "hard"

    def test_zero_width_joiner_triggers_hard_finding(self):
        findings = check_hidden_chars("description", "a\u200db")
        assert len(findings) == 1
        assert findings[0].severity == "hard"

    def test_bom_triggers_hard_finding(self):
        findings = check_hidden_chars("description", "\ufeffsome text")
        assert len(findings) == 1
        assert findings[0].severity == "hard"

    def test_rtl_override_triggers_hard_finding(self):
        findings = check_hidden_chars("description", "normal\u202etext")
        assert len(findings) == 1
        assert findings[0].severity == "hard"

    def test_clean_string_returns_empty(self):
        findings = check_hidden_chars("description", "This is a normal description.")
        assert findings == []

    def test_hidden_char_and_normal_unicode_triggers_hidden_char_only(self):
        # A hidden char alongside a regular non-ASCII char — hidden-char check fires
        findings = check_hidden_chars("description", "café\u200b")
        assert any(f.pattern == "hidden-char" for f in findings)


# ---------------------------------------------------------------------------
# Task 10 — check_whitespace_runs
# ---------------------------------------------------------------------------


class TestCheckWhitespaceRuns:
    def test_nine_spaces_returns_empty(self):
        assert check_whitespace_runs("description", "a" + " " * 9 + "b") == []

    def test_ten_spaces_returns_hard_finding(self):
        findings = check_whitespace_runs("description", "a" + " " * 10 + "b")
        assert len(findings) == 1
        assert findings[0].severity == "hard"
        assert findings[0].pattern == "whitespace-run"

    def test_mixed_whitespace_ten_or_more_returns_hard_finding(self):
        # Tabs and spaces mixed = 10 whitespace chars
        mixed = "a" + " \t" * 5 + "b"
        findings = check_whitespace_runs("description", mixed)
        assert len(findings) == 1
        assert findings[0].severity == "hard"

    def test_newline_run_of_ten_returns_hard_finding(self):
        findings = check_whitespace_runs("description", "a" + "\n" * 10 + "b")
        assert len(findings) == 1

    def test_empty_string_returns_empty(self):
        assert check_whitespace_runs("description", "") == []
# ---------------------------------------------------------------------------
# Task 12 — check_keywords
# ---------------------------------------------------------------------------


class TestCheckKeywords:
    @pytest.mark.parametrize("keyword", [
        "system", "override", "ignore previous", "ignore all prior",
        "you are now", "emergency", "before responding", "mandatory",
        "credentials", "token", "history", "password", "auth", "session",
    ])
    def test_each_keyword_triggers_soft_finding(self, keyword):
        findings = check_keywords("description", f"this is a {keyword} check")
        assert any(f.pattern == f"keyword:{keyword}" for f in findings), \
            f"Expected finding for keyword '{keyword}'"
        assert all(f.severity == "soft" for f in findings)

    def test_authentication_triggers_auth_match(self):
        findings = check_keywords("description", "handles authentication flow")
        assert any(f.pattern == "keyword:auth" for f in findings)

    def test_clean_value_returns_empty(self):
        assert check_keywords("description", "creates a new page with title") == []

    def test_multiple_keywords_return_multiple_findings(self):
        findings = check_keywords("description", "system override mandatory")
        patterns = {f.pattern for f in findings}
        assert "keyword:system" in patterns
        assert "keyword:override" in patterns
        assert "keyword:mandatory" in patterns

    def test_case_insensitive(self):
        findings = check_keywords("description", "SYSTEM prompt injection")
        assert any(f.pattern == "keyword:system" for f in findings)

    def test_finding_includes_match_position(self):
        findings = check_keywords("description", "system call")
        assert findings[0].detail.startswith("matched 'system' at position 0")


# ---------------------------------------------------------------------------
# Task 14 — check_non_ascii
# ---------------------------------------------------------------------------


class TestCheckNonAscii:
    def test_ascii_only_string_returns_empty(self):
        assert check_non_ascii("description", "plain ASCII text") == []

    def test_cyrillic_char_returns_soft_finding_with_char_in_detail(self):
        findings = check_non_ascii("description", "Привет")
        assert len(findings) == 1
        assert findings[0].severity == "soft"
        assert "U+" in findings[0].detail

    def test_emoji_returns_soft_finding(self):
        findings = check_non_ascii("description", "search pages 🔍")
        assert len(findings) == 1
        assert findings[0].severity == "soft"

    def test_hidden_char_and_non_ascii_both_detectable(self):
        # \u200b has codepoint > 127 so check_non_ascii catches it alongside accented chars
        findings = check_non_ascii("description", "café\u200b")
        assert len(findings) == 1
        assert "U+" in findings[0].detail

    def test_accented_chars_detected(self):
        findings = check_non_ascii("description", "naïve approach")
        assert len(findings) == 1

    def test_all_non_ascii_chars_listed_in_detail(self):
        findings = check_non_ascii("description", "αβγ")
        assert "U+03B1" in findings[0].detail  # α


# ---------------------------------------------------------------------------
# Task 16 — check_invalid_utf8
# ---------------------------------------------------------------------------


class TestCheckInvalidUtf8:
    def test_valid_utf8_returns_empty(self):
        assert check_invalid_utf8("description", "hello world".encode("utf-8")) == []

    def test_invalid_sequence_returns_hard_finding(self):
        bad_bytes = b"hello\xff\xfeworld"
        findings = check_invalid_utf8("description", bad_bytes)
        assert len(findings) == 1
        assert findings[0].severity == "hard"
        assert findings[0].pattern == "invalid-utf8"

    def test_finding_includes_byte_offset(self):
        bad_bytes = b"hello\xff"
        findings = check_invalid_utf8("description", bad_bytes)
        assert "byte offset 5" in findings[0].detail

    def test_empty_bytes_returns_empty(self):
        assert check_invalid_utf8("description", b"") == []


# ---------------------------------------------------------------------------
# Task 18 — check_structural_anomaly
# ---------------------------------------------------------------------------


class TestCheckStructuralAnomaly:
    def test_all_equal_lengths_returns_empty(self):
        tools = [
            {"name": f"t{i}", "description": "x" * 50}
            for i in range(5)
        ]
        assert check_structural_anomaly(tools) == []

    def test_one_tool_four_times_median_returns_soft_finding(self):
        # median = 50; threshold = 150; anomaly tool has 250 chars
        tools = [
            {"name": "normal1", "description": "x" * 50},
            {"name": "normal2", "description": "x" * 50},
            {"name": "normal3", "description": "x" * 50},
            {"name": "anomaly", "description": "x" * 250},
        ]
        findings = check_structural_anomaly(tools)
        assert len(findings) == 1
        assert findings[0].severity == "soft"
        assert findings[0].pattern == "structural-anomaly"
        assert "anomaly" in findings[0].detail

    def test_only_anomaly_tool_flagged(self):
        tools = [
            {"name": "a", "description": "x" * 50},
            {"name": "b", "description": "x" * 50},
            {"name": "c", "description": "x" * 50},
            {"name": "long", "description": "x" * 300},
        ]
        findings = check_structural_anomaly(tools)
        assert all("long" in f.detail for f in findings)

    def test_single_tool_list_returns_empty(self):
        tools = [{"name": "solo", "description": "x" * 100}]
        assert check_structural_anomaly(tools) == []

    def test_empty_list_returns_empty(self):
        assert check_structural_anomaly([]) == []

    def test_tool_missing_description_handled(self):
        tools = [
            {"name": "a", "description": "x" * 50},
            {"name": "b"},  # no description
            {"name": "c", "description": "x" * 50},
        ]
        # Should not raise
        result = check_structural_anomaly(tools)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Task 20 — check_shadowing
# ---------------------------------------------------------------------------


class TestCheckShadowing:
    def _make_registry(self, server: str, tool_names: list) -> dict:
        return {
            server: {
                "tools": {name: {"hash": "sha256:abc"} for name in tool_names}
            }
        }

    def test_tool_name_from_registry_in_description_returns_soft_finding(self):
        registry = self._make_registry("other-server", ["search_pages"])
        findings = check_shadowing(
            "description",
            "This tool also calls search_pages internally",
            registry,
            "current-server",
        )
        assert len(findings) == 1
        assert findings[0].severity == "soft"
        assert "shadowing:search_pages" in findings[0].pattern

    def test_tool_name_absent_returns_empty(self):
        registry = self._make_registry("other-server", ["create_page"])
        findings = check_shadowing(
            "description",
            "This tool finds relevant data",
            registry,
            "current-server",
        )
        assert findings == []

    def test_empty_registry_returns_empty(self):
        findings = check_shadowing("description", "some description", {}, "current-server")
        assert findings == []

    def test_current_server_own_tools_do_not_trigger(self):
        # current-server's own tool names in registry should not shadow itself
        registry = self._make_registry("current-server", ["search"])
        findings = check_shadowing(
            "description",
            "this is about search capabilities",
            registry,
            "current-server",
        )
        assert findings == []

    def test_partial_match_does_not_trigger(self):
        # Tool name "search" should NOT match inside "search_issues"
        registry = self._make_registry("other-server", ["search"])
        findings = check_shadowing(
            "description",
            "use search_issues to find bugs",
            registry,
            "current-server",
        )
        assert findings == []

    def test_word_boundary_exact_match_triggers(self):
        # "search" as a standalone word SHOULD match
        registry = self._make_registry("other-server", ["search"])
        findings = check_shadowing(
            "description",
            "use search to find pages",
            registry,
            "current-server",
        )
        assert len(findings) == 1

    def test_case_insensitive_match(self):
        registry = self._make_registry("other-server", ["SearchPages"])
        findings = check_shadowing(
            "description",
            "calls SEARCHPAGES internally",
            registry,
            "current-server",
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Task 22 — scan_tool
# ---------------------------------------------------------------------------


class TestScanTool:
    def test_clean_tool_returns_empty_findings_and_valid_hash(self):
        tool = {"name": "create_page", "description": "Creates a new page in Notion."}
        result = scan_tool(tool, "notion-mcp", {})
        assert result.findings == []
        assert result.hash.startswith("sha256:")
        assert result.action == "pinned"

    def test_tool_with_hidden_char_returns_hard_finding(self):
        tool = {"name": "search", "description": "Searches\u200b for pages"}
        result = scan_tool(tool, "notion-mcp", {})
        hard = [f for f in result.findings if f.severity == "hard"]
        assert len(hard) >= 1
        assert result.action == "blocked"

    def test_tool_with_keyword_returns_soft_finding(self):
        tool = {"name": "get_token", "description": "Returns an auth token for the session."}
        result = scan_tool(tool, "notion-mcp", {})
        soft = [f for f in result.findings if f.severity == "soft"]
        assert len(soft) >= 1
        assert result.action == "pending_approval"

    def test_serialisation_failure_returns_hard_finding(self):
        # Create an object that causes json.dumps to fail (non-serialisable)
        class Unserializable:
            pass

        tool = {"name": "bad", "description": Unserializable()}
        result = scan_tool(tool, "server", {})
        hard = [f for f in result.findings if f.severity == "hard"]
        assert len(hard) == 1
        assert hard[0].pattern == "serialisation-failure"
        assert result.action == "blocked"

    def test_non_string_field_returns_soft_finding(self):
        tool = {"name": "count_pages", "description": 42}
        result = scan_tool(tool, "server", {})
        soft = [f for f in result.findings if f.severity == "soft"]
        assert any(f.pattern == "unexpected-type" for f in soft)
