"""
Phase 3 tests — pin registry: load_registry, write_registry, compare_server.
Tasks 24, 26, 28.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from mcp_scanner import (
    compare_server,
    hash_schema,
    load_registry,
    write_registry,
)


# ---------------------------------------------------------------------------
# Task 24 — load_registry
# ---------------------------------------------------------------------------


class TestLoadRegistry:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        assert load_registry(path) == {}

    def test_valid_json_returns_parsed_dict(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        data = {"notion-mcp": {"server_version": "1.0", "tools": {}}}
        path.write_text(json.dumps(data), encoding="utf-8")
        result = load_registry(path)
        assert result == data

    def test_invalid_json_returns_empty_dict(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        path.write_text("{ not valid json }", encoding="utf-8")
        result = load_registry(path)
        assert result == {}

    def test_invalid_json_renames_to_bak(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        bak_path = tmp_path / ".mcp-pins.json.bak"
        path.write_text("corrupted!!", encoding="utf-8")
        load_registry(path)
        assert bak_path.exists()
        assert not path.exists()

    def test_existing_bak_overwritten_by_new_corrupt(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        bak_path = tmp_path / ".mcp-pins.json.bak"
        # Pre-existing .bak with old content
        bak_path.write_text("old backup", encoding="utf-8")
        # New corrupt registry
        corrupt_content = "new corrupted content"
        path.write_text(corrupt_content, encoding="utf-8")
        load_registry(path)
        # .bak should now contain the new corrupt content, overwriting old backup
        assert bak_path.read_text(encoding="utf-8") == corrupt_content


# ---------------------------------------------------------------------------
# Task 26 — write_registry
# ---------------------------------------------------------------------------


class TestWriteRegistry:
    def test_written_file_matches_input_dict(self, tmp_path):
        path = tmp_path / ".mcp-pins.json"
        data = {
            "notion-mcp": {
                "server_version": "2.1",
                "tools": {
                    "search_pages": {"hash": "sha256:abc", "approved_by": "auto"},
                },
            }
        }
        write_registry(path, data)
        assert load_registry(path) == data

    def test_write_to_read_only_path_raises_oserror(self, tmp_path):
        # Create a read-only directory
        ro_dir = tmp_path / "readonly"
        ro_dir.mkdir()
        os.chmod(str(ro_dir), 0o444)
        path = ro_dir / ".mcp-pins.json"
        try:
            with pytest.raises(OSError):
                write_registry(path, {})
        finally:
            os.chmod(str(ro_dir), 0o755)


# ---------------------------------------------------------------------------
# Task 28 — compare_server
# ---------------------------------------------------------------------------


class TestCompareServer:
    def _make_tool(self, name: str, description: str = "A tool.") -> dict:
        return {"name": name, "description": description}

    def test_unknown_server_returns_first_connect(self):
        tools = [self._make_tool("search")]
        event, results = compare_server("new-server", "1.0", tools, {})
        assert event == "first_connect"
        assert len(results) == 1
        assert results[0].tool_name == "search"

    def test_known_server_same_version_same_hashes_returns_unchanged(self):
        tool = self._make_tool("search")
        tool_hash = hash_schema(tool)
        registry = {
            "notion-mcp": {
                "server_version": "1.0",
                "tools": {
                    "search": {"hash": tool_hash, "approved_by": "auto"},
                },
            }
        }
        event, results = compare_server("notion-mcp", "1.0", [tool], registry)
        assert event == "unchanged"
        assert results[0].action == "unchanged"

    def test_known_server_different_version_returns_version_changed(self):
        tool = self._make_tool("search")
        tool_hash = hash_schema(tool)
        registry = {
            "notion-mcp": {
                "server_version": "1.0",
                "tools": {
                    "search": {"hash": tool_hash, "approved_by": "auto"},
                },
            }
        }
        event, results = compare_server("notion-mcp", "2.0", [tool], registry)
        assert event == "version_changed"
        assert len(results) >= 1

    def test_known_server_same_version_hash_changed_returns_hash_changed(self):
        original_tool = self._make_tool("search", "Finds pages.")
        modified_tool = self._make_tool("search", "Modified description — now does something else.")
        original_hash = hash_schema(original_tool)
        registry = {
            "notion-mcp": {
                "server_version": "1.0",
                "tools": {
                    "search": {"hash": original_hash, "approved_by": "auto"},
                },
            }
        }
        event, results = compare_server("notion-mcp", "1.0", [modified_tool], registry)
        assert event == "hash_changed"
        changed = [r for r in results if r.tool_name == "search"]
        assert changed[0].action == "blocked"

    def test_known_server_new_tool_returns_new_tool(self):
        old_tool = self._make_tool("search")
        old_hash = hash_schema(old_tool)
        new_tool = self._make_tool("create_page", "Creates a page.")
        registry = {
            "notion-mcp": {
                "server_version": "1.0",
                "tools": {
                    "search": {"hash": old_hash, "approved_by": "auto"},
                },
            }
        }
        event, results = compare_server("notion-mcp", "1.0", [old_tool, new_tool], registry)
        assert event == "new_tool"
        new_results = [r for r in results if r.tool_name == "create_page"]
        assert len(new_results) == 1

    def test_previously_pinned_tool_absent_returns_tool_removed(self):
        old_tool = self._make_tool("search")
        old_hash = hash_schema(old_tool)
        another_tool = self._make_tool("create_page", "Creates a page.")
        another_hash = hash_schema(another_tool)
        registry = {
            "notion-mcp": {
                "server_version": "1.0",
                "tools": {
                    "search": {"hash": old_hash, "approved_by": "auto"},
                    "create_page": {"hash": another_hash, "approved_by": "auto"},
                },
            }
        }
        event, results = compare_server("notion-mcp", "1.0", [another_tool], registry)
        assert event == "tool_removed"
        removed = [r for r in results if r.tool_name == "search"]
        assert len(removed) == 1
        assert removed[0].action == "tool_removed"
        assert any(f.pattern == "tool-removed" for f in removed[0].findings)
