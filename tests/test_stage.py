from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


# -- fixtures --

@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tools").mkdir()
    return tmp_path


@pytest.fixture
def make_tool(tmp_path):
    def _make(dir_name: str, file_name: str, code: str):
        tool_dir = tmp_path / "tools" / dir_name
        tool_dir.mkdir(parents=True, exist_ok=True)
        tool_file = tool_dir / file_name
        tool_file.write_text(textwrap.dedent(code), encoding="utf-8")
        return tool_file
    return _make


@pytest.fixture(autouse=True)
def _register_builtins():
    import deepzero.stages  # noqa: F401


# -- tool resolution --

class TestToolResolution:
    def test_builtin_resolves_by_bare_name(self):
        from deepzero.engine.stage import resolve_tool_class
        cls = resolve_tool_class("metadata_filter")
        assert cls.__name__ == "MetadataFilter"

    def test_all_builtins_resolvable(self):
        from deepzero.engine.stage import resolve_tool_class
        expected = ["file_discovery", "metadata_filter", "hash_exclude", "generic_llm", "generic_command", "semgrep_scanner", "top_k"]
        for name in expected:
            cls = resolve_tool_class(name)
            assert cls is not None, f"built-in '{name}' not found"

    def test_unknown_bare_name_fails(self):
        from deepzero.engine.stage import resolve_tool_class
        with pytest.raises(ValueError, match="bare names only match built-in"):
            resolve_tool_class("nonexistent_tool")

    def test_slash_path_resolves_tool_file(self, make_tool):
        from deepzero.engine.stage import resolve_tool_class, MapTool
        make_tool("my_filter", "my_filter.py", """
            from deepzero.engine.stage import MapTool, StageContext, StageResult
            class MyFilter(MapTool):
                def process(self, ctx: StageContext) -> StageResult:
                    return StageResult(status="completed", verdict="continue")
        """)
        cls = resolve_tool_class("my_filter/my_filter.py")
        assert issubclass(cls, MapTool)
        assert cls.__name__ == "MyFilter"

    def test_slash_path_with_explicit_class(self, make_tool):
        from deepzero.engine.stage import resolve_tool_class
        make_tool("multi", "multi.py", """
            from deepzero.engine.stage import MapTool, BatchTool, StageContext, StageResult, BatchEntry
            class ToolA(MapTool):
                def process(self, ctx): return StageResult(status="completed")
            class ToolB(BatchTool):
                def execute_batch(self, entries, config): return [StageResult(status="completed")]
        """)
        cls = resolve_tool_class("multi/multi.py:ToolB")
        assert cls.__name__ == "ToolB"

    def test_slash_path_missing_file_fails(self):
        from deepzero.engine.stage import resolve_tool_class
        with pytest.raises(FileNotFoundError):
            resolve_tool_class("does_not_exist/nope.py")

    def test_source_file_set_on_resolve(self, make_tool):
        from deepzero.engine.stage import resolve_tool_class
        make_tool("src_test", "src_test.py", """
            from deepzero.engine.stage import MapTool, StageContext, StageResult
            class SrcTest(MapTool):
                def process(self, ctx): return StageResult(status="completed")
        """)
        cls = resolve_tool_class("src_test/src_test.py")
        assert cls._source_file is not None
        assert cls._source_file.name == "src_test.py"


# -- tool base class --

class TestToolBaseClass:
    def _make_spec(self, name="test_tool"):
        from deepzero.engine.stage import StageSpec
        return StageSpec(name=name, tool="metadata_filter")

    def test_log_scoped_to_tool_name(self):
        from deepzero.engine.stage import resolve_tool_class
        cls = resolve_tool_class("metadata_filter")
        instance = cls(self._make_spec("my_stage"))
        assert instance.log.name == "deepzero.tool.my_stage"

    def test_cache_dir_created(self, tmp_path):
        from deepzero.engine.stage import resolve_tool_class
        cls = resolve_tool_class("metadata_filter")
        instance = cls(self._make_spec("cache_test"))
        cache = instance.cache_dir
        assert cache.exists()
        assert cache.name == "cache_test"

    def test_cache_dir_isolated_per_tool(self, tmp_path):
        from deepzero.engine.stage import resolve_tool_class
        cls = resolve_tool_class("metadata_filter")
        a = cls(self._make_spec("tool_a"))
        b = cls(self._make_spec("tool_b"))
        assert a.cache_dir != b.cache_dir

    def test_setup_and_teardown_callable(self):
        from deepzero.engine.stage import resolve_tool_class
        cls = resolve_tool_class("metadata_filter")
        instance = cls(self._make_spec())
        instance.setup({})
        instance.teardown()


# -- tool types --

class TestToolTypes:
    def test_map_tool_type(self):
        from deepzero.engine.stage import ToolType
        from deepzero.stages.filter import MetadataFilter
        assert MetadataFilter.tool_type == ToolType.MAP

    def test_ingest_tool_type(self):
        from deepzero.engine.stage import ToolType
        from deepzero.stages.ingest import FileDiscovery
        assert FileDiscovery.tool_type == ToolType.INGEST

    def test_batch_tool_type(self):
        from deepzero.engine.stage import ToolType
        from deepzero.stages.semgrep_scanner import SemgrepScannerTool
        assert SemgrepScannerTool.tool_type == ToolType.BATCH

    def test_reduce_tool_type(self):
        from deepzero.engine.stage import ToolType
        from deepzero.stages.top_k import TopKSelector
        assert TopKSelector.tool_type == ToolType.REDUCE


# -- data classes --

class TestDataClasses:
    def test_sample_creation(self):
        from deepzero.engine.stage import Sample
        s = Sample(sample_id="abc", source_path=Path("test.sys"), filename="test.sys")
        assert s.sample_id == "abc"
        assert s.data == {}

    def test_stage_result_defaults(self):
        from deepzero.engine.stage import StageResult
        r = StageResult(status="completed")
        assert r.verdict == "continue"
        assert r.artifacts == {}
        assert r.data == {}
        assert r.error is None

    def test_stage_spec_defaults(self):
        from deepzero.engine.stage import StageSpec, FailurePolicy
        s = StageSpec(name="test", tool="metadata_filter")
        assert s.parallel == 4
        assert s.on_failure == FailurePolicy.SKIP
        assert s.timeout == 0

    def test_stage_context_creation(self):
        from deepzero.engine.stage import StageContext
        from deepzero.engine.state import StageOutput
        ctx = StageContext(
            sample_path=Path("x.sys"),
            sample_dir=Path("work/x"),
            history={"discover": StageOutput(data={"key": "val"})},
            config={"opt": True},
            pipeline_dir=Path("."),
            global_config={},
            llm=None,
        )
        assert ctx.history["discover"].data["key"] == "val"
        assert ctx.config["opt"] is True

    def test_batch_entry_creation(self):
        from deepzero.engine.stage import BatchEntry
        entry = BatchEntry(
            sample_id="abc",
            sample_dir=Path("work/abc"),
            source_path=Path("test.sys"),
            history={},
        )
        assert entry.sample_id == "abc"


# -- tool registry --

class TestToolRegistry:
    def test_register_and_resolve(self):
        from deepzero.engine.stage import register_tool, resolve_tool_class, MapTool, StageContext, StageResult

        class CustomRegistered(MapTool):
            def process(self, ctx: StageContext) -> StageResult:
                return StageResult(status="completed")

        register_tool("_test_custom", CustomRegistered)
        cls = resolve_tool_class("_test_custom")
        assert cls is CustomRegistered

    def test_get_registered_tools(self):
        from deepzero.engine.stage import get_registered_tools
        tools = get_registered_tools()
        assert "metadata_filter" in tools
        assert "hash_exclude" in tools
        assert "top_k" in tools
        assert "semgrep_scanner" in tools
