from __future__ import annotations

from pathlib import Path

# -- metadata filter (builtin map tool) --

class TestMetadataFilter:
    def _make_ctx(self, data: dict, config: dict):
        from deepzero.engine.stage import StageContext
        from deepzero.engine.state import StageOutput
        history = {"discover": StageOutput(status="completed", data=data)}
        return StageContext(
            sample_path=Path("test.sys"),
            sample_dir=Path("work/test"),
            history=history,
            config=config,
            pipeline_dir=Path("."),
            global_config={},
            llm=None,
        )

    def _make_filter(self, config: dict | None = None):
        from deepzero.engine.stage import StageSpec
        from deepzero.stages.filter import MetadataFilter
        spec = StageSpec(name="test_filter", tool="metadata_filter", config=config or {})
        return MetadataFilter(spec)

    def test_passes_when_requirements_met(self):
        f = self._make_filter({"require": {"is_kernel_driver": True}})
        ctx = self._make_ctx({"is_kernel_driver": True}, {"require": {"is_kernel_driver": True}})
        result = f.process(ctx)
        assert result.verdict == "continue"

    def test_skips_when_requirement_not_met(self):
        f = self._make_filter()
        ctx = self._make_ctx({"is_kernel_driver": False}, {"require": {"is_kernel_driver": True}})
        result = f.process(ctx)
        assert result.verdict == "skip"

    def test_min_threshold(self):
        f = self._make_filter()
        ctx = self._make_ctx({"priority_score": 2.0}, {"min_priority_score": 5.0})
        result = f.process(ctx)
        assert result.verdict == "skip"

    def test_max_threshold(self):
        f = self._make_filter()
        ctx = self._make_ctx({"size_bytes": 50000}, {"max_size_bytes": 10000})
        result = f.process(ctx)
        assert result.verdict == "skip"

    def test_dedup_first_pass(self):
        f = self._make_filter()
        ctx = self._make_ctx({"sha256": "abc123"}, {"dedup_field": "sha256"})
        result = f.process(ctx)
        assert result.verdict == "continue"

    def test_dedup_second_pass_skips(self):
        f = self._make_filter()
        ctx1 = self._make_ctx({"sha256": "abc123"}, {"dedup_field": "sha256"})
        ctx2 = self._make_ctx({"sha256": "abc123"}, {"dedup_field": "sha256"})
        f.process(ctx1)
        result = f.process(ctx2)
        assert result.verdict == "skip"
        assert "duplicate" in result.data.get("reject_reason", "")


# -- hash exclude (builtin map tool) --

class TestHashExclude:
    def _make_ctx(self, data: dict, config: dict):
        from deepzero.engine.stage import StageContext
        from deepzero.engine.state import StageOutput
        history = {"discover": StageOutput(status="completed", data=data)}
        return StageContext(
            sample_path=Path("test.sys"),
            sample_dir=Path("work/test"),
            history=history,
            config=config,
            pipeline_dir=Path("."),
            global_config={},
            llm=None,
        )

    def test_inline_hashes_exclude(self):
        from deepzero.engine.stage import StageSpec
        from deepzero.stages.hash_filter import HashExclude
        spec = StageSpec(name="hash_test", tool="hash_exclude", config={"hashes": ["ABCD1234"]})
        f = HashExclude(spec)
        f.setup({})
        ctx = self._make_ctx({"sha256": "abcd1234"}, {"hash_field": "sha256"})
        result = f.process(ctx)
        assert result.verdict == "skip"

    def test_hash_not_in_list_passes(self):
        from deepzero.engine.stage import StageSpec
        from deepzero.stages.hash_filter import HashExclude
        spec = StageSpec(name="hash_test", tool="hash_exclude", config={"hashes": ["ABCD1234"]})
        f = HashExclude(spec)
        f.setup({})
        ctx = self._make_ctx({"sha256": "ffffff"}, {"hash_field": "sha256"})
        result = f.process(ctx)
        assert result.verdict == "continue"


# -- top-k selector (builtin reduce tool) --

class TestTopKSelector:
    def test_keeps_top_k(self):
        from deepzero.engine.stage import StageSpec
        from deepzero.engine.state import SampleState
        from deepzero.stages.top_k import TopKSelector

        spec = StageSpec(name="pick", tool="top_k", config={})
        tool = TopKSelector(spec)

        states = []
        for i in range(5):
            s = SampleState(sample_id=f"s{i}", filename=f"s{i}.sys", verdict="active")
            s.mark_stage_completed("scan", data={"finding_count": i})
            s.verdict = "active"
            states.append(s)

        config = {"metric_path": "scan.finding_count", "keep_top": 2, "sort_order": "desc"}
        result = tool.reduce(states, config)

        active = [s for s in result if s.is_active()]
        skipped = [s for s in result if s.verdict == "skipped"]
        assert len(active) == 2
        assert len(skipped) == 3
        # top 2 should be s4 and s3 (highest finding_count)
        active_ids = {s.sample_id for s in active}
        assert "s4" in active_ids
        assert "s3" in active_ids

    def test_passthrough_without_metric(self):
        from deepzero.engine.stage import StageSpec
        from deepzero.engine.state import SampleState
        from deepzero.stages.top_k import TopKSelector

        spec = StageSpec(name="pick", tool="top_k", config={})
        tool = TopKSelector(spec)
        states = [SampleState(sample_id="s0", filename="s0.sys", verdict="active")]

        result = tool.reduce(states, {})
        assert len(result) == 1
        assert result[0].is_active()
