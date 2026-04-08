from __future__ import annotations

import textwrap

import pytest

class TestPipelineLoading:
    def _write_pipeline(self, tmp_path, yaml_content: str, tool_code: str | None = None):
        pipeline_dir = tmp_path / "pipelines" / "test"
        pipeline_dir.mkdir(parents=True)
        (pipeline_dir / "pipeline.yaml").write_text(textwrap.dedent(yaml_content), encoding="utf-8")

        if tool_code:
            tool_dir = tmp_path / "tools" / "test_ingest"
            tool_dir.mkdir(parents=True)
            (tool_dir / "test_ingest.py").write_text(textwrap.dedent(tool_code), encoding="utf-8")

        return pipeline_dir

    def _ingest_code(self):
        return """
            from pathlib import Path
            from typing import Any
            from deepzero.engine.stage import IngestTool, Sample
            class TestIngest(IngestTool):
                def discover(self, target: Path, config: dict[str, Any], global_config: dict[str, Any]) -> list[Sample]:
                    return [Sample(sample_id="s1", source_path=target, filename="test.sys")]
        """

    def test_load_valid_pipeline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        self._write_pipeline(tmp_path, """
            name: test
            stages:
              - name: discover
                tool: test_ingest/test_ingest.py
              - name: filter
                tool: metadata_filter
        """, self._ingest_code())

        pipeline = load_pipeline(str(tmp_path / "pipelines" / "test"))
        assert pipeline.name == "test"
        assert len(pipeline.stage_specs) == 2
        assert pipeline.ingest_tool is not None

    def test_duplicate_stage_name_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        self._write_pipeline(tmp_path, """
            name: test
            stages:
              - name: discover
                tool: test_ingest/test_ingest.py
              - name: discover
                tool: metadata_filter
        """, self._ingest_code())

        with pytest.raises(ValueError, match="duplicate stage name"):
            load_pipeline(str(tmp_path / "pipelines" / "test"))

    def test_non_ingest_first_stage_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        self._write_pipeline(tmp_path, """
            name: test
            stages:
              - name: filter
                tool: metadata_filter
        """)

        with pytest.raises(ValueError, match="must be an IngestTool"):
            load_pipeline(str(tmp_path / "pipelines" / "test"))

    def test_env_var_expansion(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        monkeypatch.setenv("TEST_MODEL", "gpt-4")
        self._write_pipeline(tmp_path, """
            name: test
            model: ${TEST_MODEL}
            stages:
              - name: discover
                tool: test_ingest/test_ingest.py
        """, self._ingest_code())

        pipeline = load_pipeline(str(tmp_path / "pipelines" / "test"))
        assert pipeline.model == "gpt-4"

    def test_work_dir_namespaced_by_pipeline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        self._write_pipeline(tmp_path, """
            name: my_pipeline
            settings:
              work_dir: work
            stages:
              - name: discover
                tool: test_ingest/test_ingest.py
        """, self._ingest_code())

        pipeline = load_pipeline(str(tmp_path / "pipelines" / "test"))
        assert pipeline.work_dir.name == "my_pipeline"

    def test_reduce_tool_accepted_after_ingest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from deepzero.engine.pipeline import load_pipeline
        self._write_pipeline(tmp_path, """
            name: test
            stages:
              - name: discover
                tool: test_ingest/test_ingest.py
              - name: rank
                tool: top_k
                config:
                  metric_path: "discover.size_bytes"
                  keep_top: 5
        """, self._ingest_code())

        pipeline = load_pipeline(str(tmp_path / "pipelines" / "test"))
        assert len(pipeline.stages) == 1
        from deepzero.engine.stage import ReduceTool
        assert isinstance(pipeline.stages[0][1], ReduceTool)
