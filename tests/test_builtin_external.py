from __future__ import annotations

from pathlib import Path

from deepzero.engine.stage import StageContext, StageSpec
from deepzero.engine.state import StageOutput
from deepzero.stages.command import GenericCommand


class TestGenericCommand:
    def _make_ctx(self, tmp_path, config: dict):
        sample_path = tmp_path / "test.sys"
        sample_path.write_bytes(b"hello")
        
        sample_dir = tmp_path / "work" / "abc"
        sample_dir.mkdir(parents=True)
        
        history = {"discover": StageOutput(status="completed", data={"sha256": "abc"})}
        return StageContext(
            sample_path=sample_path,
            sample_dir=sample_dir,
            history=history,
            config=config,
            pipeline_dir=tmp_path,
            global_config={},
            llm=None,
        )

    def test_rendering_and_capture(self, tmp_path, monkeypatch):
        spec = StageSpec(name="cmd", tool="generic_command", config={
            "run": "echo '{filename} is mapped'",
            "stdout_to": "out.txt"
        })
        tool = GenericCommand(spec)
        ctx = self._make_ctx(tmp_path, spec.config)
        
        # mock subprocess
        import subprocess
        class MockResult:
            returncode = 0
            stdout = b"test.sys is mapped\n"
            stderr = b""
            
        def mock_run(*args, **kwargs):
            return MockResult()
            
        monkeypatch.setattr(subprocess, "run", mock_run)
        
        result = tool.process(ctx)
        assert result.verdict == "continue"
        assert (ctx.sample_dir / "out.txt").read_text() == "test.sys is mapped\n"
        assert result.data["command_exit_code"] == 0

    def test_command_failure(self, tmp_path, monkeypatch):
        spec = StageSpec(name="cmd", tool="generic_command", config={
            "run": "false"
        })
        tool = GenericCommand(spec)
        ctx = self._make_ctx(tmp_path, spec.config)
        
        # mock subprocess
        import subprocess
        class MockResult:
            returncode = 1
            stdout = b""
            stderr = b"command not found"
            
        def mock_run(*args, **kwargs):
            return MockResult()
            
        monkeypatch.setattr(subprocess, "run", mock_run)
        
        result = tool.process(ctx)
        assert result.status == "failed"
        assert result.error is not None
