from __future__ import annotations

import hashlib

from deepzero.engine.stage import StageSpec
from deepzero.stages.ingest import FileDiscovery


class TestFileDiscovery:
    def _make_tool(self):
        spec = StageSpec(name="discover", tool="file_discovery")
        return FileDiscovery(spec)

    def test_discover_single_file(self, tmp_path):
        tool = self._make_tool()
        target = tmp_path / "test.sys"
        target.write_bytes(b"hello world")
        
        samples = tool.discover(target, {}, {})
        assert len(samples) == 1
        assert samples[0].filename == "test.sys"
        assert samples[0].data["size_bytes"] == 11
        
        expected_sha256 = hashlib.sha256(b"hello world").hexdigest()
        assert samples[0].data["sha256"] == expected_sha256
        assert samples[0].sample_id == expected_sha256[:16]

    def test_discover_directory_recursive(self, tmp_path):
        tool = self._make_tool()
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        
        (tmp_path / "root.sys").write_bytes(b"1")
        (tmp_path / "a" / "mid.sys").write_bytes(b"2")
        (tmp_path / "a" / "b" / "deep.txt").write_bytes(b"3")
        
        samples = tool.discover(tmp_path, {"recursive": True}, {})
        assert len(samples) == 3

    def test_discover_directory_non_recursive(self, tmp_path):
        tool = self._make_tool()
        (tmp_path / "a").mkdir()
        
        (tmp_path / "root.sys").write_bytes(b"1")
        (tmp_path / "a" / "mid.sys").write_bytes(b"2")
        
        samples = tool.discover(tmp_path, {"recursive": False}, {})
        assert len(samples) == 1
        assert samples[0].filename == "root.sys"

    def test_discover_with_extensions(self, tmp_path):
        tool = self._make_tool()
        (tmp_path / "driver.sys").write_bytes(b"sys")
        (tmp_path / "app.exe").write_bytes(b"exe")
        (tmp_path / "readme.txt").write_bytes(b"txt")
        
        samples = tool.discover(tmp_path, {"extensions": [".sys", "exe"]}, {})
        assert len(samples) == 2
        names = {s.filename for s in samples}
        assert "driver.sys" in names
        assert "app.exe" in names

    def test_discover_missing_target(self, tmp_path):
        tool = self._make_tool()
        samples = tool.discover(tmp_path / "nope", {}, {})
        assert len(samples) == 0
