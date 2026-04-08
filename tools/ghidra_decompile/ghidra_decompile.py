from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deepzero.engine.stage import MapTool, StageContext, StageResult
from deepzero.providers.decompiler import run_ghidra_headless


class GhidraDecompile(MapTool):
    # runs ghidra headless analysis with a configurable post-script

    def should_skip(self, ctx: StageContext) -> str | None:
        cached = ctx.sample_dir / "decompiled" / "ghidra_result.json"
        if cached.exists():
            return "decompilation already cached"
        return None

    def process(self, ctx: StageContext) -> StageResult:
        tools_config = ctx.global_config.get("tools", {})
        ghidra_config = tools_config.get("ghidra", {})
        ghidra_dir = ghidra_config.get("install_dir", "")

        if not ghidra_dir:
            return StageResult(status="failed", error="ghidra install_dir not configured")

        ghidra_path = Path(ghidra_dir)
        if not ghidra_path.exists():
            return StageResult(status="failed", error=f"ghidra not found: {ghidra_dir}")

        strategy = ctx.config.get("strategy", "")
        if not strategy:
            return StageResult(status="failed", error="no strategy script configured")

        script_path = self._resolve_script(strategy)
        timeout = ctx.config.get("timeout", 300)
        java_home = ghidra_config.get("java_home", "")
        output_dir = ctx.sample_dir / "decompiled"

        extra_env: dict[str, str] = {}
        max_functions = ctx.config.get("max_functions")
        if max_functions is not None:
            extra_env["DEEPZERO_MAX_FUNCTIONS"] = str(max_functions)
        max_depth = ctx.config.get("max_depth")
        if max_depth is not None:
            extra_env["DEEPZERO_MAX_DEPTH"] = str(max_depth)

        result = run_ghidra_headless(
            binary_path=ctx.sample_path,
            output_dir=output_dir,
            ghidra_install_dir=ghidra_path,
            post_script=script_path,
            timeout=timeout,
            java_home=java_home,
            extra_env=extra_env if extra_env else None,
        )

        if not result.get("success", False):
            return StageResult(status="failed", error=result.get("error", "ghidra analysis failed"))

        data: dict[str, Any] = {}
        for key in ("device_name", "symbolic_link", "dispatch_name", "function_count"):
            if key in result:
                data[key] = result[key]

        artifacts = {"ghidra_result": "decompiled/ghidra_result.json"}
        dispatch_file = output_dir / "dispatch_ioctl.c"
        if dispatch_file.exists():
            artifacts["dispatch_ioctl"] = "decompiled/dispatch_ioctl.c"

        return StageResult(status="completed", verdict="continue", artifacts=artifacts, data=data)

    def _resolve_script(self, strategy: str) -> Path:
        tool_script = self.tool_dir / "scripts" / strategy
        if tool_script.exists():
            return tool_script

        abs_path = Path(strategy)
        if abs_path.is_absolute() and abs_path.exists():
            return abs_path

        raise FileNotFoundError(
            f"strategy '{strategy}' not found in {self.tool_dir / 'scripts'}"
        )
