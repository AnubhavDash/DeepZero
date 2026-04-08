from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("deepzero.api")


def create_app(work_dir: Path):
    """create a starlette asgi app that serves pipeline state over http"""
    try:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError:
        raise ImportError("starlette required for serve mode: pip install deepzero[serve]")

    from deepzero.engine.state import StateStore
    store = StateStore(work_dir)

    async def health(request):
        return JSONResponse({"status": "ok", "work_dir": str(work_dir)})

    async def get_runs(request):
        run_state = store.load_run()
        if run_state is None:
            return JSONResponse({"runs": []})

        from dataclasses import asdict
        return JSONResponse({"runs": [asdict(run_state)]})

    async def get_run(request):
        run_state = store.load_run()
        if run_state is None:
            return JSONResponse({"error": "no run found"}, status_code=404)

        from dataclasses import asdict
        return JSONResponse(asdict(run_state))

    async def get_samples(request):
        samples = store.list_samples()

        # filtering
        verdict = request.query_params.get("verdict")
        stage = request.query_params.get("stage")
        status_filter = request.query_params.get("status")

        results = []
        for s in samples:
            if verdict and s.metadata.get("classification") != verdict:
                continue
            if stage and s.current_stage != stage:
                continue
            if status_filter:
                stage_states = s.stages
                if not any(st.status == status_filter for st in stage_states.values()):
                    continue

            results.append({
                "sample_id": s.sample_id,
                "filename": s.filename,
                "current_stage": s.current_stage,
                "classification": s.metadata.get("classification", ""),
                "verdict": s.verdict,
                "error": s.error,
            })

        return JSONResponse({"samples": results, "total": len(results)})

    async def get_sample(request):
        sample_id = request.path_params["sample_id"]
        state = store.load_sample(sample_id)

        if state is None:
            return JSONResponse({"error": f"sample {sample_id} not found"}, status_code=404)

        from deepzero.engine.state import _sample_to_dict
        return JSONResponse(_sample_to_dict(state))

    async def get_sample_artifact(request):
        sample_id = request.path_params["sample_id"]
        artifact_name = request.path_params["name"]

        sample_dir = store.sample_dir(sample_id)
        state = store.load_sample(sample_id)

        if state is None:
            return JSONResponse({"error": "sample not found"}, status_code=404)

        # find artifact path from state
        for stage_state in state.stages.values():
            for aname, apath in stage_state.artifacts.items():
                if aname == artifact_name:
                    full_path = sample_dir / apath
                    if full_path.exists():
                        content = full_path.read_text(encoding="utf-8", errors="replace")
                        return JSONResponse({"artifact": artifact_name, "content": content})

        return JSONResponse({"error": f"artifact '{artifact_name}' not found"}, status_code=404)

    routes = [
        Route("/api/health", health),
        Route("/api/runs", get_runs),
        Route("/api/run", get_run),
        Route("/api/samples", get_samples),
        Route("/api/samples/{sample_id}", get_sample),
        Route("/api/samples/{sample_id}/artifacts/{name}", get_sample_artifact),
    ]

    return Starlette(routes=routes)
