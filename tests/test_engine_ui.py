from deepzero.engine.ui import PipelineDashboard, StageState


def test_pipeline_dashboard():
    dash = PipelineDashboard(["s1", "s2"])
    assert dash._stage_order == ["s1", "s2"]

    # Check default states
    assert dash._stages["s1"].state == StageState.PENDING
    assert dash._stages["s1"].is_ingest is True
    assert dash._stages["s2"].state == StageState.PENDING
    assert dash._stages["s2"].is_ingest is False

    # Start a stage
    dash.stage_start("s1", input_count=10)
    assert dash._stages["s1"].state == StageState.RUNNING
    assert dash._stages["s1"].input_count == 10
    assert dash._active_stage == "s1"

    # Progress
    assert dash._progress_task_id is not None
    dash.stage_update("s1", advance=2)
    # The progress object should have advanced, won't assert rich internals heavily

    # Done
    dash.stage_done("s1", passed=5, filtered=3, failed=2, elapsed_s=1.5)
    assert dash._stages["s1"].state == StageState.DONE
    assert dash._stages["s1"].passed == 5
    assert dash._stages["s1"].filtered == 3
    assert dash._stages["s1"].failed == 2
    assert dash._stages["s1"].elapsed_s == 1.5
    assert dash._active_stage is None

    # Skip
    dash.stage_skip("s2")
    assert dash._stages["s2"].state == StageState.SKIPPED

    # Renderable generation shouldn't crash
    renderable = dash._build_renderable()
    assert renderable is not None
