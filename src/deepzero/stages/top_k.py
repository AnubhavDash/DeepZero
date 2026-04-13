from __future__ import annotations

from typing import Any

from deepzero.engine.stage import ReduceTool
from deepzero.engine.state import SampleState


class TopKSelector(ReduceTool):
    # sorts all active samples by a metric in their history and keeps only the top k

    def reduce(self, states: list[SampleState], config: dict[str, Any]) -> list[SampleState]:
        metric_path = config.get("metric_path", "")
        keep_top = config.get("keep_top", 10)
        sort_order = config.get("sort_order", "desc")

        if not metric_path:
            self.log.warning("no metric_path configured, passing all samples through")
            return states

        # parse "stage_name.key" into lookup components
        parts = metric_path.split(".", 1)
        if len(parts) != 2:
            self.log.warning("metric_path must be 'stage_name.key', got '%s'", metric_path)
            return states

        stage_name, data_key = parts

        def _get_metric(s: SampleState) -> float:
            output = s.history.get(stage_name)
            if output is None:
                return 0.0
            val = output.data.get(data_key, 0)
            try:
                return float(val)
            except (TypeError, ValueError):
                return 0.0

        # sort by metric
        reverse = sort_order == "desc"
        states.sort(key=_get_metric, reverse=reverse)

        # mark losers as skipped
        if len(states) > keep_top:
            dropped = 0
            for state in states[keep_top:]:
                if state.is_active():
                    state.mark_stage_skipped(
                        self.spec.name,
                        f"outside top {keep_top} by {metric_path}",
                    )
                    dropped += 1
            self.log.info(
                "top_k: kept %d, dropped %d (metric: %s, order: %s)",
                min(keep_top, len(states)), dropped, metric_path, sort_order,
            )

        return states
