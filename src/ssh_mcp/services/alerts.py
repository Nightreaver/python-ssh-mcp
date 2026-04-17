"""Alert threshold evaluation. Pure functions; no SSH. Fed by ``ssh_host_alerts``."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models.policy import AlertsPolicy


@dataclass(frozen=True)
class Breach:
    metric: str        # "disk_use_percent" / "load_avg_1min" / "mem_free_percent"
    threshold: float   # configured limit
    current: float     # observed value
    severity: str      # "warning" (breach of configured threshold)
    detail: str        # human-readable context (mount path, etc.)


@dataclass
class EvalResult:
    host: str
    breaches: list[Breach] = field(default_factory=list)
    metrics: dict[str, float | list[dict[str, float | str]]] = field(default_factory=dict)


def evaluate(
    host: str,
    policy: AlertsPolicy,
    *,
    disk_entries: list[dict[str, str]],
    load_1min: float | None,
    mem_total_kb: int | None,
    mem_free_kb: int | None,
) -> EvalResult:
    """Compare raw metrics against configured thresholds; return breaches + observations.

    Any raw metric can be None/empty when the probe failed or the platform
    doesn't expose it; it is simply skipped. Thresholds that aren't configured
    are also skipped.
    """
    result = EvalResult(host=host)

    # Disk: one entry per mount. Breach if any mount exceeds the threshold.
    if policy.disk_use_percent_max is not None and disk_entries:
        mounts_observed: list[dict[str, float | str]] = []
        scope = set(policy.disk_mounts) if policy.disk_mounts else None
        for entry in disk_entries:
            mount = entry.get("mount", "")
            raw = entry.get("use_percent", "").rstrip("%")
            if not raw.isdigit():
                continue
            pct = float(raw)
            if scope is not None and mount not in scope:
                continue
            mounts_observed.append({"mount": mount, "use_percent": pct})
            if pct > policy.disk_use_percent_max:
                result.breaches.append(
                    Breach(
                        metric="disk_use_percent",
                        threshold=float(policy.disk_use_percent_max),
                        current=pct,
                        severity="warning",
                        detail=f"mount={mount}",
                    )
                )
        result.metrics["disk_entries"] = mounts_observed

    # Load avg (1 min).
    if policy.load_avg_1min_max is not None and load_1min is not None:
        result.metrics["load_avg_1min"] = load_1min
        if load_1min > policy.load_avg_1min_max:
            result.breaches.append(
                Breach(
                    metric="load_avg_1min",
                    threshold=policy.load_avg_1min_max,
                    current=load_1min,
                    severity="warning",
                    detail="",
                )
            )

    # Memory (free percent).
    if (
        policy.mem_free_percent_min is not None
        and mem_total_kb is not None
        and mem_free_kb is not None
        and mem_total_kb > 0
    ):
        free_pct = (mem_free_kb / mem_total_kb) * 100.0
        result.metrics["mem_free_percent"] = round(free_pct, 2)
        if free_pct < policy.mem_free_percent_min:
            result.breaches.append(
                Breach(
                    metric="mem_free_percent",
                    threshold=float(policy.mem_free_percent_min),
                    current=round(free_pct, 2),
                    severity="warning",
                    detail=f"free={mem_free_kb}kB total={mem_total_kb}kB",
                )
            )

    return result


def breach_to_dict(b: Breach) -> dict[str, str | float]:
    return {
        "metric": b.metric,
        "threshold": b.threshold,
        "current": b.current,
        "severity": b.severity,
        "detail": b.detail,
    }
