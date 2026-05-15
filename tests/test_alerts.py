"""services/alerts.evaluate -- threshold evaluation is pure-python; no SSH needed."""

from __future__ import annotations

import pytest

from ssh_mcp.models.policy import AlertsPolicy
from ssh_mcp.services.alerts import evaluate


def _ok_metrics() -> dict:
    return {
        "disk_entries": [{"mount": "/", "use_percent": "42%"}],
        "load_1min": 0.3,
        "mem_total_kb": 1_000_000,
        "mem_free_kb": 600_000,
    }


def test_no_thresholds_yields_no_breaches() -> None:
    policy = AlertsPolicy()
    result = evaluate(host="web", policy=policy, **_ok_metrics())
    assert result.breaches == []


def test_disk_breach_fires_above_threshold() -> None:
    policy = AlertsPolicy(disk_use_percent_max=50)
    metrics = _ok_metrics()
    metrics["disk_entries"] = [
        {"mount": "/", "use_percent": "30%"},
        {"mount": "/var", "use_percent": "80%"},
    ]
    result = evaluate(host="web", policy=policy, **metrics)
    assert len(result.breaches) == 1
    b = result.breaches[0]
    assert b.metric == "disk_use_percent"
    assert b.current == 80
    assert b.threshold == 50
    assert "mount=/var" in b.detail


def test_disk_respects_mount_scope_filter() -> None:
    # Only /var is scoped; / over 50% doesn't count.
    policy = AlertsPolicy(disk_use_percent_max=50, disk_mounts=["/var"])
    metrics = _ok_metrics()
    metrics["disk_entries"] = [
        {"mount": "/", "use_percent": "90%"},
        {"mount": "/var", "use_percent": "70%"},
    ]
    result = evaluate(host="web", policy=policy, **metrics)
    assert len(result.breaches) == 1
    assert "/var" in result.breaches[0].detail


def test_load_avg_breach() -> None:
    policy = AlertsPolicy(load_avg_1min_max=1.0)
    metrics = _ok_metrics()
    metrics["load_1min"] = 3.4
    result = evaluate(host="web", policy=policy, **metrics)
    assert len(result.breaches) == 1
    assert result.breaches[0].metric == "load_avg_1min"
    assert result.breaches[0].current == 3.4


def test_mem_free_percent_breach() -> None:
    # 50k free of 1M total = 5% free, below 10% threshold.
    policy = AlertsPolicy(mem_free_percent_min=10)
    metrics = _ok_metrics()
    metrics["mem_free_kb"] = 50_000
    result = evaluate(host="web", policy=policy, **metrics)
    assert len(result.breaches) == 1
    assert result.breaches[0].metric == "mem_free_percent"
    assert result.breaches[0].current == 5.0


def test_missing_metric_is_silently_skipped() -> None:
    # No load average available (non-Linux host); the configured threshold
    # simply doesn't evaluate rather than erroring.
    policy = AlertsPolicy(load_avg_1min_max=1.0)
    metrics = _ok_metrics()
    metrics["load_1min"] = None
    result = evaluate(host="web", policy=policy, **metrics)
    assert result.breaches == []


def test_multiple_simultaneous_breaches() -> None:
    policy = AlertsPolicy(disk_use_percent_max=50, load_avg_1min_max=1.0, mem_free_percent_min=50)
    metrics = {
        "disk_entries": [{"mount": "/", "use_percent": "99%"}],
        "load_1min": 5.0,
        "mem_total_kb": 1_000_000,
        "mem_free_kb": 100_000,
    }
    result = evaluate(host="web", policy=policy, **metrics)
    metrics_seen = {b.metric for b in result.breaches}
    assert metrics_seen == {"disk_use_percent", "load_avg_1min", "mem_free_percent"}


# Sprint 5: HostAlertsResult / AlertBreach models replace the dict
# response from `ssh_host_alerts` with typed Pydantic models. Pin the
# field shape and `extra="forbid"` config so a future refactor that
# adds a key to the evaluator output can't silently drift the schema.


def test_host_alerts_result_model_shape() -> None:
    from ssh_mcp.models.results import AlertBreach, HostAlertsResult

    breach = AlertBreach(
        metric="disk_use_percent",
        threshold=50.0,
        current=90.0,
        severity="warning",
        detail="mount=/var",
    )
    result = HostAlertsResult(
        host="web01",
        breaches=[breach],
        metrics={
            "disk_entries": [{"mount": "/", "use_percent": 42.0}],
            "load_avg_1min": 0.3,
            "mem_free_percent": 60.0,
        },
    )
    assert result.host == "web01"
    assert len(result.breaches) == 1
    assert result.breaches[0].metric == "disk_use_percent"
    assert result.breaches[0].current == 90.0
    assert result.metrics["load_avg_1min"] == 0.3


def test_host_alerts_result_forbids_extra_fields() -> None:
    """ConfigDict(extra="forbid") catches typos at construction time
    rather than letting them propagate through the audit log -- pinned
    by INC-046 / ADR-0025."""
    from pydantic import ValidationError

    from ssh_mcp.models.results import HostAlertsResult

    with pytest.raises(ValidationError):
        HostAlertsResult(
            host="h",
            breaches=[],
            metrics={},
            unknown_field="oops",  # type: ignore[call-arg]
        )


def test_alert_breach_forbids_extra_fields() -> None:
    from pydantic import ValidationError

    from ssh_mcp.models.results import AlertBreach

    with pytest.raises(ValidationError):
        AlertBreach(
            metric="x",
            threshold=1.0,
            current=2.0,
            severity="warning",
            detail="",
            unknown="oops",  # type: ignore[call-arg]
        )
