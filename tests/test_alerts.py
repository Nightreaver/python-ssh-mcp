"""services/alerts.evaluate -- threshold evaluation is pure-python; no SSH needed."""
from __future__ import annotations

from ssh_mcp.models.policy import AlertsPolicy
from ssh_mcp.services.alerts import breach_to_dict, evaluate


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
    policy = AlertsPolicy(
        disk_use_percent_max=50, load_avg_1min_max=1.0, mem_free_percent_min=50
    )
    metrics = {
        "disk_entries": [{"mount": "/", "use_percent": "99%"}],
        "load_1min": 5.0,
        "mem_total_kb": 1_000_000,
        "mem_free_kb": 100_000,
    }
    result = evaluate(host="web", policy=policy, **metrics)
    metrics_seen = {b.metric for b in result.breaches}
    assert metrics_seen == {"disk_use_percent", "load_avg_1min", "mem_free_percent"}


def test_breach_to_dict_shape() -> None:
    policy = AlertsPolicy(disk_use_percent_max=50)
    metrics = _ok_metrics()
    metrics["disk_entries"] = [{"mount": "/", "use_percent": "90%"}]
    result = evaluate(host="web", policy=policy, **metrics)
    d = breach_to_dict(result.breaches[0])
    assert set(d) == {"metric", "threshold", "current", "severity", "detail"}
