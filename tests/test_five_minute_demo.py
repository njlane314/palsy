from __future__ import annotations

from examples.five_minute_demo import run_demo


def test_five_minute_demo_denies_malicious_package(tmp_path):
    result = run_demo(tmp_path)

    assert result["decision"] == "deny"
    assert result["max_severity"] == "critical"
    assert "executable .pth startup hook is not allowlisted" in result["reasons"]
    assert (tmp_path / "review-denied.json").is_file()
