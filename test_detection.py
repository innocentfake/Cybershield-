import pandas as pd


def find_suspicious_ips(frame: pd.DataFrame, threshold: int) -> set[str]:
    """Return IPs with at least threshold failed login records."""
    failed = frame[frame["status"].str.lower().isin(
        ["failed", "failure", "login_failed"]
    )]
    counts = failed.groupby("ip_address").size()
    return set(counts[counts >= threshold].index)


def test_repeated_failures_are_flagged():
    frame = pd.DataFrame({
        "ip_address": ["1.2.3.4", "1.2.3.4", "1.2.3.4", "5.6.7.8"],
        "status": ["Failed", "Failed", "Failed", "Failed"],
    })
    assert find_suspicious_ips(frame, 3) == {"1.2.3.4"}


def test_threshold_is_inclusive():
    frame = pd.DataFrame({
        "ip_address": ["1.2.3.4", "1.2.3.4"],
        "status": ["Failed", "Failed"],
    })
    assert find_suspicious_ips(frame, 2) == {"1.2.3.4"}


def test_successes_do_not_count_as_failures():
    frame = pd.DataFrame({
        "ip_address": ["1.2.3.4"] * 4,
        "status": ["Success", "Success", "Failed", "Failed"],
    })
    assert find_suspicious_ips(frame, 3) == set()
