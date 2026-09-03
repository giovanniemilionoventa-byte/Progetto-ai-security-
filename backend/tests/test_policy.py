from app.engines.policy import PolicyResult, _matches
from app.engines.risk import evaluate as risk_evaluate


def test_glob_match():
    assert _matches("*", "anything")
    assert _matches("/Sales*", "/Sales/Q1")
    assert _matches("external", "external")
    assert not _matches("internal", "external")


def test_risk_transfer_is_critical():
    result = risk_evaluate("payments", "TRANSFER", "any", "external", "BLOCK")
    assert result.score >= 70
    assert result.level in {"high", "critical"}


def test_risk_internal_read_is_low():
    result = risk_evaluate("crm", "READ", "customers", None, "ALLOW")
    assert result.level in {"low", "medium"}
    assert result.score < 45


def test_policy_result_fields():
    r = PolicyResult(decision="BLOCK", reason="denied")
    assert r.decision == "BLOCK"
