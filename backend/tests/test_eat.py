from app.eat import EatError, param_hash, sign_eat, verify_eat
from app.replay import ReplayStore


def _token(**overrides) -> str:
    kwargs = dict(
        org_id="org-1",
        agent_id="agent-1",
        execution_id="exec-1",
        request_id="req-1",
        tool="crm",
        operation="read",
        scope="customers",
        destination=None,
        payload={"id": "c-1"},
        ttl_seconds=10,
        now=1_700_000_000,
        jti="jti-1",
    )
    kwargs.update(overrides)
    return sign_eat(**kwargs)


def test_valid_signature():
    token = _token()
    claims = verify_eat(token, now=1_700_000_000)
    assert claims["iss"] == "enforcement-gateway"
    assert claims["aud"] == "credential-broker"
    assert "secret" not in claims
    assert claims["param_hash"] == param_hash("customers", None, {"id": "c-1"})


def test_invalid_signature():
    token = _token()
    body, _sig = token.split(".", 1)
    try:
        verify_eat(body + ".AAAA", now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "bad_signature"


def test_expired():
    token = _token(ttl_seconds=5)
    try:
        verify_eat(token, now=1_700_000_010)
        assert False
    except EatError as exc:
        assert exc.reason == "expired"


def test_not_before():
    token = _token()
    try:
        verify_eat(token, now=1_699_999_999)
        assert False
    except EatError as exc:
        assert exc.reason == "not_yet_valid"


def test_wrong_issuer_audience():
    from app.eat import sign_claims

    claims = verify_eat(_token(), now=1_700_000_000)
    claims["iss"] = "agent"
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "bad_issuer"
    claims["iss"] = "enforcement-gateway"
    claims["aud"] = "protected-tool"
    try:
        verify_eat(sign_claims(claims), now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "bad_audience"


def test_missing_eat():
    try:
        verify_eat("", now=1_700_000_000)
        assert False
    except EatError as exc:
        assert exc.reason == "missing"


def test_param_hash_differs_on_payload_change():
    a = param_hash("customers", None, {"id": "1"})
    b = param_hash("customers", None, {"id": "2"})
    assert a != b


def test_replay_store_rejects_second_jti():
    store = ReplayStore()
    assert store.consume("jti-1", 9_999_999_999) is True
    assert store.consume("jti-1", 9_999_999_999) is False


def test_eat_contains_no_secret():
    token = _token()
    assert "aegis-internal-crm" not in token
    claims = verify_eat(token, now=1_700_000_000)
    assert "secret" not in claims
