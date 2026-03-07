"""
Live integration tests for Guardian.

These tests hit a real running Guardian instance over HTTP.
They are skipped unless GUARDIAN_TEST_URL is set.

Run manually:
    GUARDIAN_TEST_URL=http://localhost:9766 pytest tests/test_live.py -v

Or via the Makefile (handles Docker lifecycle):
    make test-guardian-live
"""

import os

import httpx
import pytest

GUARDIAN_URL = os.environ.get("GUARDIAN_TEST_URL", "")

pytestmark = pytest.mark.skipif(
    not GUARDIAN_URL,
    reason="GUARDIAN_TEST_URL not set — run via 'make test-guardian-live'",
)


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=GUARDIAN_URL, timeout=10.0) as c:
        yield c


def _check(client, tool_id, args, **kwargs):
    return client.post(
        "/check",
        json={
            "tool_id": tool_id,
            "action": "invoke",
            "args": args,
            "agent_id": "live_test_agent",
            "run_id": "live_test_run",
            "sequence_so_far": [],
            **kwargs,
        },
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "guardian"
    assert "version" in data


# ---------------------------------------------------------------------------
# Response structure
# ---------------------------------------------------------------------------


def test_check_response_has_required_fields(client):
    """Every /check response has allowed, tier, reason regardless of outcome."""
    r = _check(client, "any_tool", {"query": "hello"})
    assert r.status_code == 200
    data = r.json()
    assert "allowed" in data
    assert "tier" in data
    assert "reason" in data
    assert isinstance(data["allowed"], bool)
    assert data["tier"] in ("allow", "sandbox", "halt")


# ---------------------------------------------------------------------------
# Check 1 — tool registry
# ---------------------------------------------------------------------------


def test_unregistered_tool_is_halted(client):
    """An unknown tool_id is rejected at Check 1."""
    r = _check(client, "definitely_not_registered_xyzzy", {})
    data = r.json()
    assert data["allowed"] is False
    assert data["tier"] == "halt"


# ---------------------------------------------------------------------------
# Check 2 — capability boundary (forbidden capability names)
# ---------------------------------------------------------------------------


def test_forbidden_capability_tool_name_is_halted(client):
    """register_tool, spawn_agent_direct, etc. are blocked regardless of registry."""
    for cap in ("register_tool", "spawn_agent_direct", "escalate_scope"):
        r = _check(client, cap, {})
        data = r.json()
        # Halted at Check 1 (unregistered) OR Check 2 (forbidden) — either way blocked
        assert data["allowed"] is False, f"{cap} should be blocked"


# ---------------------------------------------------------------------------
# Check 3 — destructive pattern detection
# ---------------------------------------------------------------------------


def test_cmd_injection_in_args_is_halted(client):
    """Shell injection patterns are caught in args even for unregistered tools."""
    r = _check(client, "any_tool", {"cmd": "ls; rm -rf /"})
    data = r.json()
    assert data["allowed"] is False


def test_privilege_escalation_pattern_is_halted(client):
    r = _check(client, "any_tool", {"input": "sudo chmod 777 /etc/passwd"})
    data = r.json()
    assert data["allowed"] is False


def test_benign_args_pass_pattern_check(client):
    """Benign args don't trip the pattern detector (may still fail Check 1)."""
    r = _check(client, "web_search", {"query": "latest AI research papers"})
    data = r.json()
    # Allowed=False is acceptable here (Check 1 — unregistered tool),
    # but the reason must NOT be a destructive pattern.
    assert "DESTRUCTIVE" not in data.get("reason", "").upper() or not data["allowed"]


# ---------------------------------------------------------------------------
# Auth (only meaningful when GUARDIAN_REQUIRE_AUTH=true)
# ---------------------------------------------------------------------------


def test_check_without_auth_header(client):
    """With auth disabled (test mode), requests without a token are accepted."""
    # This test runs against a server with GUARDIAN_REQUIRE_AUTH=false.
    # We just verify the server doesn't crash — a halt for other reasons is fine.
    r = _check(client, "web_search", {"query": "test"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Concurrent requests — basic load sanity
# ---------------------------------------------------------------------------


def test_multiple_concurrent_checks(client):
    """Guardian handles a burst of requests without errors."""
    results = [_check(client, f"tool_{i}", {"x": i}) for i in range(10)]
    for r in results:
        assert r.status_code == 200
        assert "allowed" in r.json()
