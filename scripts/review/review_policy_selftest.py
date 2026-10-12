"""Offline regression tests for review budget and deduplication invariants."""

from review_policy import ReviewKey, ReviewLedger, ReviewRequest


def request(pr, sha, provider, stage="draft", risk="normal", purpose="correctness"):
    return ReviewRequest(ReviewKey(pr, sha, provider), stage, risk, purpose)


def assert_rejected(ledger, review, reason, **kwargs):
    allowed, actual = ledger.eligibility(review, **kwargs)
    assert not allowed, (allowed, actual)
    assert actual == reason, (actual, reason)


def main():
    common = dict(
        current_head="a" * 40,
        quota_available=True,
        coherent_batch=True,
        deterministic_checks_done=True,
        blocking_comment_pending=False,
        writer_active=False,
        provider_active=False,
    )

    ledger = ReviewLedger()
    first = request(463, "a" * 40, "coderabbit")
    assert ledger.eligibility(first, **common) == (True, "eligible")
    ledger.start(first)
    assert_rejected(ledger, first, "duplicate-key", **common)
    assert_rejected(ledger, request(462, "a" * 40, "amazon-q"), "global-concurrency-limit", **common)
    assert ledger.finish(first.key, "a" * 40, "completed")
    assert_rejected(ledger, first, "duplicate-key", **common)

    high = ReviewLedger()
    first_high = request(462, "b" * 40, "coderabbit", risk="protocol", purpose="bounds")
    second_high = request(462, "b" * 40, "amazon-q", risk="protocol", purpose="interop")
    high.start(first_high)
    assert high.finish(first_high.key, "b" * 40, "completed")
    assert high.eligibility(second_high, current_head="b" * 40, **{k: v for k, v in common.items() if k != "current_head"}) == (True, "eligible")
    high.start(second_high)
    assert high.finish(second_high.key, "b" * 40, "unavailable")
    assert_rejected(
        high,
        request(462, "b" * 40, "amazon-q", risk="protocol", purpose="bounds"),
        "duplicate-purpose",
        current_head="b" * 40,
        **{k: v for k, v in common.items() if k != "current_head"},
    )

    unknown_quota = ReviewLedger()
    assert_rejected(
        unknown_quota,
        request(463, "c" * 40, "coderabbit"),
        "quota-unavailable",
        current_head="c" * 40,
        quota_available=None,
        coherent_batch=True,
        deterministic_checks_done=True,
        blocking_comment_pending=False,
        writer_active=False,
        provider_active=False,
    )

    stale = ReviewLedger()
    stale_request = request(463, "d" * 40, "coderabbit")
    stale.start(stale_request)
    assert not stale.finish(stale_request.key, "e" * 40, "completed")
    assert stale_request.key in stale.active

    ready = ReviewLedger()
    final = request(463, "f" * 40, "copilot", stage="ready")
    assert ready.eligibility(final, current_head="f" * 40, **{k: v for k, v in common.items() if k != "current_head"}) == (True, "eligible")
    ready.start(final)
    assert ready.finish(final.key, "f" * 40, "completed")
    assert_rejected(
        ready,
        request(463, "1" * 40, "copilot", stage="ready"),
        "ready-budget-exhausted",
        current_head="1" * 40,
        **{k: v for k, v in common.items() if k != "current_head"},
    )
    assert_rejected(
        ready,
        request(463, "f" * 40, "copilot"),
        "provider-not-allowlisted-for-draft",
        current_head="f" * 40,
        **{k: v for k, v in common.items() if k != "current_head"},
    )

    print("review policy self-test: PASS")


if __name__ == "__main__":
    main()
