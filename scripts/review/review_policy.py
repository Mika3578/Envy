"""Pure policy checks for the controlled AI-review proposal.

This module has no GitHub, provider, network, credential, or dispatch code. It
only models the budget, concurrency, and current-HEAD invariants so they can be
tested offline before any provider is contacted.
"""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple


INTERMEDIATE_PROVIDERS = frozenset(("coderabbit", "amazon-q"))
FINAL_PROVIDER = "copilot"
GLOBAL_ACTIVE_LIMIT = 1


@dataclass(frozen=True)
class ReviewKey:
    pr: int
    head_sha: str
    provider: str


@dataclass(frozen=True)
class ReviewRequest:
    key: ReviewKey
    stage: str
    risk: str
    purpose: str


@dataclass
class ReviewLedger:
    active: FrozenSet[ReviewKey] = frozenset()
    terminal: Dict[ReviewKey, str] = field(default_factory=dict)
    draft_requests: Dict[int, int] = field(default_factory=dict)
    draft_purposes: Dict[int, set] = field(default_factory=dict)
    ready_requests: Dict[int, int] = field(default_factory=dict)

    def eligibility(
        self,
        request: ReviewRequest,
        *,
        current_head: str,
        quota_available: Optional[bool],
        coherent_batch: bool,
        deterministic_checks_done: bool,
        blocking_comment_pending: bool,
        writer_active: bool,
        provider_active: bool,
    ) -> Tuple[bool, str]:
        if request.key.head_sha != current_head:
            return False, "stale-head"
        if not coherent_batch or not deterministic_checks_done:
            return False, "checks-or-batch-incomplete"
        if blocking_comment_pending or writer_active or provider_active:
            return False, "active-work-or-untreated-comment"
        if quota_available is not True:
            return False, "quota-unavailable"
        if request.stage == "draft":
            if request.key.provider not in INTERMEDIATE_PROVIDERS:
                return False, "provider-not-allowlisted-for-draft"
            if request.risk in ("security", "protocol"):
                purposes = self.draft_purposes.setdefault(request.key.pr, set())
                if purposes and request.purpose in purposes:
                    return False, "duplicate-purpose"
            if request.key in self.active or request.key in self.terminal:
                return False, "duplicate-key"
            limit = 2 if request.risk in ("security", "protocol") else 1
            used = self.draft_requests.get(request.key.pr, 0)
            if used >= limit:
                return False, "draft-budget-exhausted"
        elif request.stage == "ready":
            if request.key.provider != FINAL_PROVIDER:
                return False, "provider-not-allowlisted-for-ready"
            if request.key in self.active or request.key in self.terminal:
                return False, "duplicate-key"
            if self.ready_requests.get(request.key.pr, 0) >= 1:
                return False, "ready-budget-exhausted"
        else:
            return False, "unknown-stage"
        if len(self.active) >= GLOBAL_ACTIVE_LIMIT:
            return False, "global-concurrency-limit"
        return True, "eligible"

    def start(self, request: ReviewRequest) -> None:
        allowed, reason = self.eligibility(
            request,
            current_head=request.key.head_sha,
            quota_available=True,
            coherent_batch=True,
            deterministic_checks_done=True,
            blocking_comment_pending=False,
            writer_active=False,
            provider_active=False,
        )
        if not allowed:
            raise ValueError(reason)
        self.active = frozenset((*self.active, request.key))
        if request.stage == "draft":
            self.draft_requests[request.key.pr] = self.draft_requests.get(request.key.pr, 0) + 1
            self.draft_purposes.setdefault(request.key.pr, set()).add(request.purpose)
        elif request.stage == "ready":
            self.ready_requests[request.key.pr] = self.ready_requests.get(request.key.pr, 0) + 1

    def finish(self, key: ReviewKey, observed_head: str, state: str) -> bool:
        if key not in self.active or observed_head != key.head_sha:
            return False
        self.active = frozenset(item for item in self.active if item != key)
        self.terminal[key] = state
        return True
