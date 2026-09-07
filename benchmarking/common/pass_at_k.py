"""pass@k helpers for benchmark aggregation."""

from __future__ import annotations

import math


def pass_at_k_unbiased(n: int, c: int, k: int) -> float:
    """Unbiased pass@k estimator given n independent samples per problem with c correct.

    pass@k = 1 - C(n-c, k) / C(n, k) when n >= k >= 0.

    When k == n (e.g. three attempts and report pass@3 as solved-if-any), this equals 1 iff c >= 1.
    """
    if k < 0 or n < 0 or c < 0 or c > n:
        raise ValueError("invalid n, c, k")
    if k > n:
        raise ValueError("k cannot exceed n")
    if k == 0:
        return 1.0 if c == n else 0.0
    if c == 0:
        return 0.0
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)
