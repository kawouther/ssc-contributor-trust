"""
Contributor behaviour profiles for the synthetic experiments.

Honest behaviour is calibrated on real data: the probability of each signal is
the pooled rate measured over 26,731 commits of 130+ contributors in
zlib, lz4, express, libarchive, zstd (data/honest_base_rates.json).
CI results are not in git; a 5% CI failure rate is ASSUMED for honest
contributors (varied in the sensitivity analysis).
"""
from __future__ import annotations

import json, random
from pathlib import Path

from signals import Signals

BASE = json.loads((Path(__file__).resolve().parents[1] / "data/honest_base_rates.json").read_text())
CI_FAIL_HONEST = 0.05
P_REVIEW_OTHERS = 0.3     # probability that a contributor reviewed someone else's work in a period


def honest(rng: random.Random, careless: bool = False) -> Signals:
    f = 0.5 if careless else 1.0
    s = Signals(
        ci_pass=rng.random() > (0.25 if careless else CI_FAIL_HONEST),
        reverted=rng.random() < (0.05 if careless else BASE["reverted"]),
        tests_included=rng.random() < BASE["tests_included"] * f,
        signed=rng.random() < BASE["signed"],
        reviewed=rng.random() < BASE["reviewed"] * f,
        sensitive=rng.random() < BASE["sensitive"],
        binary_blob=rng.random() < BASE["binary_blob"],
        new_dependency=rng.random() < BASE["new_dependency"],
        security_weakening=rng.random() < BASE["security_weakening"],
    )
    if rng.random() < P_REVIEW_OTHERS:
        s.review_deviation = abs(rng.gauss(0, 0.35 if careless else 0.2))
    return s


def malicious_act(rng: random.Random, p_obs: float) -> Signals:
    """A malicious contribution. With probability p_obs it is CONFIRMED (a scanner,
    reviewer or reproducibility check raises an alert). Otherwise it is covert: it
    looks like an ordinary contribution, except that attacks touch a sensitive file
    (build system, CI or dependency manifest) without independent review."""
    s = honest(rng)
    s.malicious = True
    s.reviewed = False
    s.sensitive = True
    s.ci_pass = True
    if rng.random() < p_obs:
        s.alert = True
        if rng.random() < 0.5:
            s.binary_blob = True
        else:
            s.new_dependency = True
    return s
