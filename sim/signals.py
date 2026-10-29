"""
Observable signals of one contribution and the evidence functions E1-E4.

The four functions keep the threshold form of [34] (Eqs. 8-11): each returns
+1 (trustworthy) or -1 (untrustworthy). We add the value 0 for "no evidence
for this dimension in this interaction", which [34] leaves undefined.
What is new is the mapping of each dimension to software-supply-chain signals
that a forge or CI pipeline can observe AT THE TIME of the contribution:

  E1 competence  T^c : does the contribution work?
        T^c = 0 if CI failed or the contributor's earlier work was reverted, else 1
        E1  = +1 if T^c > Th1 else -1                       (Th1 = 0.5)

  E2 willingness T^w : does the contributor follow the project's process?
        +1  reviewed by someone else, or includes tests
         0  neither (no evidence)
        -1  a sensitive change (build/CI/dependencies/security config) that bypassed review

  E3 integrity   T^i : risk of the contribution on the 0-10 scale of [34] (Table 9)
        R = max over the risks below;  E3 = -1 if R >= 7 (high/critical) else +1 (Eq. 10)
            confirmed alert (scanner / release artefact != source)   10
            security control removed/changed in build or CI file      8
            opaque binary blob, unreviewed                            7
            new third-party dependency, unreviewed                    7
            sensitive file changed, unreviewed                        4
            otherwise                                                 0

  E4 intent      T^int : consistency of the contributor's OWN reviews with the
        consensus, as in [34] (Eq. 11):  +1 if |R_ij - mean_k R_kj| < Th4,
        -1 if larger, 0 if the contributor reviewed nothing in this period.
        (Th4 = 0.5)  This is what exposes rubber-stamping and bad-mouthing rings.

S(t) = (E1 + E2 + E3 + E4) / 4  in [-1, 1]   (Eq. 7 of [34]; the /4 applies to the whole sum)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

TH1 = 0.5
TH4 = 0.5
RISK_HIGH = 7

RISK = dict(alert=10, security_weakening=8, binary_blob=7, new_dependency=7, sensitive=4)


@dataclass
class Signals:
    ci_pass: bool = True             # CI / build / test result (not in git; True in replays)
    reverted: bool = False           # an earlier contribution of this author was reverted (delayed evidence)
    tests_included: bool = False
    signed: bool = False
    reviewed: bool = False           # independently reviewed / merged by someone else
    sensitive: bool = False          # build system, CI, dependency manifest, security config
    binary_blob: bool = False        # opaque binary (not an image/font/doc asset)
    new_dependency: bool = False
    security_weakening: bool = False # heuristic, unconfirmed
    alert: bool = False              # confirmed violation
    review_deviation: Optional[float] = None  # mean |R_ij - consensus| of reviews i gave; None = gave none
    malicious: bool = False          # GROUND TRUTH ONLY - never read by any model
    meta: dict = field(default_factory=dict)

    @property
    def critical(self) -> bool:
        """Only a confirmed alert is critical (hard rule of the proposed model)."""
        return self.alert

    def risk(self) -> int:
        r = 0
        if self.alert: r = max(r, RISK["alert"])
        if self.security_weakening: r = max(r, RISK["security_weakening"])
        if self.binary_blob and not self.reviewed: r = max(r, RISK["binary_blob"])
        if self.new_dependency and not self.reviewed: r = max(r, RISK["new_dependency"])
        if self.sensitive and not self.reviewed: r = max(r, RISK["sensitive"])
        return r


def E1(s: Signals) -> float:
    tc = 0.0 if (s.reverted or not s.ci_pass) else 1.0
    return 1.0 if tc > TH1 else -1.0


def E2(s: Signals) -> float:
    if (s.sensitive or s.new_dependency) and not s.reviewed:
        return -1.0
    if s.reviewed or s.tests_included:
        return 1.0
    return 0.0


def E3(s: Signals) -> float:
    return -1.0 if s.risk() >= RISK_HIGH else 1.0


def E4(s: Signals) -> float:
    if s.review_deviation is None:
        return 0.0
    return 1.0 if s.review_deviation < TH4 else -1.0


def evidence(s: Signals):
    e = (E1(s), E2(s), E3(s), E4(s))
    return sum(e) / 4.0, e
