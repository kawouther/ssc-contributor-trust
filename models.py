"""
Trust models compared in the evaluation.

    M34       - the model of [34] exactly as written in the paper (Eqs. 3-5),
                plus the explicit clipping to [-1, 1] that Table 4 implies.
    Proposed  - the extended model (asymmetric update, critical-event rule with a
                restriction period, newcomer probation, trust-weighted reputation,
                inactivity decay). Each extension can be switched off for the
                ablation study.
    MovingAvg - simple moving average of S(t)                    (baseline)
    BetaRep   - Beta reputation with forgetting (Josang & Ismail) (baseline)

Every model receives exactly the same evidence stream and ratings, and the
same decision policy (config.LEVELS) is applied to every model's score.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

from config import M34 as P34, PROPOSED as PP, BASELINES as PB, INIT


def clip(x, lo=-1.0, hi=1.0):
    return lo if x < lo else hi if x > hi else x


def initial_trust(community: str, Tp=0.0, Ta=0, Tc=0, C=0, G=0.0, S=0.0) -> float:
    """Eq. 1 of [34] with normalised inputs (Tr(0) in [0,1]); Eq. 12 for public communities.
    Ta, Tc, C in {0,1,2}; G, S in {0, 0.5, 1}; Tp in [0,1]."""
    if community == "public":
        return 0.0
    w1, w2, w3, w4, w5 = INIT["omega"]
    beta = (G + S) / 2
    return w1 * Tp + w2 * Ta / 2 + w3 * Tc / 2 + w4 * C / 2 + w5 * beta


@dataclass
class CState:
    score: float
    n: int = 0                     # interactions so far
    last_ratings: list = field(default_factory=list)   # [(rater_weight, rating)]
    window: deque = field(default_factory=lambda: deque(maxlen=PB["ma_window"]))
    r: float = 0.0
    s: float = 0.0
    newcomer: bool = False
    restrict_left: int = 0


class Model:
    name = "base"
    def new(self, init: float, newcomer: bool = False) -> CState:
        return CState(score=init, newcomer=newcomer)
    def update(self, st: CState, S: float, critical: bool, ratings, community: int, dt_days: float = 0.0) -> float:
        raise NotImplementedError


class M34(Model):
    """Tr(t) = clip( eps1*Tr(t-1) + eps2 * sum_j R_ji(t-1) / N  +  S(t) )."""
    name = "M34"
    def update(self, st, S, critical, ratings, community, dt_days=0.0):
        rep = sum(r for _, r in st.last_ratings) / max(community, 1)
        st.score = clip(P34["eps1"] * st.score + P34["eps2"] * rep + S, *P34["clip"])
        st.last_ratings = ratings
        st.n += 1
        return st.score


class Proposed(Model):
    def __init__(self, asym=True, critical=True, probation=True,
                 reputation="weighted", decay=True, name=None):
        self.asym, self.use_critical = asym, critical
        self.use_probation, self.reputation, self.decay = probation, reputation, decay
        self.name = name or "Proposed"

    def _rep(self, st, community):
        rs = st.last_ratings
        if not rs:
            return None
        if self.reputation == "sumN":                      # as in [34]
            return sum(r for _, r in rs) / max(community, 1)
        if self.reputation == "mean":                      # naive fix of the N problem
            return sum(r for _, r in rs) / len(rs)
        # "weighted" / "eigen": weight = rater trust (or EigenTrust value) above a floor
        ws = [(w, r) for w, r in rs if w >= PP["rater_min_trust"]]
        if not ws:
            return None
        tot = sum(w for w, _ in ws)
        return sum(w * r for w, r in ws) / tot

    def update(self, st, S, critical, ratings, community, dt_days=0.0):
        if self.decay and dt_days > 0:
            st.score *= 0.5 ** (dt_days / PP["inactivity_halflife_days"])
        rep = self._rep(st, community)
        H = st.score if rep is None else PP["eps1"] * st.score + PP["eps2"] * rep
        if self.asym:
            # fast loss only for genuinely negative evidence; otherwise slow movement
            a = PP["alpha_down"] if S < 0 else PP["alpha_up"]
        else:
            a = 0.5 * (PP["alpha_up"] + PP["alpha_down"])
        x = (1 - a) * H + a * S                    # convex combination -> stays in [-1, 1]
        if self.use_probation and st.newcomer and st.n < PP["probation_n"]:
            x = min(x, PP["probation_cap"])
        if self.use_critical and critical:
            st.restrict_left = PP["restrict_n"]
        if st.restrict_left > 0:
            x = min(x, PP["critical_cap"])
            st.restrict_left -= 1
        st.score = clip(x)
        st.last_ratings = ratings
        st.n += 1
        return st.score


class MovingAvg(Model):
    name = "MovingAvg"
    def new(self, init, newcomer=False):
        st = CState(score=init, newcomer=newcomer)
        return st
    def update(self, st, S, critical, ratings, community, dt_days=0.0):
        st.window.append(S)
        st.score = sum(st.window) / len(st.window)
        st.n += 1
        return st.score


class BetaRep(Model):
    """Beta reputation: r, s accumulate positive/negative evidence with forgetting.
    score = (r - s) / (r + s + 2)  in (-1, 1)."""
    name = "BetaRep"
    def new(self, init, newcomer=False):
        st = CState(score=init, newcomer=newcomer)
        # encode the initial score as 2 pseudo-observations
        st.r, st.s = (1 + init), (1 - init)
        st.score = (st.r - st.s) / (st.r + st.s + 2)
        return st
    def update(self, st, S, critical, ratings, community, dt_days=0.0):
        lam = PB["beta_forget"]
        st.r = lam * st.r + (1 + S) / 2
        st.s = lam * st.s + (1 - S) / 2
        st.score = (st.r - st.s) / (st.r + st.s + 2)
        st.n += 1
        return st.score


def all_models():
    return [M34(), MovingAvg(), BetaRep(), Proposed()]


def ablations():
    return [
        Proposed(name="Proposed"),
        Proposed(asym=False, name="-asymmetry"),
        Proposed(critical=False, name="-critical rule"),
        Proposed(probation=False, name="-probation"),
    ]
