"""
Synthetic attack experiments with repeated runs.

Scenarios (one contributor, horizon T interactions, public community unless noted):
  honest      calibrated honest contributor                         -> false positives
  careless    low-quality but not malicious ("suspicious" profile)   -> should not be trusted
  malicious   attacks with prob. 0.3 from the first interaction
  longcon     honest for 100 interactions, then attacks with prob. 0.3   (xz-style sleeper)
  onoff       adaptive: attacks whenever its (public, on-chain) score is >= 0.5, else behaves well
  whitewash   attacks with prob. 0.3; when flagged (score < 0) it re-registers as a new identity
  collusion   community of N members; a Sybil ring bad-mouths an honest target and praises itself

Metrics:
  exposure       malicious contributions submitted while the author was at Level 2
                 (i.e. they would get standard review only)
  detected       author flagged (score < 0) at some point after its first malicious act
  ttd            interactions from the first malicious act to the first flag
  fp_ever        honest author flagged at least once after a 10-interaction warm-up
  burden         share of an honest author's contributions submitted at Level 0/restricted
  t_L2           interactions an honest author needs to reach Level 2

Every model sees the same random signal stream for a given (scenario, run, p_obs):
signals are generated from a per-run seed independent of the model. Adaptive
attackers (onoff, whitewash) react to each model's own score.
"""
from __future__ import annotations

import json, math, random, statistics as st, sys
from collections import defaultdict
from pathlib import Path

import agents
from signals import Signals, evidence
from models import M34, Proposed, MovingAvg, BetaRep, initial_trust, ablations
from config import EXPERIMENT as X, LEVELS

OUT = Path(__file__).resolve().parents[1] / "results"
WARMUP = 10
P_ATTACK = 0.3


def lvl2(x): return x >= LEVELS["high"]
def flagged(x): return x < LEVELS["low"]


def run_single(model, scenario, seed, p_obs, T, private=False, trace=None):
    rng = random.Random(seed)            # same stream for every model
    init = initial_trust("private", Tp=0.7, Ta=2, Tc=2, C=1, G=1, S=1) if private else 0.0
    st_ = model.new(init, newcomer=not private)
    m = dict(exposure=0, mal=0, first_mal=None, first_flag=None, flags_after_warm=0,
             burden=0, n_after=0, t_L2=None, identities=1, L2=0)
    for t in range(T):
        pre = st_.score
        attack = False
        if scenario == "malicious" or scenario == "whitewash":
            attack = rng.random() < P_ATTACK
        elif scenario == "longcon":
            attack = t >= X["longcon_warmup"] and rng.random() < P_ATTACK
        elif scenario == "onoff":
            r = rng.random()
            attack = pre >= X["onoff_attack_threshold"]
        else:
            rng.random()
        s = agents.malicious_act(rng, p_obs) if attack else agents.honest(rng, careless=(scenario == "careless"))
        S, _ = evidence(s)
        if attack:
            m["mal"] += 1
            if m["first_mal"] is None: m["first_mal"] = t
            if lvl2(pre): m["exposure"] += 1
        if t >= WARMUP:
            m["n_after"] += 1
            if not (pre >= LEVELS["low"]): m["burden"] += 1
            if lvl2(pre): m["L2"] += 1
        if m["t_L2"] is None and lvl2(pre): m["t_L2"] = t
        post = model.update(st_, S, s.critical, [], 1)
        if trace is not None:
            trace.append((t, round(S, 4), round(post, 4), int(attack), int(s.alert)))
        if flagged(post):
            if t >= WARMUP: m["flags_after_warm"] += 1
            if m["first_mal"] is not None and m["first_flag"] is None:
                m["first_flag"] = t
            if scenario == "whitewash":          # abandon identity, re-register at Tr = 0
                st_ = model.new(0.0, newcomer=True)
                m["identities"] += 1
    return m


def summarise(vals):
    vals = [v for v in vals if v is not None]
    if not vals: return {"mean": None, "sd": None, "ci95": None, "n": 0}
    mu = st.mean(vals); sd = st.pstdev(vals) if len(vals) > 1 else 0.0
    return {"mean": round(mu, 4), "sd": round(sd, 4), "ci95": round(1.96 * sd / math.sqrt(len(vals)), 4), "n": len(vals)}


def single_agent(models, runs, T, p_list, scenarios, private=False):
    res = []
    for sc in scenarios:
        for p in (p_list if sc not in ("honest", "careless") else [None]):
            for model in models:
                ms = [run_single(model, sc, 1000 * r + 17, p or 0.0, T, private) for r in range(runs)]
                row = dict(scenario=sc, p_obs=p, model=model.name, private=private)
                if sc in ("honest", "careless"):
                    row["fp_ever"] = summarise([int(m["flags_after_warm"] > 0) for m in ms])
                    row["burden"] = summarise([m["burden"] / m["n_after"] for m in ms])
                    row["frac_L2"] = summarise([m["L2"] / m["n_after"] for m in ms])
                    row["t_L2"] = summarise([m["t_L2"] for m in ms])
                    row["t_L2_never"] = sum(m["t_L2"] is None for m in ms) / runs
                else:
                    row["exposure"] = summarise([m["exposure"] for m in ms])
                    row["malicious_acts"] = summarise([m["mal"] for m in ms])
                    row["exposure_rate"] = summarise([m["exposure"] / m["mal"] for m in ms if m["mal"]])
                    row["detected"] = summarise([int(m["first_flag"] is not None) for m in ms if m["first_mal"] is not None])
                    row["ttd"] = summarise([m["first_flag"] - m["first_mal"] for m in ms if m["first_flag"] is not None])
                    if sc == "whitewash":
                        row["identities"] = summarise([m["identities"] for m in ms])
                res.append(row)
    return res


# ------------------------------------------------------------------ collusion
def collusion(model_factory, ring, runs, T, N, k_rev, policy="open"):
    """Community of N contributors: honest vetted members (private init), one honest
    target (newcomer) and `ring` Sybil newcomers that contribute honestly but rate
    dishonestly (+1 to the ring, -1 to the target).

    policy = "open":     anyone may rate anyone (as in [34], reputations are collected
                         from all members); every Sybil rates every Sybil and the target
                         in every round, in addition to the assigned reviews.
    policy = "assigned": only the k_rev reviewers assigned by the platform to a
                         contribution may rate it (assignment recorded on-chain);
                         Sybils can only bad-mouth when they happen to be assigned.
    E4 (intent) compares each rating with the MEDIAN rating of the same contribution."""
    out = []
    for r in range(runs):
        rng = random.Random(77 * r + ring)
        model = model_factory()
        members = list(range(N))
        target = 0
        sybils = set(range(1, 1 + ring))
        init_priv = initial_trust("private", Tp=0.7, Ta=2, Tc=2, C=1, G=1, S=1)
        states = {i: model.new(0.0 if (i == target or i in sybils) else init_priv,
                               newcomer=(i == target or i in sybils)) for i in members}
        tgt_scores, tgt_flags, syb_L2 = [], 0, 0
        for t in range(T):
            contrib = {i: agents.honest(rng) for i in members}
            S_of = {i: evidence(contrib[i])[0] for i in members}
            ratings = defaultdict(list)          # ratee -> [(rater, rating)]
            def rate(j, i):
                if j in sybils:
                    return -1.0 if i == target else (1.0 if i in sybils else S_of[i])
                return max(-1.0, min(1.0, S_of[i] + rng.gauss(0, 0.2)))
            for i in members:
                for j in rng.sample([j for j in members if j != i], k_rev):
                    ratings[i].append((j, rate(j, i)))
            if policy == "open":
                for a in sybils:
                    for b in sybils:
                        if a != b and all(a != x for x, _ in ratings[b]):
                            ratings[b].append((a, 1.0))
                    if all(a != x for x, _ in ratings[target]):
                        ratings[target].append((a, -1.0))
            given = defaultdict(list)
            for ratee, lst in ratings.items():
                cons = st.median(x for _, x in lst)
                for rater, x in lst:
                    given[rater].append(abs(x - cons))
            for i in members:
                contrib[i].review_deviation = st.mean(given[i]) if given[i] else None
            for i in members:
                S, _ = evidence(contrib[i])
                lst = [(states[j].score, x) for j, x in ratings[i]]
                model.update(states[i], S, contrib[i].critical, lst, N)
            if t >= WARMUP:
                tgt_scores.append(states[target].score)
                tgt_flags += flagged(states[target].score)
                syb_L2 += sum(lvl2(states[s].score) for s in sybils)
        out.append(dict(target_mean=st.mean(tgt_scores), target_flag_rate=tgt_flags / (T - WARMUP),
                        sybil_L2_rate=syb_L2 / ((T - WARMUP) * max(ring, 1))))
    return {k: summarise([o[k] for o in out]) for k in out[0]}


def main(quick=False):
    OUT.mkdir(exist_ok=True)
    runs = 20 if quick else X["runs"]
    T = X["horizon"]
    models = [M34(), MovingAvg(), BetaRep(), Proposed()]
    scen = ["honest", "careless", "malicious", "longcon", "onoff", "whitewash"]
    res = single_agent(models, runs, T, list(X["p_observable"]), scen)
    res += single_agent([M34(), Proposed()], runs, T, [0.5], ["honest", "longcon"], private=True)
    json.dump(res, open(OUT / "synthetic_main.json", "w"), indent=1)

    abl = single_agent(ablations(), runs, T, [0.5], ["honest", "longcon", "onoff", "whitewash"])
    json.dump(abl, open(OUT / "synthetic_ablation.json", "w"), indent=1)

    col = []
    factories = {"M34": M34, "Proposed": Proposed,
                 "Proposed (rep: mean)": lambda: Proposed(reputation="mean", name="Proposed (rep: mean)")}
    for policy in ("open", "assigned"):
        for ring in (0,) + tuple(X["collusion_ring"]):
            for name, f in factories.items():
                r = collusion(f, ring, max(runs // 4, 10), 100, X["community"], X["reviewers_per_interaction"], policy)
                col.append(dict(policy=policy, ring=ring, model=name, **r))
    json.dump(col, open(OUT / "synthetic_collusion.json", "w"), indent=1)
    sens = sensitivity(max(runs // 2, 10), T)
    json.dump(sens, open(OUT / "synthetic_sensitivity.json", "w"), indent=1)
    print("done", len(res), len(abl), len(col), len(sens))




# ------------------------------------------------------------------ sensitivity
def sensitivity(runs, T):
    """One-at-a-time variation of each NEW parameter around its default."""
    from config import PROPOSED as PP
    grid = {
        "alpha_up": [0.05, 0.10, 0.15, 0.25, 0.40],
        "alpha_down": [0.20, 0.30, 0.40, 0.50, 0.60, 0.80],
        "probation_n": [0, 5, 10, 20, 40],
        "restrict_n": [0, 10, 30, 60],
    }
    default = dict(PP)
    rows = []
    for param, values in grid.items():
        for v in values:
            PP.update(default); PP[param] = v
            r = single_agent([Proposed()], runs, T, [0.5], ["honest", "longcon", "onoff", "whitewash"])
            by = {x["scenario"]: x for x in r}
            rows.append(dict(param=param, value=v, is_default=(v == default[param]),
                             honest_fp_ever=by["honest"]["fp_ever"]["mean"], honest_burden=by["honest"]["burden"]["mean"],
                             honest_frac_L2=by["honest"]["frac_L2"]["mean"],
                             longcon_exposure=by["longcon"]["exposure"]["mean"], longcon_ttd=by["longcon"]["ttd"]["mean"],
                             onoff_exposure=by["onoff"]["exposure"]["mean"], whitewash_exposure=by["whitewash"]["exposure"]["mean"]))
    PP.update(default)
    return rows


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
