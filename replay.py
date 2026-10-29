"""
Replay real repository histories through every trust model.

Each author is a contributor in a PUBLIC community (Tr(0) = 0, Eq. 12 of [34]).
Events are processed in commit order; the score BEFORE a commit decides the
review level the commit would have received (config.LEVELS).

Git contains no review ratings, so R_ji is empty for every model (the
reputation term contributes nothing) and E4 = 0 (no evidence).

Outputs (results/):
  replay_trajectories_<repo>.csv   per-event score of every model for selected authors
  replay_attacks.json              level of each malicious commit at submission, flags before discovery
  replay_population.csv            false-positive statistics for presumed-honest contributors
"""
from __future__ import annotations

import csv, json, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from signals import Signals, evidence
from models import M34, Proposed, MovingAvg, BetaRep
from config import LEVELS

ROOT = Path(__file__).resolve().parents[1]
DATA, OUT = ROOT / "data", ROOT / "results"
GT = json.loads((DATA / "ground_truth.json").read_text())
REPOS = ["xz", "event-stream", "zlib", "lz4", "express", "libarchive", "zstd", "curl"]
MIN_COMMITS = 10


def models():
    return [M34(), MovingAvg(), BetaRep(), Proposed()]


def level(x):
    if x < LEVELS["restricted"]: return "restricted"
    if x < LEVELS["low"]: return "L0"
    if x < LEVELS["high"]: return "L1"
    return "L2"


def to_signals(e, extra_alert=False) -> Signals:
    if e["kind"] == "reverted":
        return Signals(reverted=True)
    if e["kind"] == "release":
        return Signals(reviewed=False, sensitive=True, alert=extra_alert)
    return Signals(tests_included=e["tests_included"], signed=e["signed"], reviewed=e["reviewed"],
                   sensitive=e["sensitive"], binary_blob=e["binary_blob"], new_dependency=e["new_dependency"],
                   security_weakening=e["security_weakening"], alert=extra_alert)


def ts(d):
    return datetime.fromisoformat(d).replace(tzinfo=timezone.utc).timestamp()


def replay(repo, extra_events=(), cutoff=None):
    """Return {author: [ {sha,t,subject,S,pre:{model:score}, post:{model:score}} ]}.
    extra_events: additional interactions (e.g. a release whose artefact failed a check)."""
    path = DATA / f"events_{repo}.jsonl"
    events = [json.loads(l) for l in open(path)] + list(extra_events)
    events.sort(key=lambda e: e["t"])
    if cutoff:
        events = [e for e in events if e["t"] < cutoff]
    ms = models()
    state = {}
    last_t = {}
    hist = defaultdict(list)
    for e in events:
        a = e["author"]
        if a not in state:
            state[a] = {m.name: m.new(0.0, newcomer=True) for m in ms}
        sig = to_signals(e, extra_alert=e.get("alert", False))
        S, comps = evidence(sig)
        dt = (e["t"] - last_t[a]) / 86400 if a in last_t else 0.0
        last_t[a] = e["t"]
        pre = {m.name: state[a][m.name].score for m in ms}
        post = {m.name: m.update(state[a][m.name], S, sig.critical, [], 1, dt_days=dt) for m in ms}
        hist[a].append(dict(sha=e["sha"], t=e["t"], kind=e["kind"], subject=e.get("subject", ""),
                            S=S, E=comps, risk=sig.risk(), pre=pre, post=post))
    return hist


def attack_report(repo, hist, scenario):
    gt = GT[repo]
    disc = ts(gt["discovery_date"])
    out = {"repo": repo, "scenario": scenario, "attackers": {}}
    for a in gt["attacker"] + gt.get("related_accounts", []):
        h = hist.get(a, [])
        if not h:
            continue
        rec = {"n_events": len(h), "first": h[0]["t"], "malicious": [], "first_flag_before_discovery": {},
               "min_score_before_discovery": {}}
        for m in h[0]["pre"]:
            flagged = [x for x in h if x["t"] < disc and x["post"][m] < LEVELS["low"]]
            rec["first_flag_before_discovery"][m] = (
                {"sha": flagged[0]["sha"][:8], "date": datetime.fromtimestamp(flagged[0]["t"], timezone.utc).date().isoformat(),
                 "subject": flagged[0]["subject"], "score": round(flagged[0]["post"][m], 3)} if flagged else None)
            pre_disc = [x["post"][m] for x in h if x["t"] < disc]
            rec["min_score_before_discovery"][m] = round(min(pre_disc), 3) if pre_disc else None
        for x in h:
            if any(x["sha"].startswith(s) for s in gt["malicious_commits"]):
                rec["malicious"].append({
                    "sha": x["sha"][:8], "date": datetime.fromtimestamp(x["t"], timezone.utc).date().isoformat(),
                    "subject": x["subject"], "S": x["S"], "E": x["E"], "risk": x["risk"],
                    "level_at_submission": {m: level(v) for m, v in x["pre"].items()},
                    "score_before": {m: round(v, 3) for m, v in x["pre"].items()},
                    "score_after": {m: round(v, 3) for m, v in x["post"].items()},
                })
        out["attackers"][a] = rec
    return out


def population(repo, hist, exclude):
    rows = []
    for a, h in hist.items():
        commits = [x for x in h if x["kind"] == "commit"]
        if a in exclude or len(commits) < MIN_COMMITS:
            continue
        for m in h[0]["pre"]:
            pre_levels = [level(x["pre"][m]) for x in commits]
            posts = [x["post"][m] for x in h]
            # warm-up: ignore the first 10 commits for "level at submission" burden (everyone starts at 0)
            after = pre_levels[MIN_COMMITS:]
            rows.append(dict(
                repo=repo, author=a, model=m, commits=len(commits),
                ever_flagged=int(min(posts[MIN_COMMITS:] or [1]) < LEVELS["low"]),
                ever_restricted=int(min(posts[MIN_COMMITS:] or [1]) < LEVELS["restricted"]),
                frac_extra_review=round(sum(l in ("L0", "restricted") for l in after) / max(len(after), 1), 4),
                frac_L2=round(sum(l == "L2" for l in after) / max(len(after), 1), 4),
                commits_to_L2=next((i for i, l in enumerate(pre_levels) if l == "L2"), None),
            ))
    return rows


def write_traj(repo, hist, authors, suffix=""):
    authors = list(dict.fromkeys(authors))          # de-duplicate, keep order
    with open(OUT / f"replay_trajectories_{repo}{suffix}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["author", "date", "sha", "kind", "subject", "S", "risk"] + [f"{m}" for m in ["M34", "MovingAvg", "BetaRep", "Proposed"]])
        for a in authors:
            for x in hist.get(a, []):
                w.writerow([a, datetime.fromtimestamp(x["t"], timezone.utc).date().isoformat(), x["sha"][:8], x["kind"],
                            x["subject"][:70], x["S"], x["risk"]] + [round(x["post"][m], 4) for m in ["M34", "MovingAvg", "BetaRep", "Proposed"]])


def main():
    OUT.mkdir(exist_ok=True)
    reports, pop = [], []
    for repo in REPOS:
        if not (DATA / f"events_{repo}.jsonl").exists():
            print("missing", repo, file=sys.stderr); continue
        hist = replay(repo)
        exclude = set()
        if repo in GT:
            exclude = set(GT[repo]["attacker"]) | set(GT[repo].get("related_accounts", []))
            reports.append(attack_report(repo, hist, "git signals only"))
            # all contributors of the repo in the trajectory file
            write_traj(repo, hist, list(GT[repo]["attacker"]) + list(GT[repo].get("related_accounts", []))
                       + [a for a, h in sorted(hist.items(), key=lambda kv: -len(kv[1]))[:2]])
        pop += population(repo, hist, exclude)
    # counterfactual: a release-artefact check (tarball vs. git) raises a confirmed alert
    if (DATA / "events_xz.jsonl").exists():
        rel = [dict(sha=sha, t=int(ts(d) + 43200), author="jia tan", kind="release", alert=True,
                    subject=f"release {v}: tarball differs from git (build-to-host.m4)")
               for sha, v, d in [("2d7d862e", "5.6.0", "2024-02-24"), ("fd1b975b", "5.6.1", "2024-03-09")]]
        hist = replay("xz", extra_events=rel)
        reports.append(attack_report("xz", hist, "git signals + release-tarball reproducibility check"))
        write_traj("xz", hist, ["jia tan", "lasse collin"], suffix="_with_tarball_check")
    json.dump(reports, open(OUT / "replay_attacks.json", "w"), indent=2, ensure_ascii=False)
    with open(OUT / "replay_population.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(pop[0])); w.writeheader(); w.writerows(pop)
    print(f"{len(reports)} attack reports, {len(pop)//4} presumed-honest contributors")


if __name__ == "__main__":
    main()
