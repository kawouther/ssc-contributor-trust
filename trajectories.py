"""
Per-interaction CTS values (the measured replacement for the old Table 4 / Fig. 8).

Writes results/per_interaction_cts.csv : every interaction of every run
        (scenario, model, run, t, S, CTS, malicious_act, confirmed_alert)
and    results/per_interaction_summary.csv : mean, sd, 5th/95th percentile per t.
"""
import csv, statistics as st
from pathlib import Path
from experiments import run_single
from models import M34, Proposed, MovingAvg, BetaRep
from config import EXPERIMENT as X

OUT = Path(__file__).resolve().parents[1] / "results"
P_OBS = 0.5
SCEN = ["honest", "careless", "malicious", "longcon", "onoff"]


def main():
    runs, T = X["runs"], X["horizon"]
    rows, summ = [], []
    for sc in SCEN:
        for m in [M34(), MovingAvg(), BetaRep(), Proposed()]:
            per_t = [[] for _ in range(T)]
            for r in range(runs):
                tr = []
                run_single(m, sc, 1000 * r + 17, P_OBS, T, trace=tr)
                for t, S, cts, mal, al in tr:
                    rows.append((sc, m.name, r, t + 1, S, cts, mal, al))
                    per_t[t].append(cts)
            for t, v in enumerate(per_t):
                v = sorted(v)
                summ.append((sc, m.name, t + 1, round(st.mean(v), 4), round(st.pstdev(v), 4),
                             v[int(0.05 * (len(v) - 1))], v[int(0.95 * (len(v) - 1))]))
    with open(OUT / "per_interaction_cts.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["scenario", "model", "run", "interaction", "S", "CTS", "malicious_act", "confirmed_alert"]); w.writerows(rows)
    with open(OUT / "per_interaction_summary.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["scenario", "model", "interaction", "mean", "sd", "p05", "p95"]); w.writerows(summ)
    print(len(rows), "rows")


if __name__ == "__main__":
    main()
