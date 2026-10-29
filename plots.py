"""Figures for the paper (PDF for LaTeX, PNG for preview). Reads results/*, writes paper/figures/*."""
import csv, json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker

ROOT = Path(__file__).resolve().parents[1]
RES, FIG = ROOT / "results", ROOT / "paper/figures"
FIG.mkdir(parents=True, exist_ok=True)

# fixed categorical order (validated: CVD-separated; low-contrast slots carry line style + labels)
COL = {"Proposed": "#2a78d6", "M34": "#eb6834", "MovingAvg": "#1baf7a", "BetaRep": "#eda100"}
LS = {"Proposed": "-", "M34": "--", "MovingAvg": "-.", "BetaRep": ":"}
LABEL = {"Proposed": "Proposed", "M34": "Original model", "MovingAvg": "Moving average", "BetaRep": "Beta reputation"}
INK, MUTED, GRID = "#262624", "#6b6a64", "#e4e3dd"

plt.rcParams.update({
    "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.4, "pdf.fonttype": 42,
})


def bands(ax):
    for y in (-0.5, 0.0, 0.5):
        ax.axhline(y, color=MUTED, lw=0.6, ls=(0, (2, 2)), zorder=0)
    x1 = ax.get_xlim()[1]
    for y, t in ((0.75, "Level 2"), (0.25, "Level 1"), (-0.25, "Level 0"), (-0.75, "Restricted")):
        ax.text(1.005, (y + 1) / 2, t, transform=ax.transAxes, fontsize=6, color=MUTED, va="center")
    ax.set_ylim(-1.05, 1.05)


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(FIG / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def read_traj(path, author):
    rows = [r for r in csv.DictReader(open(path)) if r["author"] == author]
    return rows


# ---------------------------------------------------------------- xz replay
def fig_xz():
    gt = json.load(open(ROOT / "data/ground_truth.json"))["xz"]
    a = read_traj(RES / "replay_trajectories_xz.csv", "jia tan")
    b = read_traj(RES / "replay_trajectories_xz_with_tarball_check.csv", "jia tan")
    fig, axes = plt.subplots(2, 1, figsize=(7.0, 4.2), sharex=True)
    for ax, rows, title in ((axes[0], a, "(a) Signals available in git only"),
                            (axes[1], b, "(b) Plus a release-artefact check (tarball vs. git) on 5.6.0 and 5.6.1")):
        d = [datetime.fromisoformat(r["date"]) for r in rows]
        for m in ["M34", "MovingAvg", "BetaRep", "Proposed"]:
            ax.plot(d, [float(r[m]) for r in rows], color=COL[m], ls=LS[m], lw=1.6 if m == "Proposed" else 1.1,
                    label=LABEL[m], drawstyle="steps-post")
        for r in rows:
            if any(r["sha"].startswith(s[:8]) for s in gt["malicious_commits"]):
                ax.axvline(datetime.fromisoformat(r["date"]), color="#e34948", lw=0.9)
            if r["kind"] == "release":
                ax.axvline(datetime.fromisoformat(r["date"]), color=INK, lw=0.9, ls=(0, (1, 1.5)))
        ax.axvline(datetime(2024, 3, 29), color=INK, lw=1.0)
        ax.text(datetime(2024, 3, 29), 1.08, " discovery", fontsize=6.5, color=INK, va="bottom")
        bands(ax)
        ax.set_title(title, loc="left", color=INK)
        ax.set_ylabel("CTS")
    axes[1].set_xlim(datetime(2023, 9, 1), datetime(2024, 4, 5))
    axes[1].xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    h, l = axes[0].get_legend_handles_labels()
    h += [plt.Line2D([], [], color="#e34948", lw=0.9), plt.Line2D([], [], color=INK, lw=0.9, ls=(0, (1, 1.5)))]
    l += ["Malicious commit", "Tampered release"]
    fig.legend(h, l, loc="upper center", ncol=6, frameon=False, bbox_to_anchor=(0.5, 1.03))
    fig.tight_layout(rect=(0, 0, 0.95, 0.96))
    save(fig, "fig_xz_replay")


def fig_eventstream():
    rows = read_traj(RES / "replay_trajectories_event-stream.csv", "北川")
    fig, ax = plt.subplots(figsize=(3.5, 2.3))
    x = list(range(1, len(rows) + 1))
    for m in ["M34", "MovingAvg", "BetaRep", "Proposed"]:
        ax.plot(x, [float(r[m]) for r in rows], color=COL[m], ls=LS[m], marker="o", ms=3, label=LABEL[m])
    for i, r in enumerate(rows, 1):
        if r["sha"].startswith("e316336"):
            ax.axvline(i, color="#e34948", lw=0.9)
            ax.text(i + 0.2, 0.62, "adds\nflatmap-stream", fontsize=6, color="#e34948", va="bottom")
    bands(ax)
    ax.set_xlabel("Commit of the attacker as a contributor (Sept 2018)")
    ax.set_ylabel("CTS")
    ax.legend(frameon=False, loc="lower right", ncol=1, fontsize=6)
    save(fig, "fig_eventstream_replay")


# ---------------------------------------------------------------- per-interaction CTS
def fig_cts():
    S = defaultdict(lambda: defaultdict(list))
    for r in csv.DictReader(open(RES / "per_interaction_summary.csv")):
        S[r["scenario"]][r["model"]].append((int(r["interaction"]), float(r["mean"]), float(r["p05"]), float(r["p95"])))
    titles = {"honest": "(a) Honest", "careless": "(b) Careless (suspicious)", "longcon": "(c) Long-con (malicious after t = 100)",
              "onoff": "(d) Adaptive on-off attacker"}
    fig, axes = plt.subplots(2, 2, figsize=(7.0, 4.4), sharex=True, sharey=True)
    for ax, sc in zip(axes.flat, titles):
        for m in ["M34", "MovingAvg", "BetaRep", "Proposed"]:
            v = sorted(S[sc][m])
            t = [x[0] for x in v]
            ax.plot(t, [x[1] for x in v], color=COL[m], ls=LS[m], lw=1.6 if m == "Proposed" else 1.1, label=LABEL[m])
            if m in ("Proposed", "M34"):
                ax.fill_between(t, [x[2] for x in v], [x[3] for x in v], color=COL[m], alpha=0.12, lw=0)
        if sc == "longcon":
            ax.axvline(100, color="#e34948", lw=0.9)
        bands(ax)
        ax.set_title(titles[sc], loc="left", color=INK)
    for ax in axes[1]: ax.set_xlabel("Interaction")
    for ax in axes[:, 0]: ax.set_ylabel("CTS")
    h, l = axes[0, 0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 1.03))
    fig.tight_layout(rect=(0, 0, 0.95, 0.96))
    save(fig, "fig_cts_per_interaction")


# ---------------------------------------------------------------- trade-off (sensitivity)
def fig_tradeoff():
    sens = json.load(open(RES / "synthetic_sensitivity.json"))
    main = json.load(open(RES / "synthetic_main.json"))
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    sweep = [r for r in sens if r["param"] == "alpha_down"]
    ax.plot([r["honest_burden"] * 100 for r in sweep], [r["longcon_exposure"] for r in sweep], color=COL["Proposed"],
            marker="o", ms=4, label="Proposed, $\\alpha_{down}$ sweep")
    for r in sweep:
        ax.annotate(f"{r['value']:.1f}", (r["honest_burden"] * 100, r["longcon_exposure"]), fontsize=6, color=MUTED,
                    xytext=(3, 3), textcoords="offset points")
    by = {(r["scenario"], r["model"]): r for r in main if not r["private"] and r["p_obs"] in (None, 0.5)}
    for m in ["M34", "MovingAvg", "BetaRep"]:
        ax.plot(by[("honest", m)]["burden"]["mean"] * 100, by[("longcon", m)]["exposure"]["mean"], ls="none",
                marker="s", ms=5, color=COL[m], label=LABEL[m])
    ax.set_xlabel("Honest contributions sent to extra review (%)")
    ax.set_ylabel("Long-con attacks at Level 2 (count)")
    ax.legend(frameon=False, fontsize=6)
    save(fig, "fig_tradeoff")


# ---------------------------------------------------------------- gas
def fig_gas():
    g = json.load(open(RES / "gas_summary.json"))
    s = {(r["design"], r["op"]): r for r in g["summary"]}
    batch = g["args"]["batch"]
    anchor = next(r for (d, op), r in s.items() if d == "TrustAnchorBatch" and op.startswith("anchor"))
    items = [("A  Full history in storage", s[("TrustRegistryFull", "update")]["gas_mean"]),
             ("B  Latest score + event log", s[("TrustRegistryEvent", "update")]["gas_mean"]),
             ("D  B with 3-of-5 evaluator quorum", s[("TrustRegistryQuorum", "update(3 submits)")]["gas_mean"]),
             (f"C  Merkle anchor per {batch} updates", anchor["gas_mean"] / batch)]
    fig, ax = plt.subplots(figsize=(3.5, 1.7))
    y = range(len(items))
    ax.barh(list(y), [v for _, v in items], color=COL["Proposed"], height=0.55)
    for i, (_, v) in enumerate(items):
        ax.text(v + 2500, i, f"{v:,.0f}", va="center", fontsize=6.5, color=INK)
    ax.set_yticks(list(y)); ax.set_yticklabels([n for n, _ in items])
    ax.invert_yaxis()
    ax.set_xlabel("Gas per trust update")
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v/1000:.0f}k"))
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(v for _, v in items) * 1.25)
    save(fig, "fig_gas")


if __name__ == "__main__":
    fig_xz(); fig_eventstream(); fig_cts(); fig_gas()
    print("figures in", FIG)
