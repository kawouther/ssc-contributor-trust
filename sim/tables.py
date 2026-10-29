"""Generate the LaTeX tables of Section 6 from results/* (writes paper/tables/*.tex)."""
import csv, json
from collections import defaultdict
from pathlib import Path

import pandas as pd

from config import M34 as P34, PROPOSED as PP, INIT, LEVELS, EXPERIMENT as X

ROOT = Path(__file__).resolve().parents[1]
RES, TAB = ROOT / "results", ROOT / "paper/tables"
TAB.mkdir(parents=True, exist_ok=True)
NAME = {"M34": "Original model", "MovingAvg": "Moving avg.", "BetaRep": "Beta rep.", "Proposed": "Proposed"}
ORDER = ["M34", "MovingAvg", "BetaRep", "Proposed"]
KEY = {}


def ms(c, pct=False, d=2):
    if c is None or c["mean"] is None: return "--"
    k = 100 if pct else 1
    if pct: return f"{c['mean']*k:.1f}"
    return f"{c['mean']:.{d}f} $\\pm$ {c['sd']:.{d}f}"


def write(name, body):
    # scale every tabular to the text width so wide tables never overflow
    body = body.replace("\\begin{tabular}", "\\begin{adjustbox}{max width=\\linewidth}\n\\begin{tabular}")
    body = body.replace("\\end{tabular}", "\\end{tabular}\n\\end{adjustbox}")
    body = body.replace("\\begin{table}[t]", "\\begin{table}[htbp]").replace("\\begin{table*}[t]", "\\begin{table*}[htbp]")
    (TAB / f"{name}.tex").write_text(body)


# ------------------------------------------------------------ parameters
def t_params():
    rows = [
        (r"$\epsilon_1,\ \epsilon_2$", f"{P34['eps1']}, {P34['eps2']}", "weights of direct and indirect trust in $H_i(t)$", "\\cite{bennaceur2026multidim}"),
        (r"$w_1..w_5$", ", ".join(f"{w:.2f}" for w in INIT["omega"]), r"weights of $T_p, T_a, T_c, C, \beta$ in $Tr_i(0)$ (inputs normalised to $[0,1]$)", "new"),
        (r"$Th_1$, $Th_4$", "0.5, 0.5", r"thresholds of $E_1$ and $E_4$", "\\cite{bennaceur2026multidim} (form)"),
        (r"risk $\geq 7$", "Table~\\ref{tab:risk}", r"$E_3=-1$ if the contribution risk is high or critical", "\\cite{bennaceur2026multidim}"),
        (r"$\alpha_{up}$", f"{PP['alpha_up']}", r"evidence weight when $S_i(t)\geq 0$ (slow gain)", "new"),
        (r"$\alpha_{down}$", f"{PP['alpha_down']}", r"evidence weight when $S_i(t)<0$ (fast loss)", "new"),
        (r"$\tau_{crit}$, $n_{restr}$", f"{PP['critical_cap']}, {PP['restrict_n']}", "cap and duration (interactions) after a confirmed critical alert", "new (period: \\cite{bennaceur2026multidim})"),
        (r"$n_{prob}$, $\tau_{prob}$", f"{PP['probation_n']}, {PP['probation_cap']}", "newcomer probation: length and trust cap", "new"),
        (r"$h$", f"{PP['inactivity_halflife_days']} days", "half-life of trust during inactivity", "new"),
        (r"$\theta_{rater}$", f"{PP['rater_min_trust']}", r"minimum trust for a rating to count in $\bar R_i$", "new"),
        ("Levels", "$-0.5,\\ 0,\\ 0.5$", "boundaries of Restricted / Level 0 / 1 / 2", "Table~\\ref{tab:levels}"),
    ]
    body = ["\\begin{table}[t]\\centering\\small",
            "\\caption{All parameters of the trust model. a citation marks values taken unchanged from \\cite{bennaceur2026multidim}; ``new'' marks parameters introduced here, whose values were fixed by the sensitivity analysis of Section~\\ref{sec:sensitivity}.}",
            "\\label{tab:params}", "\\begin{tabular}{@{}llp{6.2cm}l@{}}", "\\toprule",
            "Symbol & Value & Meaning & Source\\\\", "\\midrule"]
    body += [" & ".join(r) + "\\\\" for r in rows]
    body += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_params", "\n".join(body))


# ------------------------------------------------------------ synthetic main
def t_synthetic():
    res = json.load(open(RES / "synthetic_main.json"))
    by = {(r["scenario"], r["model"], r["p_obs"], r["private"]): r for r in res}
    p = 0.5
    lines = ["\\begin{table*}[t]\\centering\\small",
             f"\\caption{{Synthetic evaluation, public community, {X['runs']} runs of {X['horizon']} interactions per cell, "
             f"probability that a malicious act raises a confirmed alert $p_{{obs}}={p}$. "
             "Exposure = malicious contributions submitted while the author was at Level~2 (mean $\\pm$ s.d.). "
             "Detected = share of runs in which the attacker was flagged (CTS $<0$) after its first attack; "
             "TTD = interactions from the first attack to the first flag (mean over detected runs).}",
             "\\label{tab:synthetic}",
             "\\begin{tabular}{@{}lcccccccc@{}}", "\\toprule",
             " & \\multicolumn{3}{c}{Honest} & Careless & \\multicolumn{2}{c}{Long-con} & On-off & Whitewashing\\\\",
             "\\cmidrule(lr){2-4}\\cmidrule(lr){5-5}\\cmidrule(lr){6-7}\\cmidrule(lr){8-8}\\cmidrule(lr){9-9}",
             "Model & flagged$^a$ (\\%) & extra review (\\%) & at L2 (\\%) & at L2 (\\%) & exposure & TTD & exposure & exposure\\\\",
             "\\midrule"]
    for m in ORDER:
        h, c = by[("honest", m, None, False)], by[("careless", m, None, False)]
        lc, oo, ww = by[("longcon", m, p, False)], by[("onoff", m, p, False)], by[("whitewash", m, p, False)]
        ttd = f"{lc['ttd']['mean']:.1f} ({lc['detected']['mean']*100:.0f}\\%)" if lc["ttd"]["mean"] is not None else f"-- (0\\%)"
        lines.append(f"{NAME[m]} & {h['fp_ever']['mean']*100:.1f} & {h['burden']['mean']*100:.2f} & {h['frac_L2']['mean']*100:.1f} & "
                     f"{c['frac_L2']['mean']*100:.1f} & {ms(lc['exposure'],d=1)} & {ttd} & {ms(oo['exposure'],d=1)} & {ms(ww['exposure'],d=1)}\\\\")
        KEY[f"syn_{m}"] = dict(honest_flag=h['fp_ever']['mean'], honest_burden=h['burden']['mean'], honest_L2=h['frac_L2']['mean'],
                              careless_L2=c['frac_L2']['mean'], longcon_exp=lc['exposure']['mean'], longcon_det=lc['detected']['mean'],
                              longcon_ttd=lc['ttd']['mean'], onoff_exp=oo['exposure']['mean'], ww_exp=ww['exposure']['mean'],
                              ww_ident=by[("whitewash", m, p, False)].get("identities", {}).get("mean"),
                              mal_exp=by[("malicious", m, p, False)]['exposure']['mean'],
                              mal_acts=by[("malicious", m, p, False)]['malicious_acts']['mean'],
                              longcon_acts=lc['malicious_acts']['mean'], onoff_acts=oo['malicious_acts']['mean'])
    lines += ["\\bottomrule", "\\end{tabular}",
              "\\\\[2pt]\\footnotesize $^a$ flagged (CTS $<0$) at least once after a 10-interaction warm-up.",
              "\\end{table*}"]
    write("tab_synthetic", "\n".join(lines))

    # exposure vs p_obs
    lines = ["\\begin{table}[t]\\centering\\small",
             "\\caption{Long-con attacker: exposure (mean) and detection rate as a function of $p_{obs}$, the probability that a malicious act raises a confirmed alert.}",
             "\\label{tab:pobs}", "\\begin{tabular}{@{}l" + "c" * len(X["p_observable"]) + "@{}}", "\\toprule",
             "Model & " + " & ".join(f"$p_{{obs}}={q}$" for q in X["p_observable"]) + "\\\\", "\\midrule"]
    for m in ORDER:
        cells = []
        for q in X["p_observable"]:
            r = by[("longcon", m, q, False)]
            cells.append(f"{r['exposure']['mean']:.1f} / {r['detected']['mean']*100:.0f}\\%")
        lines.append(f"{NAME[m]} & " + " & ".join(cells) + "\\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_pobs", "\n".join(lines))


def t_ablation():
    res = json.load(open(RES / "synthetic_ablation.json"))
    by = defaultdict(dict)
    for r in res: by[r["model"]][r["scenario"]] = r
    lines = ["\\begin{table}[t]\\centering\\small",
             "\\caption{Ablation of the proposed extensions ($p_{obs}=0.5$). Each row removes one extension or replaces the reputation aggregator.}",
             "\\label{tab:ablation}", "\\begin{tabular}{@{}lcccc@{}}", "\\toprule",
             "Variant & Honest flagged (\\%) & Long-con exp. & On-off exp. & Whitewash exp.\\\\", "\\midrule"]
    for m, d in by.items():
        if m.startswith("rep:"):   # reputation aggregators only matter with ratings -> Table collusion
            continue
        lines.append(f"{m} & {d['honest']['fp_ever']['mean']*100:.1f} & {d['longcon']['exposure']['mean']:.2f} & "
                     f"{d['onoff']['exposure']['mean']:.2f} & {d['whitewash']['exposure']['mean']:.2f}\\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_ablation", "\n".join(lines))
    KEY["ablation"] = {m: {s: d[s]["exposure" if s != "honest" else "fp_ever"]["mean"] for s in d} for m, d in by.items()}


def t_collusion():
    res = json.load(open(RES / "synthetic_collusion.json"))
    lines = ["\\begin{table}[t]\\centering\\small",
             f"\\caption{{Bad-mouthing by a Sybil ring against an honest newcomer in a community of {X['community']} members "
             f"({X['reviewers_per_interaction']} assigned reviewers per contribution, 100 rounds). Cells: target's mean CTS / share of rounds in which the target is flagged.}}",
             "\\label{tab:collusion}", "\\begin{tabular}{@{}llcccc@{}}", "\\toprule",
             "Rating policy & Model & " + " & ".join(f"ring = {k}" for k in (0,) + tuple(X["collusion_ring"])) + "\\\\", "\\midrule"]
    by = defaultdict(dict)
    for r in res: by[(r["policy"], r["model"])][r["ring"]] = r
    for (pol, m), d in by.items():
        cells = [f"{d[k]['target_mean']['mean']:.2f} / {d[k]['target_flag_rate']['mean']*100:.0f}\\%" for k in sorted(d)]
        lines.append(f"{pol} & {m.replace('M34','Original model')} & " + " & ".join(cells) + "\\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_collusion", "\n".join(lines))
    KEY["collusion"] = {f"{p}|{m}": {k: (d[k]['target_mean']['mean'], d[k]['target_flag_rate']['mean']) for k in d} for (p, m), d in by.items()}


def t_sensitivity():
    res = json.load(open(RES / "synthetic_sensitivity.json"))
    lines = ["\\begin{table}[t]\\centering\\small",
             "\\caption{One-at-a-time sensitivity of the new parameters ($p_{obs}=0.5$, 100 runs). Bold: value used.}",
             "\\label{tab:sensitivity}", "\\begin{tabular}{@{}llccccc@{}}", "\\toprule",
             "Param. & Value & Honest flagged (\\%) & Honest at L2 (\\%) & Long-con exp. & On-off exp. & Whitewash exp.\\\\", "\\midrule"]
    for r in res:
        v = f"\\textbf{{{r['value']}}}" if r["is_default"] else f"{r['value']}"
        lines.append(f"\\texttt{{{r['param'].replace('_','\\_')}}} & {v} & {r['honest_fp_ever']*100:.1f} & {r['honest_frac_L2']*100:.1f} & "
                     f"{r['longcon_exposure']:.2f} & {r['onoff_exposure']:.2f} & {r['whitewash_exposure']:.2f}\\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_sensitivity", "\n".join(lines))


# ------------------------------------------------------------ replay
def t_replay():
    rep = json.load(open(RES / "replay_attacks.json"))
    lines = ["\\begin{table*}[t]\\centering\\small",
             "\\caption{Replay of two real attacks. Review level each malicious commit would have received (level and CTS of its author \\emph{before} the commit). "
             "L2 = standard review only; L1 = standard review + automated checks; L0 = mandatory additional review; R = restricted.}",
             "\\label{tab:replay}", "\\begin{tabular}{@{}lllcccc@{}}", "\\toprule",
             "Signals & Commit & Date & Original model & Moving avg. & Beta rep. & Proposed\\\\", "\\midrule"]
    LV = {"L2": "L2", "L1": "L1", "L0": "L0", "restricted": "R"}
    for r in rep:
        tag = {"git signals only": "git only", "git signals + release-tarball reproducibility check": "git + tarball check"}[r["scenario"]]
        for a, rec in r["attackers"].items():
            for x in rec["malicious"]:
                cells = [f"{LV[x['level_at_submission'][m]]} ({x['score_before'][m]:.2f})" for m in ORDER]
                lines.append(f"{r['repo']}: {tag} & \\texttt{{{x['sha']}}} & {x['date']} & " + " & ".join(cells) + "\\\\")
                KEY[f"replay|{r['repo']}|{tag}|{x['sha']}"] = {m: (x['level_at_submission'][m], x['score_before'][m]) for m in ORDER}
            KEY[f"replay_flag|{r['repo']}|{tag}|{a}"] = rec["first_flag_before_discovery"]
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    write("tab_replay", "\n".join(lines))

    pop = pd.read_csv(RES / "replay_population.csv")
    g = pop.groupby("model").agg(n=("author", "count"), commits=("commits", "sum"), flag=("ever_flagged", "mean"),
                                 restr=("ever_restricted", "mean"), extra=("frac_extra_review", "mean"),
                                 L2=("frac_L2", "mean"), toL2=("commits_to_L2", "median"))
    nrepo = pop["repo"].nunique()
    lines = ["\\begin{table}[t]\\centering\\small",
             f"\\caption{{False positives on {int(g.loc['Proposed','n'])} presumed-honest contributors (at least 10 commits; attackers excluded) from {nrepo} real repositories "
             f"({int(g.loc['Proposed','commits']):,} commits). Extra review = share of commits submitted at Level 0 or below, after the first 10.}}",
             "\\label{tab:population}", "\\begin{tabular}{@{}lcccc@{}}", "\\toprule",
             "Model & Ever flagged (\\%) & Extra review (\\%) & At L2 (\\%) & Commits to L2 (median)\\\\", "\\midrule"]
    for m in ORDER:
        x = g.loc[m]
        lines.append(f"{NAME[m]} & {x['flag']*100:.1f} & {x['extra']*100:.2f} & {x['L2']*100:.1f} & {x['toL2']:.0f}\\\\")
        KEY[f"pop_{m}"] = dict(n=int(x['n']), commits=int(x['commits']), flag=x['flag'], extra=x['extra'], L2=x['L2'], toL2=x['toL2'])
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write("tab_population", "\n".join(lines))


# ------------------------------------------------------------ gas
def t_gas():
    g = json.load(open(RES / "gas_summary.json"))
    s = {(r["design"], r["op"]): r for r in g["summary"]}
    B = g["args"]["batch"]
    anchor = next(r for (d, op), r in s.items() if d == "TrustAnchorBatch" and op.startswith("anchor"))
    verify = next(r for (d, op), r in s.items() if d == "TrustAnchorBatch" and op.startswith("verify"))
    designs = [
        ("A: full history in storage", "TrustRegistryFull", s[("TrustRegistryFull", "register")]["gas_mean"], s[("TrustRegistryFull", "update")], 64),
        ("B: latest score + event log", "TrustRegistryEvent", s[("TrustRegistryEvent", "register")]["gas_mean"], s[("TrustRegistryEvent", "update")], 0),
        ("C: Merkle anchor per epoch", "TrustAnchorBatch", None, {"gas_mean": anchor["gas_mean"] / B, "gas_sd": 0}, 64 / B),
        ("D: B + 3-of-5 evaluator quorum", "TrustRegistryQuorum", s[("TrustRegistryQuorum", "register")]["gas_mean"], s[("TrustRegistryQuorum", "update(3 submits)")], 0),
    ]
    workloads = [("zstd", 416), ("curl", 3477)]
    lines = ["\\begin{table*}[t]\\centering\\small",
             "\\caption{Measured cost of the on-chain layer (Solidity 0.8.28, optimiser 200 runs, executed on the Ethereum execution specification, Prague rules). "
             f"Gas per update averaged over {s[('TrustRegistryFull','update')]['n']} updates (20 contributors $\\times$ 50). "
             f"Design C anchors one Merkle root per epoch of {B} updates ({anchor['gas_mean']:,} gas per anchor); verifying one record costs {verify['gas_mean']:,} gas as a call. "
             f"Recording the 3 reviewers assigned to a contribution costs {s[('All designs','assignReviewers(3)')]['gas_mean']:,} gas in every design; a correction costs {s[('TrustRegistryEvent','correction')]['gas_mean']:,} (B) to {s[('TrustRegistryFull','correction')]['gas_mean']:,} (A) gas. "
             "Yearly cost = commits per year $\\times$ gas per update, in ETH at 1 and 10 gwei.}",
             "\\label{tab:gas}", "\\begin{tabular}{@{}lrrrrrrr@{}}", "\\toprule",
             " & Deploy & Register & Update & Storage & \\multicolumn{2}{c}{zstd, 416 commits/yr} & curl, 3,477 commits/yr\\\\",
             "\\cmidrule(lr){6-7}\\cmidrule(lr){8-8}",
             "Design & (gas) & (gas) & (gas, mean $\\pm$ s.d.) & (B/update) & 1 gwei & 10 gwei & 10 gwei\\\\", "\\midrule"]
    KEY["gas"] = {}
    for name, d, reg, upd, stor in designs:
        dep = s[(d, "deploy")]["gas_mean"]
        u = upd["gas_mean"]
        cost = lambda n, gw: n * u * gw * 1e-9
        lines.append(f"{name} & {dep:,} & {reg:,}" if reg else f"{name} & {dep:,} & --")
        lines[-1] += f" & {u:,.0f} $\\pm$ {upd['gas_sd']:,} & {stor:g} & {cost(416,1):.4f} & {cost(416,10):.4f} & {cost(3477,10):.3f}\\\\"
        KEY["gas"][name] = dict(deploy=dep, register=reg, update=u, sd=upd["gas_sd"], storage=stor)
    KEY["gas"]["verify"] = verify["gas_mean"]; KEY["gas"]["anchor"] = anchor["gas_mean"]
    KEY["gas"]["assign3"] = s[("All designs", "assignReviewers(3)")]["gas_mean"]
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    write("tab_gas", "\n".join(lines))


if __name__ == "__main__":
    t_params(); t_synthetic(); t_ablation(); t_collusion(); t_replay(); t_gas()
    if (RES / "synthetic_sensitivity.json").exists(): t_sensitivity()
    json.dump(KEY, open(RES / "key_numbers.json", "w"), indent=1, ensure_ascii=False, default=float)
    print("tables in", TAB)
