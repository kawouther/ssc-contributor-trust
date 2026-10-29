"""
All parameters of the trust model, the decision policy and the experiments.
Values taken from [34] are marked [34]. Values introduced in this paper are
marked [NEW] and are reported in the parameter table of the paper.
Re-run `python3 run_all.py` after editing; every table and figure is
regenerated from this file.
"""

# --------------------------------------------------------------------------
# Model of [34] as written in the paper (Eqs. 1-5), used as baseline "M34"
# --------------------------------------------------------------------------
M34 = dict(
    eps1=0.8,        # [34] weight of direct (historical) trust, Eq. 6 of [34]
    eps2=0.2,        # [34] weight of indirect trust (reputation), Eq. 6 of [34]
    clip=(-1.0, 1.0) # clipping is NOT in [34]; without it Tr leaves [-1, 1] (Table 4 shows it was applied)
)

# Initial trust, Eq. 1 of [34] (private/targeted community). Public community: Tr(0) = 0 (Eq. 12 of [34]).
# [34] scores Ta, Tc, C in {0,1,2} and beta = G + S in [0,2], so Eq. 1 can exceed 1.
# [NEW] every input is normalised to [0,1] (divide by 2) and beta gets its own weight w5,
#       with w1+...+w5 = 1, so Tr(0) is in [0, 1].
INIT = dict(
    omega=(0.30, 0.15, 0.15, 0.20, 0.20),  # [NEW] w1..w5 for Tp, Ta, Tc, C, beta
)

# --------------------------------------------------------------------------
# Proposed extensions (what is NEW relative to [34] and [35])
# --------------------------------------------------------------------------
PROPOSED = dict(
    eps1=0.8, eps2=0.2,     # [34] same H(t) weights as M34
    alpha_up=0.15,          # evidence weight for non-negative evidence (slow gain / slow drift)
    alpha_down=0.40,        # evidence weight for negative evidence S < 0 (fast loss); chosen by the
                            # sensitivity analysis: 0.6 -> 33% honest flagged at least once, 0.4 -> 4%,
                            # with the same attack exposure
    critical_cap=-0.6,      # trust after a confirmed critical alert (=> restricted, extra review)
    restrict_n=30,          # ... and it stays <= critical_cap for this many interactions (penalty period of [34], Sec. 4.3)
    probation_n=10,         # newcomer probation: first n interactions ...
    probation_cap=0.45,     # ... trust cannot exceed this (stays below Level 2)
    inactivity_halflife_days=180,  # trust decays toward 0 during inactivity (real-data replay)
    rater_min_trust=0.5,    # only Level-2 raters (Tr >= 0.5) carry weight in R(t)
)

# --------------------------------------------------------------------------
# Baselines
# --------------------------------------------------------------------------
BASELINES = dict(
    ma_window=10,           # simple moving average of S(t)
    beta_forget=0.95,       # Beta reputation (Josang & Ismail 2002) forgetting factor
)

# --------------------------------------------------------------------------
# Decision policy (Table 3) - identical for every model
# --------------------------------------------------------------------------
LEVELS = dict(restricted=-0.5, low=0.0, high=0.5)
#   Tr <  -0.5          -> Suspended / restricted
#   -0.5 <= Tr < 0      -> Level 0  : mandatory additional review  ("flagged")
#    0   <= Tr < 0.5    -> Level 1  : standard review + automated checks
#    0.5 <= Tr          -> Level 2  : standard review only ("trusted")

# Evidence functions E1..E4: thresholds Th1 = 0.5, Th4 = 0.5 and the 0-10 risk
# table are defined in signals.py (they are part of the model, not tunables).

# --------------------------------------------------------------------------
# Synthetic experiments
# --------------------------------------------------------------------------
EXPERIMENT = dict(
    runs=200,               # independent repetitions (seeds)
    horizon=200,            # interactions per contributor
    community=50,           # community size N
    reviewers_per_interaction=3,  # platform-assigned reviewers per contribution
    p_observable=(0.0, 0.25, 0.5, 0.75, 1.0),  # prob. a malicious act leaves a detectable signal
    longcon_warmup=100,     # honest interactions before a sleeper turns malicious
    onoff_attack_threshold=0.5,   # adaptive attacker strikes only while trusted (Level 2)
    collusion_ring=(2, 5, 10),    # Sybil ring sizes
)
