"""
Measure gas, storage growth and execution time of the four recording designs.

Usage:  python3 evm/measure_gas.py  [--contributors 20 --updates 50]
Output: results/gas_*.csv, results/gas_summary.json
"""
from __future__ import annotations

import argparse, csv, json, math, random, statistics as st
from pathlib import Path

from harness import Chain, encode_call, load_build, keccak256

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "contracts/build/combined.json"
OUT = ROOT / "results"

ADMIN = b"\xaa" * 20
EVALS = [bytes([0xe0 + i]) * 20 for i in range(5)]


def pid(i: int) -> bytes:                    # pseudonymous id = keccak(account || salt)
    return bytes(keccak256(f"github:user{i}|salt".encode()))


def ev(i: int, j: int) -> bytes:             # evidence hash
    return bytes(keccak256(f"evidence:{i}:{j}".encode()))


def deploy(chain, build, name, ctor_args=b""):
    r = chain.send(ADMIN, None, bytes.fromhex(build[name]["bin"]) + ctor_args)
    assert r.success, name
    return r


def call(chain, sender, addr, sig, *a):
    r = chain.send(sender, addr, encode_call(sig, *a))
    if not r.success:
        raise RuntimeError(f"{sig} reverted")
    return r


def merkle(leaves):
    """Sorted-pair Merkle tree, same rule as TrustAnchorBatch.verify."""
    layers = [leaves]
    while len(layers[-1]) > 1:
        cur, nxt = layers[-1], []
        for i in range(0, len(cur), 2):
            a = cur[i]; b = cur[i + 1] if i + 1 < len(cur) else cur[i]
            lo, hi = sorted([a, b])
            nxt.append(bytes(keccak256(lo + hi)))
        layers.append(nxt)
    return layers


def proof(layers, idx):
    p = []
    for layer in layers[:-1]:
        sib = idx ^ 1
        p.append(layer[sib] if sib < len(layer) else layer[idx])
        idx //= 2
    return p


def summarize(xs):
    return {"mean": st.mean(xs), "sd": st.pstdev(xs), "min": min(xs), "max": max(xs), "n": len(xs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contributors", type=int, default=20)
    ap.add_argument("--updates", type=int, default=50)
    ap.add_argument("--batch", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    build = load_build(BUILD)
    OUT.mkdir(exist_ok=True)

    rows = []  # design, op, gas, intrinsic, ms
    def log(design, op, r):
        rows.append({"design": design, "op": op, "gas": r.gas_used,
                     "intrinsic": r.intrinsic, "exec_ms": round(r.wall_ms, 2)})

    chain = Chain()
    chain.fund(ADMIN)
    for e in EVALS:
        chain.fund(e)

    # ---------------- deployments
    addr = {}
    for name in ["TrustRegistryFull", "TrustRegistryEvent", "TrustAnchorBatch"]:
        r = deploy(chain, build, name); addr[name] = r.created; log(name, "deploy", r)
    r = deploy(chain, build, "TrustRegistryQuorum", (3).to_bytes(32, "big"))
    addr["TrustRegistryQuorum"] = r.created; log("TrustRegistryQuorum", "deploy", r)
    for e in EVALS:
        for name in ["TrustRegistryFull", "TrustRegistryEvent", "TrustAnchorBatch", "TrustRegistryQuorum"]:
            call(chain, ADMIN, addr[name], "setEvaluator(address,bool)", e.rjust(32, b"\0")[-32:].rjust(32, b"\0"), 1)

    # ---------------- A / B / D : register + per-interaction updates
    for i in range(args.contributors):
        for name in ["TrustRegistryFull", "TrustRegistryEvent", "TrustRegistryQuorum"]:
            log(name, "register", call(chain, ADMIN, addr[name], "register(bytes32,int16,bytes32)", pid(i), 0, ev(i, 0)))

    final = {}
    for j in range(1, args.updates + 1):
        for i in range(args.contributors):
            score = rng.randint(-1000, 1000)
            final[i] = score
            for name in ["TrustRegistryFull", "TrustRegistryEvent"]:
                log(name, "update", call(chain, EVALS[0], addr[name], "recordUpdate(bytes32,int16,bytes32)", pid(i), score, ev(i, j)))
            # quorum: 3 evaluators submit (small disagreement); median is recorded
            tot = 0
            for e, d in zip(EVALS[:3], (-5, 0, 5)):
                r = call(chain, e, addr["TrustRegistryQuorum"], "submit(bytes32,int16,bytes32)", pid(i), max(-1000, min(1000, score + d)), ev(i, j))
                log("TrustRegistryQuorum", "submit", r); tot += r.gas_used
            rows.append({"design": "TrustRegistryQuorum", "op": "update(3 submits)", "gas": tot, "intrinsic": 0, "exec_ms": 0})

    # corrections (appeal upheld)
    for i in range(min(5, args.contributors)):
        log("TrustRegistryFull", "correction", call(chain, ADMIN, addr["TrustRegistryFull"], "recordCorrection(bytes32,uint32,int16,bytes32)", pid(i), 3, 100, ev(i, 999)))
        log("TrustRegistryEvent", "correction", call(chain, ADMIN, addr["TrustRegistryEvent"], "recordCorrection(bytes32,uint32,int16,bytes32)", pid(i), 3, 100, ev(i, 999)))

    # reviewer assignment: 3 platform-assigned reviewers per contribution (Eq. 8)
    for i in range(args.contributors):
        revs = [pid((i + k) % args.contributors) for k in (1, 2, 3)]
        r = call(chain, EVALS[0], addr["TrustRegistryEvent"], "assignReviewers(bytes32,bytes32,bytes32[])", pid(i), ev(i, 777), revs)
        log("All designs", "assignReviewers(3)", r)
        assert len(r.logs) == 1, "assignment event missing"
    # corrections on the quorum design
    for i in range(min(5, args.contributors)):
        log("TrustRegistryQuorum", "correction", call(chain, ADMIN, addr["TrustRegistryQuorum"], "recordCorrection(bytes32,uint32,int16,bytes32)", pid(i), 3, 100, ev(i, 999)))

    # correctness check: latest() equals last written score (design A)
    for i in range(args.contributors):
        if i < 5:
            continue  # corrected ones differ on purpose
        r = chain.send(ADMIN, addr["TrustRegistryFull"], encode_call("latest(bytes32)", pid(i)))
        got = int.from_bytes(r.output[:32], "big", signed=True)
        assert got == final[i], (i, got, final[i])

    # ---------------- C : Merkle anchoring
    leaves = [bytes(keccak256(pid(i % args.contributors) + j.to_bytes(32, "big") + ev(i, j)))
              for j, i in enumerate(range(args.batch))]
    layers = merkle(leaves)
    root = layers[-1][0]
    for epoch in range(1, 11):
        log("TrustAnchorBatch", f"anchor({args.batch} records)", call(chain, EVALS[0], addr["TrustAnchorBatch"], "anchor(uint64,bytes32,uint32)", epoch, root, args.batch))
    ver_ok = 0
    for idx in rng.sample(range(args.batch), 20):
        p = proof(layers, idx)
        r = chain.send(ADMIN, addr["TrustAnchorBatch"], encode_call("verify(uint64,bytes32,bytes32[])", 1, leaves[idx], p))
        ver_ok += int.from_bytes(r.output[:32], "big")
        log("TrustAnchorBatch", f"verify(proof={len(p)})", r)
    assert ver_ok == 20, "merkle verification failed"
    # tampered leaf must fail
    bad = bytearray(leaves[0]); bad[0] ^= 1
    r = chain.send(ADMIN, addr["TrustAnchorBatch"], encode_call("verify(uint64,bytes32,bytes32[])", 1, bytes(bad), proof(layers, 0)))
    assert int.from_bytes(r.output[:32], "big") == 0

    # ---------------- write
    with open(OUT / "gas_raw.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    groups = {}
    for r in rows:
        groups.setdefault((r["design"], r["op"]), []).append(r)
    summary = []
    for (d, op), rs in groups.items():
        g = summarize([x["gas"] for x in rs])
        ms = [x["exec_ms"] for x in rs if x["exec_ms"]]
        summary.append({"design": d, "op": op, "n": g["n"], "gas_mean": round(g["mean"]), "gas_sd": round(g["sd"]),
                        "gas_min": g["min"], "gas_max": g["max"],
                        "spec_exec_ms_mean": round(st.mean(ms), 1) if ms else None})
    with open(OUT / "gas_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0])); w.writeheader(); w.writerows(summary)

    # storage growth (bytes of contract storage, from the layouts in TrustRegistry.sol)
    storage = {
        "TrustRegistryFull":   {"per_contributor": 32, "per_update": 64},   # array length slot + 2-slot record
        "TrustRegistryEvent":  {"per_contributor": 32, "per_update": 0},    # 1 slot, overwritten
        "TrustRegistryQuorum": {"per_contributor": 32 + 32 * 3, "per_update": 0},  # state + vote marks (reused)
        "TrustAnchorBatch":    {"per_contributor": 0, "per_update": 64 / args.batch},  # 2 slots per epoch
    }
    json.dump({"args": vars(args), "storage_bytes": storage, "summary": summary,
               "checks": {"latest_matches_last_write": True, "merkle_verify_ok": ver_ok, "tampered_leaf_rejected": True}},
              open(OUT / "gas_summary.json", "w"), indent=2)
    for s in summary:
        print(f'{s["design"]:22s} {s["op"]:24s} n={s["n"]:5d} gas={s["gas_mean"]:>9,} ±{s["gas_sd"]:<6,} exec={s["spec_exec_ms_mean"]} ms')


if __name__ == "__main__":
    main()
