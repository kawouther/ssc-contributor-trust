"""Regenerate every result, table and figure of the paper.

    python3 run_all.py            # full run (200 repetitions)
    python3 run_all.py --quick    # 20 repetitions, for a smoke test

Requires: Python 3.10+, matplotlib, pandas; git repositories cloned under
REPOS_DIR (default /tmp/repos) for the replay; solc 0.8.28 and the Ethereum
execution-specs checkout (see evm/README) for the gas measurements.
"""
import os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOS = os.environ.get("REPOS_DIR", "/tmp/repos")
REPO_LIST = ["xz", "event-stream", "zlib", "lz4", "express", "libarchive", "zstd", "curl"]
quick = "--quick" in sys.argv


def run(*cmd, cwd=ROOT):
    print("$", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


if "--skip-extract" not in sys.argv:
    for r in REPO_LIST:
        if Path(REPOS, r).exists():
            run(sys.executable, "sim/git_extract.py", f"{REPOS}/{r}", f"data/events_{r}.jsonl")
run(sys.executable, "experiments.py", *(["--quick"] if quick else []), cwd=ROOT / "sim")
run(sys.executable, "trajectories.py", cwd=ROOT / "sim")
run(sys.executable, "replay.py", cwd=ROOT / "sim")
if "--skip-gas" not in sys.argv:
    run("solc", "--optimize", "--optimize-runs", "200", "--evm-version", "prague", "--combined-json",
        "abi,bin,bin-runtime,hashes", "TrustRegistry.sol", "-o", "build", "--overwrite", cwd=ROOT / "contracts")
    run(sys.executable, "evm/measure_gas.py", "--contributors", "20", "--updates", "50", "--batch", "1024")
run(sys.executable, "tables.py", cwd=ROOT / "sim")
run(sys.executable, "plots.py", cwd=ROOT / "sim")
