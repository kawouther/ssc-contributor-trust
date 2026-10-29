# Contributor trust for software supply chains — code, data and paper

This folder reproduces every table and figure of the revised paper.

```
contracts/TrustRegistry.sol   four on-chain recording designs (A full history, B event log,
                              C Merkle anchoring, D k-of-n evaluator quorum)
evm/harness.py                runs transactions on the official Ethereum execution spec (Prague)
evm/measure_gas.py            gas / storage measurement  -> results/gas_*.{csv,json}
sim/config.py                 ALL model and experiment parameters (edit here, then re-run)
sim/signals.py                observable signals and the evidence functions E1-E4 + risk table
sim/models.py                 Original model of [34], Proposed model, Moving average, Beta reputation
sim/agents.py                 synthetic contributor profiles (calibrated on real git data)
sim/experiments.py            synthetic attacks, collusion, ablation, sensitivity (200 runs)
sim/trajectories.py           per-interaction CTS of every run -> results/per_interaction_cts.csv.gz
                              (gzip-compressed; open with pandas.read_csv or gunzip)
sim/git_extract.py            extracts per-commit signals from a git repository
sim/replay.py                 replays real histories (xz-utils, event-stream, 6 more repos)
sim/tables.py, sim/plots.py   LaTeX tables and figures -> paper/tables, paper/figures
data/                         extracted signals (events_*.jsonl), ground truth, base rates
results/                      every raw result
run_all.py                    regenerates everything
```

## Reproduce

```bash
pip install matplotlib pandas
# 1. clone the repositories analysed
mkdir -p /tmp/repos && cd /tmp/repos
for r in tukaani-project/xz dominictarr/event-stream madler/zlib lz4/lz4 \
         libarchive/libarchive expressjs/express curl/curl facebook/zstd; do
  git clone https://github.com/$r.git; done
# 2. EVM measurement dependencies (only for the gas numbers)
#    - solc 0.8.28 on PATH (https://github.com/ethereum/solc-bin, linux-amd64/)
#    - git clone https://github.com/ethereum/execution-specs, ethereum-types, ethereum-rlp
#      into one folder and set EVM_DEPS=<that folder>.  The evm/shims folders provide a
#      pure-Python keccak and stubs for libraries used only by precompiles we never call.
# 3. run
cd <this folder> && python3 run_all.py              # ~4 minutes
python3 run_all.py --skip-extract --skip-gas         # model/experiment changes only
```

Results are deterministic (fixed seeds). Changing a parameter in `sim/config.py` and re-running
regenerates every table and figure of the paper with the new values.

## Notes and limitations
- CI results are not stored in git; replays assume CI passed. Review is detected from
  committer != author, review trailers, or pull-request references, which under-counts reviews.
- Ground truth for xz-utils comes from the maintainer's own commits e93e13c8 (backdoor removal)
  and f9cf4c05 (sabotaged Landlock check); for event-stream from commit e316336.
- Gas is exact for solc 0.8.28 and the Prague rules. No public-network deployment was made,
  so no transaction hashes or network latency are reported.
