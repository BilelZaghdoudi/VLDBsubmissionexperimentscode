"""
run_experiments.py

Runs the parameter sweeps behind the figures of the VERDICT paper (Section 7)
by invoking evaluate_secure_lineage.py and evaluate_skip_insertion.py.

Results are written under results/<experiment>/ and can be plotted with
plot_results.py.

Usage:
    python run_experiments.py                  # full sweeps (paper settings, long)
    python run_experiments.py --quick          # small smoke run (a few minutes)
    python run_experiments.py --only nodes --runs 5 --max-nodes 5000
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Sweeps follow the ranges reported in Section 7.1 of the paper.
FULL = {
    "nodes":     {"nodes": [1000, 2500, 5000, 7500, 10000, 15000, 20000], "genesis": [50], "edges": [10]},
    "genesis":   {"nodes": [2000], "genesis": [50, 100, 200, 300, 400, 500], "edges": [10]},
    "edges":     {"nodes": [1000], "genesis": [50], "edges": [10, 15, 20, 25]},
    "insertion": {"nodes": [1000, 2500, 5000, 7500, 10000, 15000, 20000], "genesis": [50], "edges": [10]},
}
QUICK = {
    "nodes":     {"nodes": [200, 400, 800], "genesis": [10], "edges": [5]},
    "genesis":   {"nodes": [400], "genesis": [10, 20, 40], "edges": [5]},
    "edges":     {"nodes": [300], "genesis": [10], "edges": [3, 5, 8]},
    "insertion": {"nodes": [200, 400, 800], "genesis": [10], "edges": [5]},
}


def run(cmd):
    cmd = [str(c) for c in cmd]
    print("  $", " ".join(cmd), flush=True)
    t0 = time.perf_counter()
    subprocess.run(cmd, check=True, cwd=HERE, stdout=subprocess.DEVNULL)
    print(f"    done in {time.perf_counter() - t0:.1f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run the VERDICT evaluation sweeps")
    parser.add_argument("--quick", action="store_true", help="Small configuration for a smoke test")
    parser.add_argument("--only", choices=sorted(FULL), nargs="+", help="Run only these experiments")
    parser.add_argument("--runs", type=int, default=None, help="Repetitions per configuration (paper: 32)")
    parser.add_argument("--max-nodes", type=int, default=None, help="Skip configurations above this size")
    parser.add_argument("--buckets", type=int, default=4, help="Buckets per level")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed")
    parser.add_argument("--out", type=str, default="results", help="Output directory")
    args = parser.parse_args()

    grid = QUICK if args.quick else FULL
    runs = args.runs if args.runs is not None else (2 if args.quick else 32)
    out = (HERE / args.out).resolve()

    for name in args.only or list(grid):
        cfg = grid[name]
        exp_dir = out / name
        exp_dir.mkdir(parents=True, exist_ok=True)
        print(f"[{name}] -> {exp_dir}")
        for n in cfg["nodes"]:
            if args.max_nodes and n > args.max_nodes:
                print(f"  skipping nodes={n} (> --max-nodes)")
                continue
            for g in cfg["genesis"]:
                for e in cfg["edges"]:
                    if name == "insertion":
                        run([sys.executable, "evaluate_skip_insertion.py",
                             "--nodes", n, "--genesis", g, "--edges", e,
                             "--insertions", runs, "--buckets", args.buckets,
                             "--seed", args.seed, "--out", exp_dir])
                    else:
                        run([sys.executable, "evaluate_secure_lineage.py",
                             "--runs", runs, "--nodes", n, "--genesis", g, "--edges", e,
                             "--buckets", args.buckets,
                             "--seed", args.seed, "--out", exp_dir])
    print(f"\nAll experiments finished. Plot with: python plot_results.py --results {args.out}")


if __name__ == "__main__":
    main()
