"""
evaluate_secure_lineage.py

Experimental evaluation of VERDICT for one configuration (Section 7).
For both the Data DAG and the Event DAG it measures:
  - skip DAG construction: ECMH level hashing, signed level hashes and
    skip edges, timed separately for each DAG                  (Fig. 2)
  - skip search: path reconstruction from L_1 to a target level (Fig. 4)
  - skip verification: Algorithm 3, phases 1-2                (Figs. 5, 8, 9)
  - bucket Merkle construction for all levels                  (Fig. 6)
  - Merkle membership verification: Algorithm 3, phase 3       (Fig. 7)
  - skip DAG diversity: entropy of skip-edge lengths           (Fig. 1)
plus full and cross-DAG verification and correctness counters.

Results are appended to <out>/evaluation_log.csv, one row per run.

Usage:
    python evaluate_secure_lineage.py --runs 10 --nodes 1000 --genesis 10 --edges 5 --buckets 4
"""
import argparse
import random
import time
from collections import Counter
from math import log2
from pathlib import Path

import pandas as pd

from secure_lineage_system import (
    Verdict, binary_descent_path, extract_event_dag, generate_data_dag,
    link_producing_events, reconstruct_path, verify_cross_dag,
)

TRIALS = 10


def calculate_entropy(distribution):
    total = sum(distribution.values())
    return -sum((c / total) * log2(c / total) for c in distribution.values()) if total else 0.0


def ms(seconds):
    return round(seconds * 1000, 6)


def evaluate_dag(verdict, prefix, row):
    dag = verdict.dag

    t = time.perf_counter()
    verdict.build_skip_dag()
    row[f"{prefix}_skip_dag_time_ms"] = ms(time.perf_counter() - t)

    t = time.perf_counter()
    verdict.build_merkle()
    row[f"{prefix}_merkle_time_ms"] = ms(time.perf_counter() - t)

    t = time.perf_counter()
    verdict.sign_all_paths()
    row[f"{prefix}_path_signing_time_ms"] = ms(time.perf_counter() - t)

    n = verdict.n
    row[f"{prefix}_levels"] = n
    row[f"{prefix}_edges"] = dag.graph.number_of_edges()
    row[f"{prefix}_skip_edges"] = verdict.skip.number_of_edges()
    row[f"{prefix}_skip_diversity"] = round(calculate_entropy(Counter(v - u for u, v in verdict.skip.edges())), 3)

    search = 0.0
    for _ in range(TRIALS):
        j = random.randint(1, n)
        t = time.perf_counter()
        reconstruct_path(verdict.skip, j)
        search += time.perf_counter() - t
    row[f"avg_{prefix}_skip_search_time_ms"] = ms(search / TRIALS)

    ids = sorted(dag.level_map)
    sample = [dag.elements[random.choice(ids)] for _ in range(TRIALS)]
    skip_t = merkle_t = 0.0
    skip_fail = merkle_fail = 0
    max_path = bound_violations = 0
    for x in sample:
        t = time.perf_counter()
        ok = verdict.verify_path(x)
        skip_t += time.perf_counter() - t
        skip_fail += not ok

        t = time.perf_counter()
        ok = verdict.verify_membership(x)
        merkle_t += time.perf_counter() - t
        merkle_fail += not ok

        j = x.proof["level"]
        length = len(binary_descent_path(j))
        max_path = max(max_path, length)
        bound_violations += length > j.bit_length()   # bound: floor(log2 j) + 1

    row[f"{prefix}_verification_time_ms"] = ms(skip_t / TRIALS)
    row[f"{prefix}_merkle_verification_time_ms"] = ms(merkle_t / TRIALS)
    row[f"{prefix}_signature_failures"] = skip_fail
    row[f"{prefix}_merkle_verification_failures"] = merkle_fail
    row[f"{prefix}_max_path_length"] = max_path
    row[f"{prefix}_path_bound_violations"] = bound_violations
    return sample


def evaluate_run(run_id, nodes, genesis, edges, buckets_per_level):
    row = {"run_id": run_id, "nodes": nodes, "genesis": genesis, "edges": edges,
           "buckets_per_level": buckets_per_level}

    data_dag = generate_data_dag(nodes, genesis, edges)
    event_dag = extract_event_dag(data_dag)

    t = time.perf_counter()
    data_dag.partition_into_levels()
    row["data_level_partition_time_ms"] = ms(time.perf_counter() - t)
    t = time.perf_counter()
    event_dag.partition_into_levels()
    row["event_level_partition_time_ms"] = ms(time.perf_counter() - t)
    link_producing_events(data_dag, event_dag)

    data = Verdict(data_dag, k_buckets=buckets_per_level)
    event = Verdict(event_dag, k_buckets=buckets_per_level)
    data_sample = evaluate_dag(data, "data", row)
    evaluate_dag(event, "event", row)

    full_t = cross_t = 0.0
    full_fail = cross_fail = 0
    for x in data_sample:
        t = time.perf_counter()
        full_fail += not data.verify_existence(x)
        full_t += time.perf_counter() - t
        t = time.perf_counter()
        cross_fail += not verify_cross_dag(x, data, event)
        cross_t += time.perf_counter() - t
    row["data_full_verification_time_ms"] = ms(full_t / TRIALS)
    row["cross_dag_verification_time_ms"] = ms(cross_t / TRIALS)
    row["data_full_verification_failures"] = full_fail
    row["cross_dag_verification_failures"] = cross_fail
    return row


def main():
    parser = argparse.ArgumentParser(description="Evaluate VERDICT for one configuration")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--nodes", type=int, default=25)
    parser.add_argument("--genesis", type=int, default=4)
    parser.add_argument("--edges", type=int, default=3)
    parser.add_argument("--buckets", type=int, default=4)
    parser.add_argument("--seed", type=int, default=None,
                        help="Base random seed; run i uses seed+i (default: unseeded)")
    parser.add_argument("--out", type=str, default="lineage_eval",
                        help="Output directory for evaluation_log.csv")
    args = parser.parse_args()

    eval_path = Path(args.out)
    eval_path.mkdir(parents=True, exist_ok=True)
    log_file = eval_path / "evaluation_log.csv"
    eval_log = pd.read_csv(log_file) if log_file.exists() else pd.DataFrame()

    for run_id in range(1, args.runs + 1):
        if args.seed is not None:
            random.seed(args.seed + run_id)
        print(f"[Run {run_id}] nodes={args.nodes}, genesis={args.genesis}, "
              f"edges={args.edges}, buckets={args.buckets}", flush=True)
        row = evaluate_run(run_id, args.nodes, args.genesis, args.edges, args.buckets)
        eval_log = pd.concat([eval_log, pd.DataFrame([row])], ignore_index=True)
        eval_log.to_csv(log_file, index=False)

    print("\nEvaluation complete. Log saved to:", log_file.absolute())


if __name__ == "__main__":
    main()
