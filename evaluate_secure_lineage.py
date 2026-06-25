"""
evaluate_secure_lineage.py

Experimental evaluation of the Secure Lineage System.
Benchmarks Skip DAG construction, search, and verification times,
as well as Merkle bucket tree construction and membership verification,
across both the Data DAG and Event DAG.

Results are appended to lineage_eval/evaluation_log.csv.

Usage:
    python evaluate_secure_lineage.py --runs 10 --nodes 1000 --genesis 10 --edges 5
                                      --skip-prob 0.5 --buckets 4
"""
import argparse
import pandas as pd
import time
import random
import hashlib
import networkx as nx
from pathlib import Path

# Helper for entropy calculation
def calculate_entropy(distribution):
    from math import log2
    total = sum(distribution.values())
    entropy = 0.0
    for count in distribution.values():
        p = count / total
        entropy -= p * log2(p)
    return entropy

def evaluate_run(run_id, nodes, genesis, edges, skip_prob, buckets_per_level, eval_log):
    from secure_lineage_system import (
        generate_data_dag, extract_event_dag,
        compute_hashed_level_dag, build_skip_dag,
        find_path_in_skip, verify_skip_path,
        prepare_merkle_metadata, verify_full_membership,
        DataArtifact
    )

    t0 = time.perf_counter()
    data_dag = generate_data_dag(nodes, genesis, edges)
    t1 = time.perf_counter()
    event_dag = extract_event_dag(data_dag)
    t2 = time.perf_counter()

    # Level compression
    dlvl_start = time.perf_counter()
    data_levels, _ = data_dag.partition_into_levels()
    dlvl_end = time.perf_counter()

    elvl_start = time.perf_counter()
    event_levels, _ = event_dag.partition_into_levels()
    elvl_end = time.perf_counter()

    # Hash and skip DAG
    h1 = time.perf_counter()
    data_crypto, _, _, data_concat = compute_hashed_level_dag(data_dag, is_data=True)
    h2 = time.perf_counter()
    event_crypto, _, _, event_concat = compute_hashed_level_dag(event_dag, is_data=False)
    h3 = time.perf_counter()

    data_skip, data_signs = build_skip_dag(max(data_levels), data_concat, data_crypto, skip_prob)
    h4 = time.perf_counter()
    event_skip, event_signs = build_skip_dag(max(event_levels), event_concat, event_crypto, skip_prob)
    h5 = time.perf_counter()

    # --- Skip DAG search time measurement ---
    search_trials = 10
    data_search_time = 0.0
    event_search_time = 0.0

    # Search in the data skip DAG
    data_level_keys = list(data_levels.keys())
    for _ in range(search_trials):
        target_level = random.choice(data_level_keys)
        t_start = time.perf_counter()
        _ = find_path_in_skip(data_skip, 1, target_level)
        data_search_time += (time.perf_counter() - t_start) * 1000  # in ms

    avg_data_search_time = round(data_search_time / search_trials, 3)

    # Search in the event skip DAG
    event_level_keys = list(event_levels.keys())
    for _ in range(search_trials):
        target_level = random.choice(event_level_keys)
        t_start = time.perf_counter()
        _ = find_path_in_skip(event_skip, 1, target_level)
        event_search_time += (time.perf_counter() - t_start) * 1000  # in ms

    avg_event_search_time = round(event_search_time / search_trials, 3)


    # --- BUCKET/MERKLE EVALUATION ---

    # 1. Time bucket assignment and Merkle tree construction for data and event levels
    merkle_data_time, merkle_event_time = 0.0, 0.0
    data_merkle_roots, event_merkle_roots = {}, {}
    for lvl in sorted(data_levels):
        items = [data_dag.artifacts[nid] for nid in sorted(data_levels[lvl])]
        t_start = time.perf_counter()
        root, sig = prepare_merkle_metadata(items, buckets_per_level, data_crypto, is_data=True)
        merkle_data_time += (time.perf_counter() - t_start)
        data_merkle_roots[lvl] = (root, sig)

    for lvl in sorted(event_levels):
        items = [event_dag.events[nid] for nid in sorted(event_levels[lvl])]
        t_start = time.perf_counter()
        root, sig = prepare_merkle_metadata(items, buckets_per_level, event_crypto, is_data=False)
        merkle_event_time += (time.perf_counter() - t_start)
        event_merkle_roots[lvl] = (root, sig)

    merkle_data_time_ms = round(merkle_data_time * 1000, 3)
    merkle_event_time_ms = round(merkle_event_time * 1000, 3)

    # 2. Time Merkle verification for a random artifact/event, multi-trial average
    trials = 10
    m_data_fails, m_event_fails = 0, 0
    m_data_verif_time, m_event_verif_time = 0.0, 0.0

    # Data artifacts
    data_level_keys = list(data_levels.keys())
    for _ in range(trials):
        lvl = random.choice(data_level_keys)
        items = [data_dag.artifacts[nid] for nid in sorted(data_levels[lvl])]
        artifact = random.choice(items)
        t1 = time.perf_counter()
        ok = verify_full_membership(artifact, buckets_per_level, data_crypto, items)
        m_data_verif_time += (time.perf_counter() - t1) * 1000
        if not ok:
            m_data_fails += 1

    # Event artifacts
    event_level_keys = list(event_levels.keys())
    for _ in range(trials):
        lvl = random.choice(event_level_keys)
        items = [event_dag.events[nid] for nid in sorted(event_levels[lvl])]
        event = random.choice(items)
        t1 = time.perf_counter()
        ok = verify_full_membership(event, buckets_per_level, event_crypto, items)
        m_event_verif_time += (time.perf_counter() - t1) * 1000
        if not ok:
            m_event_fails += 1

    m_data_verif_time_avg = round(m_data_verif_time / trials, 3)
    m_event_verif_time_avg = round(m_event_verif_time / trials, 3)

    # Edge and diversity metrics
    data_edges = data_dag.graph.number_of_edges()
    event_edges = event_dag.graph.number_of_edges()
    data_skip_edges = len(data_skip.edges())
    event_skip_edges = len(event_skip.edges())

    data_dist = {v - u: 0 for u, v in data_skip.edges()}
    for u, v in data_skip.edges():
        data_dist[v - u] += 1
    data_entropy = calculate_entropy(data_dist) if data_dist else 0

    event_dist = {v - u: 0 for u, v in event_skip.edges()}
    for u, v in event_skip.edges():
        event_dist[v - u] += 1
    event_entropy = calculate_entropy(event_dist) if event_dist else 0

    # Verification (multi-trial avg, skip DAG)
    trials = 10
    d_fails = 0
    e_fails = 0
    d_time = 0.0
    e_time = 0.0

    for _ in range(trials):
        d_target = random.choice(list(data_concat))
        e_target = random.choice(list(event_concat))

        t1 = time.perf_counter()
        d_path = find_path_in_skip(data_skip, 1, d_target)
        if not d_path or not verify_skip_path(d_path, data_concat, data_crypto, data_signs):
            d_fails += 1
        d_time += (time.perf_counter() - t1) * 1000

        t2 = time.perf_counter()
        e_path = find_path_in_skip(event_skip, 1, e_target)
        if not e_path or not verify_skip_path(e_path, event_concat, event_crypto, event_signs):
            e_fails += 1
        e_time += (time.perf_counter() - t2) * 1000

    # Compile results
    row = {
        "run_id": run_id,
        "nodes": nodes,
        "genesis": genesis,
        "edges": edges,
        "skip_prob": skip_prob,
        "buckets_per_level": buckets_per_level,
        "data_levels": len(data_levels),
        "event_levels": len(event_levels),
        "data_edges": data_edges,
        "event_edges": event_edges,
        "data_skip_edges": data_skip_edges,
        "event_skip_edges": event_skip_edges,
        "data_skip_diversity": round(data_entropy, 3),
        "event_skip_diversity": round(event_entropy, 3),
        "data_signature_failures": d_fails,
        "event_signature_failures": e_fails,
        "data_verification_time_ms": round(d_time / trials, 3),
        "event_verification_time_ms": round(e_time / trials, 3),
        "data_level_partition_time_ms": round((dlvl_end - dlvl_start) * 1000, 3),
        "event_level_partition_time_ms": round((elvl_end - elvl_start) * 1000, 3),
        "data_skip_dag_time_ms": round((h4 - h2) * 1000, 3),
        "event_skip_dag_time_ms": round((h5 - h3) * 1000, 3),
        "data_merkle_time_ms": merkle_data_time_ms,
        "event_merkle_time_ms": merkle_event_time_ms,
        "data_merkle_verification_time_ms": m_data_verif_time_avg,
        "event_merkle_verification_time_ms": m_event_verif_time_avg,
        "data_merkle_verification_failures": m_data_fails,
        "event_merkle_verification_failures": m_event_fails,
        "avg_data_skip_search_time_ms": avg_data_search_time,
        "avg_event_skip_search_time_ms": avg_event_search_time
    }

    eval_log = pd.concat([eval_log, pd.DataFrame([row])], ignore_index=True)
    return eval_log

def main():
    parser = argparse.ArgumentParser(description="Evaluate Secure Lineage with Bucket/Merkle timing")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--nodes", type=int, default=25)
    parser.add_argument("--genesis", type=int, default=4)
    parser.add_argument("--edges", type=int, default=3)
    parser.add_argument("--skip-prob", type=float, default=0.6)
    parser.add_argument("--buckets", type=int, default=4)
    args = parser.parse_args()

    eval_path = Path("lineage_eval")
    eval_path.mkdir(exist_ok=True)
    log_file = eval_path / "evaluation_log.csv"

    log_columns = [
        "run_id", "nodes", "genesis", "edges", "skip_prob", "buckets_per_level",
        "data_levels", "event_levels",
        "data_edges", "event_edges",
        "data_skip_edges", "event_skip_edges",
        "data_skip_diversity", "event_skip_diversity",
        "data_signature_failures", "event_signature_failures",
        "data_verification_time_ms", "event_verification_time_ms",
        "data_level_partition_time_ms", "event_level_partition_time_ms",
        "data_skip_dag_time_ms", "event_skip_dag_time_ms",
        "data_merkle_time_ms", "event_merkle_time_ms",
        "data_merkle_verification_time_ms", "event_merkle_verification_time_ms",
        "data_merkle_verification_failures", "event_merkle_verification_failures",
        "avg_data_skip_search_time_ms", "avg_event_skip_search_time_ms"
    ]

    if log_file.exists():
        eval_log = pd.read_csv(log_file)
    else:
        eval_log = pd.DataFrame(columns=log_columns)

    for run_id in range(1, args.runs + 1):
        print(f"[Run {run_id}] Evaluating with nodes={args.nodes}, genesis={args.genesis}, edges={args.edges}, buckets={args.buckets}")
        eval_log = evaluate_run(run_id, args.nodes, args.genesis, args.edges, args.skip_prob, args.buckets, eval_log)
        eval_log.to_csv(log_file, index=False)

    print("\nEvaluation complete. Log saved to:", log_file.absolute())

if __name__ == "__main__":
    main()
