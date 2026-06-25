"""
evaluate_skip_insertion.py

Evaluates the time cost of inserting new nodes into the Skip DAG
for both the Data DAG and the Event DAG.

Results are saved to skip_insertion_eval_detailed_results_{nodes}.csv.

Usage:
    python evaluate_skip_insertion.py --nodes 25 --genesis 4 --edges 3
                                      --skip-prob 0.6 --insertions 32
"""
import argparse
import pandas as pd
import random
import time
from lineage_system_base import (
    generate_data_dag, extract_event_dag,
    compute_hashed_level_dag, build_skip_dag,
    CryptoKeys, HomomorphicHash, DataArtifact, LineageEvent
)

def insert_into_skip_dag(dag, skip_dag, concat_hashes, crypto, is_data):
    new_id = f"new_item_{random.randint(100000,999999)}"
    new_node = DataArtifact(new_id) if is_data else LineageEvent(new_id)
    dag.graph.add_node(new_id)
    target_level = max(dag.levels.keys())
    dag.levels[target_level].add(new_id)
    new_hash = new_node.compute_full_hash()
    concat_hashes[target_level] = HomomorphicHash.combine(concat_hashes[target_level], new_hash)

    signed_paths = {}
    for (u, v) in skip_dag.edges():
        if u == target_level or v == target_level:
            path_data = concat_hashes[u] + concat_hashes[v]
            path_hash = CryptoKeys().sign(path_data)
            signed_paths[(u, v)] = path_hash

    return signed_paths, new_id, target_level

def evaluate_insertions(nodes, genesis, edges, skip_prob, num_insertions):
    results = []

    data_dag = generate_data_dag(nodes, genesis, edges)
    event_dag = extract_event_dag(data_dag)

    data_dag.partition_into_levels()
    event_dag.partition_into_levels()

    data_crypto, _, _, data_concat = compute_hashed_level_dag(data_dag, is_data=True)
    event_crypto, _, _, event_concat = compute_hashed_level_dag(event_dag, is_data=False)

    data_skip, _ = build_skip_dag(max(data_dag.levels), data_concat, data_crypto, skip_prob)
    event_skip, _ = build_skip_dag(max(event_dag.levels), event_concat, event_crypto, skip_prob)

    for dag, skip, concat, crypto, is_data, name in [
        (data_dag, data_skip, data_concat, data_crypto, True, "Data"),
        (event_dag, event_skip, event_concat, event_crypto, False, "Event")]:

        for i in range(num_insertions):
            start_time = time.perf_counter()
            signed_paths, new_node_id, target_level = insert_into_skip_dag(dag, skip, concat, crypto, is_data)
            insertion_time_ms = (time.perf_counter() - start_time) * 1000

            results.append({
                "dag_type": name,
                "insertion_index": i + 1,
                "new_node_id": new_node_id,
                "target_level": target_level,
                "num_levels": len(dag.levels),
                "num_nodes": dag.graph.number_of_nodes(),
                "num_edges": dag.graph.number_of_edges(),
                "num_skip_edges": skip.number_of_edges(),
                "insertion_time_ms": round(insertion_time_ms, 6)
            })

    return pd.DataFrame(results)

def main():
    parser = argparse.ArgumentParser(description="Evaluate Skip DAG Insertions")
    parser.add_argument("--nodes", type=int, default=25)
    parser.add_argument("--genesis", type=int, default=4)
    parser.add_argument("--edges", type=int, default=3)
    parser.add_argument("--skip-prob", type=float, default=0.6)
    parser.add_argument("--insertions", type=int, default=32)

    args = parser.parse_args()

    eval_results = evaluate_insertions(
        args.nodes, args.genesis, args.edges, args.skip_prob, args.insertions)

    eval_results.to_csv(f"skip_insertion_eval_detailed_results_{str(args.nodes)}.csv", index=False)
    print(eval_results)

if __name__ == "__main__":
    main()
