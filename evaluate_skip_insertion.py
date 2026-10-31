"""
evaluate_skip_insertion.py

Measures the cost of inserting new elements into the skip DAG with
InsertIntoSkipDAG (Algorithm 2): ECMH update of the target level, the
binary-descent path, and the signed path hash stored in the element's
metadata. Covers both the Data DAG and the Event DAG (Fig. 3).

Each new data artifact derives from 1..edges random existing artifacts, so its
level is 1 + the highest level of its parents; the matching transformation
event is inserted into the Event DAG in the same way.

Results are saved to <out>/skip_insertion_eval_detailed_results_{nodes}.csv.

Usage:
    python evaluate_skip_insertion.py --nodes 1000 --genesis 50 --edges 10 --insertions 32
"""
import argparse
import random
import time
from pathlib import Path

import pandas as pd

from secure_lineage_system import (
    DataArtifact, LineageEvent, Verdict, extract_event_dag, generate_data_dag,
    link_producing_events,
)


def new_lineage_step(data, event, edges, i):
    """Creates a new artifact derived from random parents and its producing event."""
    data_dag, event_dag = data.dag, event.dag
    existing = sorted(data_dag.level_map)
    parents = random.sample(existing, random.randint(1, min(edges, len(existing))))
    top = max(parents, key=lambda u: (data_dag.level_map[u], u))
    j_data = data_dag.level_map[top] + 1

    aid = f"new_data_{i}"
    eid = f"new_evt_{top}_{aid}"
    art = DataArtifact(aid, metadata={"event_ref": eid})
    evt = LineageEvent(eid, description=f"Transform {top} to {aid}", inputs=[top], outputs=[aid],
                       metadata={"type": "transform", "source": top, "target": aid})
    producers = [p for p in event_dag.graph.nodes if aid != p and top in event_dag.events[p].outputs]
    j_event = 1 + max((event_dag.level_map[p] for p in producers), default=0)
    return art, j_data, parents, evt, j_event, producers


def register(dag, x, j, preds, is_data):
    """Adds the element to the DAG bookkeeping (not part of the timed insertion)."""
    if is_data:
        dag.add_data_artifact(x)
        for p in preds:
            dag.add_dependency(p, x.id, x.metadata["event_ref"])
    else:
        dag.add_event(x)
        for p in preds:
            dag.add_causal_dependency(p, x.id)
    dag.level_map[x.id] = j
    dag.levels.setdefault(j, set()).add(x.id)


def evaluate_insertions(nodes, genesis, edges, num_insertions, buckets):
    data_dag = generate_data_dag(nodes, genesis, edges)
    event_dag = extract_event_dag(data_dag)
    data_dag.partition_into_levels()
    event_dag.partition_into_levels()
    link_producing_events(data_dag, event_dag)
    data = Verdict(data_dag, k_buckets=buckets).build()
    event = Verdict(event_dag, k_buckets=buckets).build()

    results = []
    for i in range(num_insertions):
        art, j_data, parents, evt, j_event, producers = new_lineage_step(data, event, edges, i)
        for verdict, x, j, preds, name in ((data, art, j_data, parents, "Data"),
                                           (event, evt, j_event, producers, "Event")):
            levels_before = verdict.n
            t = time.perf_counter()
            verdict.insert(x, j)
            insertion_time_ms = (time.perf_counter() - t) * 1000
            register(verdict.dag, x, j, preds, name == "Data")
            verdict.insert_merkle(x, j)
            results.append({
                "dag_type": name,
                "insertion_index": i + 1,
                "new_node_id": x.id,
                "target_level": j,
                "new_level_created": j > levels_before,
                "num_levels": verdict.n,
                "num_nodes": verdict.dag.graph.number_of_nodes(),
                "num_edges": verdict.dag.graph.number_of_edges(),
                "num_skip_edges": verdict.skip.number_of_edges(),
                "insertion_time_ms": round(insertion_time_ms, 6),
                "verified_after_insertion": verdict.verify_existence(x),
            })
    return pd.DataFrame(results)


def main():
    parser = argparse.ArgumentParser(description="Evaluate Skip DAG insertions (Algorithm 2)")
    parser.add_argument("--nodes", type=int, default=25)
    parser.add_argument("--genesis", type=int, default=4)
    parser.add_argument("--edges", type=int, default=3)
    parser.add_argument("--insertions", type=int, default=32)
    parser.add_argument("--buckets", type=int, default=4)
    parser.add_argument("--seed", type=int, default=None, help="Random seed (default: unseeded)")
    parser.add_argument("--out", type=str, default=".", help="Output directory for the CSV")
    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    eval_results = evaluate_insertions(args.nodes, args.genesis, args.edges, args.insertions, args.buckets)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_results.to_csv(out_dir / f"skip_insertion_eval_detailed_results_{args.nodes}.csv", index=False)
    print(eval_results.groupby("dag_type")[["insertion_time_ms"]].describe())


if __name__ == "__main__":
    main()
