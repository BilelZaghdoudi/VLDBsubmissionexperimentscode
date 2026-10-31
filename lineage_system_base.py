#!/usr/bin/env python3
"""
lineage_system_base.py

Builds a small VERDICT instance and writes interactive HTML visualizations of
the Data DAG, the Event DAG and their deterministic binary skip DAGs.

The implementation itself lives in secure_lineage_system.py.
"""
import argparse
import random

from pyvis.network import Network

from secure_lineage_system import build_system, binary_descent_path

EDGE_COLORS = {1: "gray", 2: "red", 4: "blue", 8: "green", 16: "purple"}


def write_dag(dag, path, label_edges=False):
    net = Network(directed=True)
    for nid in dag.graph.nodes():
        net.add_node(nid, label=nid, title=f"level {dag.level_map[nid]}")
    for u, v, edata in dag.graph.edges(data=True):
        label = edata.get("event", "") if label_edges else ""
        net.add_edge(u, v, label=label, title=label)
    net.write_html(path)
    print(f"Saved visualization to {path}")


def write_skip_dag(verdict, path):
    net = Network(directed=True)
    for lvl in range(1, verdict.skip.n + 1):
        net.add_node(str(lvl), label=str(lvl))
    for u, v in verdict.skip.edges():
        dist = v - u
        net.add_edge(str(u), str(v), label=str(dist), color=EDGE_COLORS.get(dist, "orange"))
    net.write_html(path)
    print(f"Saved visualization to {path}")


def main():
    parser = argparse.ArgumentParser(description="Visualize VERDICT DAGs and skip DAGs")
    parser.add_argument("--nodes", type=int, default=10, help="Number of data artifacts")
    parser.add_argument("--genesis", type=int, default=2, help="Number of genesis nodes")
    parser.add_argument("--edges", type=int, default=2, help="Max edges per node")
    parser.add_argument("--seed", type=int, default=None, help="Random seed (default: unseeded)")
    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    data, event = build_system(args.nodes, args.genesis, args.edges)
    for name, v in (("Data", data), ("Event", event)):
        print(f"{name} DAG levels:")
        for lvl in sorted(v.dag.levels):
            print(f"  Level {lvl}: {sorted(v.dag.levels[lvl])}")
        print(f"{name} skip DAG edges: {sorted(v.skip.edges())}")
        print(f"{name} path to top level {v.n}: {binary_descent_path(v.n)}\n")

    write_dag(data.dag, "data_dag.html", label_edges=True)
    write_dag(event.dag, "event_dag.html")
    write_skip_dag(data, "data_skip_dag.html")
    write_skip_dag(event, "event_skip_dag.html")


if __name__ == "__main__":
    main()
