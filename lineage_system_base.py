#!/usr/bin/env python3
"""
lineage_system_base.py

Base implementation of the Secure Lineage System (without Merkle bucket verification).
Contains Data DAG, Event DAG, Skip DAG construction, and path verification.

Used by evaluate_skip_insertion.py for skip insertion time experiments.
"""
import argparse
import networkx as nx
import hashlib
import random
from datetime import datetime
from typing import List, Dict, Set, Tuple
from pyvis.network import Network
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class DataArtifact:
    """Represents a data artifact in the Data DAG."""
    def __init__(self, artifact_id: str, content: str = None, metadata: Dict = None):
        self.id = artifact_id
        self.content = content or f"Data artifact {artifact_id}"
        self.metadata = metadata or {}
        self.timestamp = datetime.now().isoformat()
        self.content_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        s = f"{self.content}{self.timestamp}"
        return hashlib.sha256(s.encode()).hexdigest()[:16]

    def compute_full_hash(self) -> bytes:
        data = f"{self.content}||{repr(self.metadata)}".encode()
        return hashlib.sha256(data).digest()


class LineageEvent:
    """Represents a lineage event (transformation) in the Event DAG."""
    def __init__(self, event_id: str, description: str = None,
                 inputs: List[str] = None, outputs: List[str] = None, metadata: Dict = None):
        self.id = event_id
        self.description = description or f"Event {event_id}"
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.metadata = metadata or {}
        self.timestamp = datetime.now().isoformat()
        self.event_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        s = f"{self.description}{sorted(self.inputs)}{sorted(self.outputs)}{self.timestamp}"
        return hashlib.sha256(s.encode()).hexdigest()[:16]

    def compute_full_hash(self) -> bytes:
        data = f"{self.description}||{repr(sorted(self.inputs))}||{repr(sorted(self.outputs))}||{repr(self.metadata)}".encode()
        return hashlib.sha256(data).digest()


class DataDAG:
    """Represents the Data DAG (nodes=DataArtifact)."""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.artifacts: Dict[str, DataArtifact] = {}
        self.genesis_nodes: Set[str] = set()
        self.levels: Dict[int, Set[str]] = {}
        self.level_map: Dict[str, int] = {}

    def add_data_artifact(self, artifact: DataArtifact):
        self.artifacts[artifact.id] = artifact
        self.graph.add_node(artifact.id, content_hash=artifact.content_hash, metadata=artifact.metadata, timestamp=artifact.timestamp)
        if self.graph.in_degree(artifact.id) == 0:
            self.genesis_nodes.add(artifact.id)

    def add_dependency(self, source_id: str, target_id: str, event_ref: str = None):
        if source_id not in self.graph or target_id not in self.graph:
            raise ValueError("Source and target must exist in Data DAG")
        self.graph.add_edge(source_id, target_id, event=event_ref)
        if target_id in self.genesis_nodes:
            self.genesis_nodes.remove(target_id)

    def partition_into_levels(self) -> Tuple[Dict[int, Set[str]], Dict[str, int]]:
        """Partition nodes into levels (Algorithm 1)."""
        self.levels.clear()
        self.level_map.clear()
        in_degree = {v: self.graph.in_degree(v) for v in self.graph.nodes()}
        in_processed = {v: 0 for v in self.graph.nodes()}
        queue = []
        level1 = set()
        for v, deg in in_degree.items():
            if deg == 0:
                self.level_map[v] = 1
                level1.add(v)
                queue.append(v)
        self.levels[1] = level1
        while queue:
            u = queue.pop(0)
            u_level = self.level_map[u]
            for w in self.graph.successors(u):
                in_processed[w] += 1
                if w not in self.level_map or self.level_map[w] < u_level + 1:
                    old = self.level_map.get(w)
                    new = u_level + 1
                    if old and w in self.levels.get(old, set()):
                        self.levels[old].remove(w)
                    self.level_map[w] = new
                    if new not in self.levels:
                        self.levels[new] = set()
                    self.levels[new].add(w)
                if in_processed[w] == in_degree[w]:
                    queue.append(w)
        self.levels = {lvl: nodes for lvl, nodes in self.levels.items() if nodes}
        return self.levels, self.level_map


class EventDAG:
    """Represents the Event DAG (nodes=LineageEvent)."""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.events: Dict[str, LineageEvent] = {}
        self.genesis_events: Set[str] = set()
        self.levels: Dict[int, Set[str]] = {}
        self.level_map: Dict[str, int] = {}

    def add_event(self, event: LineageEvent):
        self.events[event.id] = event
        self.graph.add_node(event.id, description=event.description, inputs=event.inputs, outputs=event.outputs, timestamp=event.timestamp)
        if self.graph.in_degree(event.id) == 0:
            self.genesis_events.add(event.id)

    def add_causal_dependency(self, source_event_id: str, target_event_id: str):
        if source_event_id not in self.graph or target_event_id not in self.graph:
            raise ValueError("Source/target event must exist")
        self.graph.add_edge(source_event_id, target_event_id)
        if target_event_id in self.genesis_events:
            self.genesis_events.remove(target_event_id)

    def partition_into_levels(self) -> Tuple[Dict[int, Set[str]], Dict[str, int]]:
        """Partition events into levels (Algorithm 1)."""
        self.levels.clear()
        self.level_map.clear()
        in_degree = {v: self.graph.in_degree(v) for v in self.graph.nodes()}
        in_processed = {v: 0 for v in self.graph.nodes()}
        queue = []
        level1 = set()
        for v, deg in in_degree.items():
            if deg == 0:
                self.level_map[v] = 1
                level1.add(v)
                queue.append(v)
        self.levels[1] = level1
        while queue:
            u = queue.pop(0)
            u_level = self.level_map[u]
            for w in self.graph.successors(u):
                in_processed[w] += 1
                if w not in self.level_map or self.level_map[w] < u_level + 1:
                    old = self.level_map.get(w)
                    new = u_level + 1
                    if old and w in self.levels.get(old, set()):
                        self.levels[old].remove(w)
                    self.level_map[w] = new
                    if new not in self.levels:
                        self.levels[new] = set()
                    self.levels[new].add(w)
                if in_processed[w] == in_degree[w]:
                    queue.append(w)
        self.levels = {lvl: nodes for lvl, nodes in self.levels.items() if nodes}
        return self.levels, self.level_map


class HomomorphicHash:
    """Homomorphic hash: H(x⊕y) = H(x) ⊗ H(y)."""
    @staticmethod
    def combine(h1: bytes, h2: bytes) -> bytes:
        max_len = max(len(h1), len(h2))
        h1_p = h1 + bytes([0])*(max_len - len(h1))
        h2_p = h2 + bytes([0])*(max_len - len(h2))
        comb = bytes(a ^ b for a, b in zip(h1_p, h2_p))
        return hashlib.sha256(comb).digest()


class CryptoKeys:
    """Manages RSA key pair for signing/verification."""
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data,
                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                      hashes.SHA256())

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, data,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
            return True
        except:
            return False


def generate_data_dag(num_nodes: int, num_start_nodes: int, max_edges: int) -> DataDAG:
    if num_start_nodes >= num_nodes:
        raise ValueError("genesis must be less than total nodes")
    data_dag = DataDAG()
    artifacts = []
    for i in range(num_nodes):
        art = DataArtifact(artifact_id=f"data_{i}")
        artifacts.append(art)
        data_dag.add_data_artifact(art)
    genesis_indices = set(random.sample(range(num_nodes), num_start_nodes))
    for i in range(num_nodes):
        aid = f"data_{i}"
        if i in genesis_indices:
            data_dag.genesis_nodes.add(aid)
            continue
        possible = list(range(i))
        if not possible:
            data_dag.genesis_nodes.add(aid)
            continue
        num_edges = random.randint(1, min(max_edges, len(possible)))
        sources = random.sample(possible, num_edges)
        for src in sources:
            s_id = f"data_{src}"
            event_ref = f"evt_{src}_{i}"
            data_dag.add_dependency(s_id, aid, event_ref)
    return data_dag


def extract_event_dag(data_dag: DataDAG) -> EventDAG:
    event_dag = EventDAG()
    for src, tgt, edata in data_dag.graph.edges(data=True):
        event_ref = edata.get('event')
        if event_ref:
            event = LineageEvent(event_id=event_ref,
                                 description=f"Transform {src} to {tgt}",
                                 inputs=[src], outputs=[tgt],
                                 metadata={"type": "transform", "source": src, "target": tgt})
            event_dag.add_event(event)
    for g in data_dag.genesis_nodes:
        outs = list(data_dag.graph.out_edges(g, data=True))
        if outs:
            geid = f"genesis_event_{g}"
            ge = LineageEvent(event_id=geid,
                              description=f"Genesis for {g}",
                              inputs=[], outputs=[g],
                              metadata={"type": "genesis", "artifact": g})
            event_dag.add_event(ge)
            for _, _, edata in outs:
                ev_ref = edata.get('event')
                if ev_ref and ev_ref in event_dag.events:
                    event_dag.add_causal_dependency(geid, ev_ref)
    ev_items = list(event_dag.events.items())
    for e1_id, e1 in ev_items:
        for e2_id, e2 in ev_items:
            if e1_id != e2_id:
                if set(e1.outputs) & set(e2.inputs):
                    event_dag.add_causal_dependency(e1_id, e2_id)
    return event_dag


def compute_hashed_level_dag(dag, is_data: bool):
    """Compute level hashes and concatenated hashes."""
    crypto = CryptoKeys()
    level_hashes: Dict[int, bytes] = {}
    signed_hashes: Dict[int, bytes] = {}
    concatenated: Dict[int, bytes] = {}
    levels = dag.levels
    for level in sorted(levels):
        nodes = levels[level]
        full_hash = None
        for node_id in sorted(nodes):
            if is_data:
                h = dag.artifacts[node_id].compute_full_hash()
            else:
                h = dag.events[node_id].compute_full_hash()
            if full_hash is None:
                full_hash = h
            else:
                full_hash = HomomorphicHash.combine(full_hash, h)
        if full_hash is None:
            full_hash = b''
        level_hashes[level] = full_hash
        sig = crypto.sign(full_hash)
        signed_hashes[level] = sig
        if level == 1:
            concatenated[level] = full_hash
        else:
            prev = concatenated[level-1]
            concatenated[level] = hashlib.sha256(prev + full_hash).digest()
    return crypto, level_hashes, signed_hashes, concatenated


def build_skip_dag(max_level: int, concatenated_hashes: Dict[int, bytes], crypto: CryptoKeys, skip_prob: float):
    """Build skip DAG (levels as nodes) with edges i->i+2^k pattern."""
    G = nx.DiGraph()
    for level in range(1, max_level+1):
        G.add_node(level)
    for i in range(1, max_level):
        G.add_edge(i, i+1)
    for i in range(1, max_level):
        skip_dist = 2
        while i + skip_dist <= max_level:
            if random.random() <= skip_prob:
                G.add_edge(i, i + skip_dist)
                skip_dist *= 2
            else:
                break
    signed_paths: Dict[Tuple[int,int], bytes] = {}
    for (u, v) in G.edges():
        src_concat = concatenated_hashes[u]
        tgt_concat = concatenated_hashes[v]
        path_data = src_concat + tgt_concat
        path_hash = hashlib.sha256(path_data).digest()
        signature = crypto.sign(path_hash)
        signed_paths[(u, v)] = signature
    return G, signed_paths


def find_path_in_skip(G: nx.DiGraph, start: int, target: int) -> List[int]:
    """Find a path from start level to target level in skip DAG."""
    if start == target:
        return [start]
    from collections import deque
    queue = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        node = path[-1]
        if node == target:
            return path
        for nxt in G.successors(node):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(path + [nxt])
    return []


def verify_skip_path(path: List[int], concatenated_hashes: Dict[int, bytes], crypto: CryptoKeys, signed_paths: Dict[Tuple[int,int], bytes]) -> bool:
    """Verify signatures along the skip path."""
    for i in range(len(path)-1):
        u = path[i]
        v = path[i+1]
        if (u, v) not in signed_paths:
            return False
        data = hashlib.sha256(concatenated_hashes[u] + concatenated_hashes[v]).digest()
        sig = signed_paths[(u, v)]
        if not crypto.verify(data, sig):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Secure Lineage DAG")
    parser.add_argument("--nodes", type=int, default=10, help="Number of data artifacts")
    parser.add_argument("--genesis", type=int, default=2, help="Number of genesis nodes")
    parser.add_argument("--edges", type=int, default=2, help="Max edges per node")
    parser.add_argument("--skip-prob", type=float, default=1.0, help="Probability to include each skip link")
    args = parser.parse_args()

    data_dag = generate_data_dag(args.nodes, args.genesis, args.edges)
    event_dag = extract_event_dag(data_dag)
    assert nx.is_directed_acyclic_graph(data_dag.graph), "Data DAG has cycles!"
    assert nx.is_directed_acyclic_graph(event_dag.graph), "Event DAG has cycles!"

    data_levels, data_level_map = data_dag.partition_into_levels()
    event_levels, event_level_map = event_dag.partition_into_levels()

    print("Data DAG levels:")
    for lvl in sorted(data_levels):
        print(f"  Level {lvl}: {sorted(data_levels[lvl])}")
    print("Event DAG levels:")
    for lvl in sorted(event_levels):
        print(f"  Level {lvl}: {sorted(event_levels[lvl])}")

    data_crypto, data_level_hashes, data_signed_hashes, data_concat = compute_hashed_level_dag(data_dag, is_data=True)
    event_crypto, event_level_hashes, event_signed_hashes, event_concat = compute_hashed_level_dag(event_dag, is_data=False)

    print("\nConcatenated level hashes (Data DAG):")
    for lvl in sorted(data_concat):
        print(f"  Level {lvl}: {data_concat[lvl].hex()[:16]}...")
    print("Concatenated level hashes (Event DAG):")
    for lvl in sorted(event_concat):
        print(f"  Level {lvl}: {event_concat[lvl].hex()[:16]}...")

    max_data_level = max(data_levels) if data_levels else 0
    max_event_level = max(event_levels) if event_levels else 0
    data_skip_graph, data_skip_sigs = build_skip_dag(max_data_level, data_concat, data_crypto, args.skip_prob)
    event_skip_graph, event_skip_sigs = build_skip_dag(max_event_level, event_concat, event_crypto, args.skip_prob)

    print("\nSkip DAG edges (data):")
    for u, v in sorted(data_skip_graph.edges()):
        dist = v - u
        print(f"  Edge {u} -> {v} (skip={dist})")
    print("Skip DAG edges (event):")
    for u, v in sorted(event_skip_graph.edges()):
        dist = v - u
        print(f"  Edge {u} -> {v} (skip={dist})")

    if data_level_map:
        artifact_id, level = random.choice(list(data_level_map.items()))
        print(f"\nVerifying data artifact {artifact_id} at level {level}:")
        path = find_path_in_skip(data_skip_graph, 1, level)
        if path and verify_skip_path(path, data_concat, data_crypto, data_skip_sigs):
            print(f"Verified path to level {level}: {path}")
        else:
            print(f"Failed to verify artifact {artifact_id}")
    if event_level_map:
        event_id, level = random.choice(list(event_level_map.items()))
        print(f"\nVerifying event {event_id} at level {level}:")
        path = find_path_in_skip(event_skip_graph, 1, level)
        if path and verify_skip_path(path, event_concat, event_crypto, event_skip_sigs):
            print(f"Verified path to level {level}: {path}")
        else:
            print(f"Failed to verify event {event_id}")

    net_data = Network(directed=True)
    for nid in data_dag.graph.nodes():
        art = data_dag.artifacts[nid]
        net_data.add_node(nid, label=nid, title=f"{art.content_hash[:6]}")
    for u, v, edata in data_dag.graph.edges(data=True):
        net_data.add_edge(u, v, label=edata.get('event', ''), title=edata.get('event', ''))
    net_data.write_html("data_dag.html")
    print("Saved visualization to data_dag.html")

    net_event = Network(directed=True)
    for nid in event_dag.graph.nodes():
        ev = event_dag.events[nid]
        net_event.add_node(nid, label=nid, title=f"{ev.event_hash[:6]}")
    for u, v in event_dag.graph.edges():
        net_event.add_edge(u, v)
    net_event.write_html("event_dag.html")
    print("Saved visualization to event_dag.html")

    net_data_skip = Network(directed=True)
    color_map = {1: "gray", 2: "red", 4: "blue", 8: "green", 16: "purple"}
    for lvl in data_skip_graph.nodes():
        net_data_skip.add_node(str(lvl), label=str(lvl))
    for u, v in data_skip_graph.edges():
        dist = v - u
        color = color_map.get(dist, "orange")
        net_data_skip.add_edge(str(u), str(v), label=str(dist), color=color)
    net_data_skip.write_html("data_skip_dag.html")
    print("Saved visualization to data_skip_dag.html")

    net_event_skip = Network(directed=True)
    for lvl in event_skip_graph.nodes():
        net_event_skip.add_node(str(lvl), label=str(lvl))
    for u, v in event_skip_graph.edges():
        dist = v - u
        color = color_map.get(dist, "orange")
        net_event_skip.add_edge(str(u), str(v), label=str(dist), color=color)
    net_event_skip.write_html("event_skip_dag.html")
    print("Saved visualization to event_skip_dag.html")


if __name__ == "__main__":
    main()
