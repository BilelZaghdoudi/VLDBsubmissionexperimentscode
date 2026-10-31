#!/usr/bin/env python3
"""
secure_lineage_system.py

Core implementation of VERDICT, following Sections 3-5 of the paper:
  - Data DAG and Event DAG (Section 2.2)
  - level partitioning (Section 3.1)
  - ECMH level hashing over P-256 with signed level hashes and
    concatenated level hashes CH(L_i) (Sections 3.2-3.3, see ecmh.py)
  - deterministic binary skip DAG: edges L_i -> L_{i+2^k} (Section 4)
  - BinaryDescentPath (Algorithm 1), InsertIntoSkipDAG (Algorithm 2),
    VerifyExistence (Algorithm 3) with one signed path proof per element
  - hash-based bucket indexing with per-level Merkle trees and signed roots
    (Section 5.1-5.3)
  - cross-DAG consistency verification (Section 5.4)

Signatures use Ed25519; the paper only requires an EUF-CMA signature scheme.
"""
import argparse
import hashlib
import random
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecmh import ECMH

# Fields written by VERDICT into an element's metadata live under this key.
# They are excluded from the element hash, since they are derived from it.
PROOF_KEY = "verdict"


def Hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Elements and DAGs
# ---------------------------------------------------------------------------

class DataArtifact:
    """Represents a data artifact in the Data DAG."""
    def __init__(self, artifact_id: str, content: str = None, metadata: Dict = None):
        self.id = artifact_id
        self.content = content or f"Data artifact {artifact_id}"
        self.metadata = metadata or {}
        self.timestamp = datetime.now().isoformat()

    def compute_full_hash(self) -> bytes:
        """H(v) = Hash(content || metadata) for the Data DAG."""
        meta = {k: v for k, v in self.metadata.items() if k != PROOF_KEY}
        return Hash(f"{self.content}||{repr(sorted(meta.items()))}".encode())

    @property
    def proof(self) -> Dict:
        return self.metadata.setdefault(PROOF_KEY, {})


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

    def compute_full_hash(self) -> bytes:
        """H(v) = Hash(description || inputs || outputs || metadata) for the Event DAG."""
        meta = {k: v for k, v in self.metadata.items() if k != PROOF_KEY}
        return Hash(f"{self.description}||{repr(sorted(self.inputs))}||"
                    f"{repr(sorted(self.outputs))}||{repr(sorted(meta.items()))}".encode())

    @property
    def proof(self) -> Dict:
        return self.metadata.setdefault(PROOF_KEY, {})


def partition_into_levels(graph: nx.DiGraph) -> Tuple[Dict[int, Set[str]], Dict[str, int]]:
    """Level partitioning (Section 3.1): L(v) = 1 for genesis nodes,
    otherwise 1 + max level of its predecessors. O(|V| + |E|)."""
    level_map: Dict[str, int] = {}
    for v in nx.topological_sort(graph):
        preds = list(graph.predecessors(v))
        level_map[v] = 1 + max((level_map[u] for u in preds), default=0)
    levels: Dict[int, Set[str]] = defaultdict(set)
    for v, lvl in level_map.items():
        levels[lvl].add(v)
    return dict(levels), level_map


class DataDAG:
    """Data DAG: vertices are data artifacts, edges are derivations annotated with events."""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.artifacts: Dict[str, DataArtifact] = {}
        self.genesis_nodes: Set[str] = set()
        self.levels: Dict[int, Set[str]] = {}
        self.level_map: Dict[str, int] = {}

    @property
    def elements(self):
        return self.artifacts

    def add_data_artifact(self, artifact: DataArtifact):
        self.artifacts[artifact.id] = artifact
        self.graph.add_node(artifact.id)
        if self.graph.in_degree(artifact.id) == 0:
            self.genesis_nodes.add(artifact.id)

    def add_dependency(self, source_id: str, target_id: str, event_ref: str = None):
        if source_id not in self.graph or target_id not in self.graph:
            raise ValueError("Source and target must exist in Data DAG")
        self.graph.add_edge(source_id, target_id, event=event_ref)
        self.genesis_nodes.discard(target_id)

    def partition_into_levels(self):
        self.levels, self.level_map = partition_into_levels(self.graph)
        return self.levels, self.level_map


class EventDAG:
    """Event DAG: vertices are transformation events, edges are causal dependencies."""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.events: Dict[str, LineageEvent] = {}
        self.genesis_events: Set[str] = set()
        self.levels: Dict[int, Set[str]] = {}
        self.level_map: Dict[str, int] = {}

    @property
    def elements(self):
        return self.events

    def add_event(self, event: LineageEvent):
        self.events[event.id] = event
        self.graph.add_node(event.id)
        if self.graph.in_degree(event.id) == 0:
            self.genesis_events.add(event.id)

    def add_causal_dependency(self, source_event_id: str, target_event_id: str):
        if source_event_id not in self.graph or target_event_id not in self.graph:
            raise ValueError("Source/target event must exist")
        self.graph.add_edge(source_event_id, target_event_id)
        self.genesis_events.discard(target_event_id)

    def partition_into_levels(self):
        self.levels, self.level_map = partition_into_levels(self.graph)
        return self.levels, self.level_map


def generate_data_dag(num_nodes: int, num_start_nodes: int, max_edges: int) -> DataDAG:
    """Synthetic Data DAG: num_start_nodes genesis artifacts; every other artifact
    derives from 1..max_edges earlier artifacts chosen uniformly at random."""
    if num_start_nodes >= num_nodes:
        raise ValueError("genesis must be less than total nodes")
    data_dag = DataDAG()
    for i in range(num_nodes):
        data_dag.add_data_artifact(DataArtifact(artifact_id=f"data_{i}"))
    genesis_indices = set(random.sample(range(num_nodes), num_start_nodes))
    for i in range(num_nodes):
        aid = f"data_{i}"
        if i in genesis_indices or i == 0:
            data_dag.genesis_nodes.add(aid)
            continue
        num_edges = random.randint(1, min(max_edges, i))
        for src in random.sample(range(i), num_edges):
            data_dag.add_dependency(f"data_{src}", aid, f"evt_{src}_{i}")
    return data_dag


def extract_event_dag(data_dag: DataDAG) -> EventDAG:
    """Builds the Event DAG from the Data DAG: one transformation event per
    data edge, one genesis event per genesis artifact, and an edge e1 -> e2
    whenever an output of e1 is an input of e2. O(|V_E| + |E_E|)."""
    event_dag = EventDAG()
    producers: Dict[str, List[str]] = defaultdict(list)   # artifact -> events that output it
    consumers: Dict[str, List[str]] = defaultdict(list)   # artifact -> events that take it as input
    for g in sorted(data_dag.genesis_nodes):
        geid = f"genesis_event_{g}"
        event_dag.add_event(LineageEvent(event_id=geid, description=f"Genesis for {g}",
                                         inputs=[], outputs=[g],
                                         metadata={"type": "genesis", "artifact": g}))
        producers[g].append(geid)
    for src, tgt, edata in data_dag.graph.edges(data=True):
        eid = edata["event"]
        event_dag.add_event(LineageEvent(event_id=eid, description=f"Transform {src} to {tgt}",
                                         inputs=[src], outputs=[tgt],
                                         metadata={"type": "transform", "source": src, "target": tgt}))
        producers[tgt].append(eid)
        consumers[src].append(eid)
    for artifact, prod in producers.items():
        for e1 in prod:
            for e2 in consumers.get(artifact, ()):
                event_dag.add_causal_dependency(e1, e2)
    return event_dag


def link_producing_events(data_dag: DataDAG, event_dag: EventDAG):
    """Annotates each artifact x with event_ref, the event that produced x
    from its highest-level parent (the genesis event for genesis artifacts).
    This is the edge that determines L(x), so level_D(x) = level_E(event_ref)."""
    for aid, art in data_dag.artifacts.items():
        parents = list(data_dag.graph.predecessors(aid))
        if parents:
            top = max(parents, key=lambda u: (data_dag.level_map[u], u))
            art.metadata["event_ref"] = data_dag.graph.edges[top, aid]["event"]
        else:
            art.metadata["event_ref"] = f"genesis_event_{aid}"


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

class CryptoKeys:
    """Signing key pair of a DataHub (Ed25519)."""
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Hashed level DAG (Section 3)
# ---------------------------------------------------------------------------

class HashedLevelDAG:
    """ECMH level hashes H(L_i), signed level hashes Sig(L_i), and
    concatenated hashes CH(L_i) = Hash(H(L_1) || ... || H(L_i))."""

    def __init__(self, keys: CryptoKeys):
        self.keys = keys
        self.acc: Dict[int, ECMH] = {}
        self.level_sigs: Dict[int, bytes] = {}
        self._prefix: List = []   # _prefix[i-1] = SHA-256 state after H(L_1..L_i)
        self.n = 0

    @classmethod
    def build(cls, dag, keys: CryptoKeys) -> "HashedLevelDAG":
        """Single pass over all nodes, O(|V|) point additions."""
        h = cls(keys)
        h.n = max(dag.levels) if dag.levels else 0
        for lvl in range(1, h.n + 1):
            acc = ECMH()
            for nid in dag.levels.get(lvl, ()):
                acc.add(dag.elements[nid].compute_full_hash())
            h.acc[lvl] = acc
            h.level_sigs[lvl] = keys.sign(acc.digest())
        return h

    def level_hash(self, i: int) -> bytes:
        return self.acc[i].digest()

    def add_to_level(self, j: int, node_hash: bytes):
        """O(1) incremental update H'(L_j) = H(L_j) (+) phi(H(x))."""
        if j > self.n:
            for lvl in range(self.n + 1, j + 1):
                self.acc[lvl] = ECMH()
            self.n = j
        self.acc[j].add(node_hash)
        self.level_sigs[j] = self.keys.sign(self.acc[j].digest())
        del self._prefix[j - 1:]

    def ch(self, i: int) -> bytes:
        while len(self._prefix) < i:
            k = len(self._prefix) + 1
            state = self._prefix[-1].copy() if self._prefix else hashlib.sha256()
            state.update(self.level_hash(k))
            self._prefix.append(state)
        return self._prefix[i - 1].copy().digest()


# ---------------------------------------------------------------------------
# Deterministic binary skip DAG (Section 4)
# ---------------------------------------------------------------------------

class SkipDAG:
    """Levels 1..n with edges (L_i, L_{i+2^k}) for every k >= 0 with i + 2^k <= n."""

    def __init__(self, n: int = 0):
        self.n = 0
        self.out: Dict[int, List[int]] = {}
        self.extend(n)

    def extend(self, n: int):
        """Adds levels up to n together with their incoming skip edges."""
        for j in range(self.n + 1, n + 1):
            self.out[j] = []
            k = 1
            while j - k >= 1:
                self.out[j - k].append(j)
                k <<= 1
        self.n = max(self.n, n)

    def edges(self):
        return [(i, l) for i, targets in self.out.items() for l in targets]

    def number_of_edges(self) -> int:
        return sum(len(t) for t in self.out.values())

    def to_networkx(self) -> nx.DiGraph:
        g = nx.DiGraph()
        g.add_nodes_from(range(1, self.n + 1))
        g.add_edges_from(self.edges())
        return g


def binary_descent_path(j: int, n: int = None) -> List[int]:
    """Algorithm 1: BinaryDescentPath(j, n)."""
    i, path = 1, [1]
    while i < j:
        i += 1 << ((j - i).bit_length() - 1)
        path.append(i)
    return path


def reconstruct_path(skip: SkipDAG, j: int) -> List[int]:
    """Algorithm 3, Phase 1: forward traversal from L_1, taking at each level
    the longest skip edge (L_i, L_l) with l <= j."""
    i, path = 1, [1]
    while i < j:
        best = i + 1
        for l in skip.out.get(i, ()):
            if best < l <= j:
                best = l
        i = best
        path.append(i)
    return path


def path_hash(path: List[int], hashed: HashedLevelDAG) -> bytes:
    """PH(pi) = Hash(CH(L_i1) || ... || CH(L_ir))."""
    return Hash(b"".join(hashed.ch(i) for i in path))


def sign_element_path(x, j: int, hashed: HashedLevelDAG, keys: CryptoKeys):
    """Algorithm 2, steps 2-3: SP(x) = Sign(PH(pi(1, j)), SK), stored in x's metadata."""
    sp = keys.sign(path_hash(binary_descent_path(j), hashed))
    x.proof["level"] = j
    x.proof["signed_path"] = sp
    return sp


# ---------------------------------------------------------------------------
# Bucket indexing and Merkle trees (Section 5)
# ---------------------------------------------------------------------------

def bucket_index(digest: bytes, k: int) -> int:
    """bucket_index(x) = H(x) mod k."""
    return int.from_bytes(digest, "big") % k


def bucket_leaf(bucket: List[bytes]) -> bytes:
    """H(B_j) = Hash(H(x_1) || ... || H(x_n)), digests in canonical (sorted) order."""
    return Hash(b"".join(sorted(bucket)))


class LevelMerkle:
    """Buckets of element digests (private storage) and the Merkle tree over
    them; the signed root SMR_i is the public commitment for level L_i."""

    def __init__(self, k: int, keys: CryptoKeys):
        self.k = k
        self.keys = keys
        self.buckets: List[List[bytes]] = [[] for _ in range(k)]
        self.tree: List[List[bytes]] = []
        self.root = b""
        self.smr = b""

    @classmethod
    def build(cls, digests: List[bytes], k: int, keys: CryptoKeys) -> "LevelMerkle":
        """O(m + k): assign m digests to buckets, then build the tree bottom-up."""
        m = cls(k, keys)
        for d in digests:
            m.buckets[bucket_index(d, k)].append(d)
        level = [bucket_leaf(b) for b in m.buckets]
        m.tree = [level]
        while len(level) > 1:
            level = [Hash(level[i] + (level[i + 1] if i + 1 < len(level) else level[i]))
                     for i in range(0, len(level), 2)]
            m.tree.append(level)
        m.root = level[0]
        m.smr = keys.sign(m.root)
        return m

    def insert(self, digest: bytes):
        """Section 5.2: append to bucket, update the leaf and its path to the root, re-sign."""
        j = bucket_index(digest, self.k)
        self.buckets[j].append(digest)
        self.tree[0][j] = bucket_leaf(self.buckets[j])
        idx = j
        for depth in range(1, len(self.tree)):
            below = self.tree[depth - 1]
            left = idx - (idx % 2)
            right = left + 1 if left + 1 < len(below) else left
            idx //= 2
            self.tree[depth][idx] = Hash(below[left] + below[right])
        self.root = self.tree[-1][0]
        self.smr = self.keys.sign(self.root)

    def proof(self, j: int) -> List[Tuple[str, bytes]]:
        """MP(x): sibling hashes from leaf B_j up to the root."""
        path, idx = [], j
        for level in self.tree[:-1]:
            sib = idx ^ 1
            if sib >= len(level):
                sib = idx
            path.append(("right" if idx % 2 == 0 else "left", level[sib]))
            idx //= 2
        return path


def root_from_proof(leaf: bytes, proof: List[Tuple[str, bytes]]) -> bytes:
    h = leaf
    for side, sib in proof:
        h = Hash(h + sib) if side == "right" else Hash(sib + h)
    return h


def verify_merkle_membership(x, merkle: LevelMerkle, public_key: CryptoKeys) -> bool:
    """Section 5.3: compute j = H(x) mod k, check H(x) in B_j, rebuild the root
    from MP(x) and verify it against the signed Merkle root SMR_i."""
    hx = x.compute_full_hash()
    j = bucket_index(hx, merkle.k)
    bucket = merkle.buckets[j]
    if hx not in bucket:
        return False
    mr = root_from_proof(bucket_leaf(bucket), merkle.proof(j))
    return public_key.verify(mr, merkle.smr)


# ---------------------------------------------------------------------------
# One VERDICT instance per DAG (Data or Event)
# ---------------------------------------------------------------------------

class Verdict:
    """Hashed level DAG + skip DAG + per-level Merkle trees for one DAG."""

    def __init__(self, dag, keys: CryptoKeys = None, k_buckets: int = 4):
        self.dag = dag
        self.keys = keys or CryptoKeys()
        self.k = k_buckets
        self.hashed: Optional[HashedLevelDAG] = None
        self.skip: Optional[SkipDAG] = None
        self.merkle: Dict[int, LevelMerkle] = {}

    @property
    def n(self) -> int:
        return self.hashed.n if self.hashed else 0

    def build_skip_dag(self):
        """Hashed level DAG (ECMH + signed level hashes) and skip edges."""
        self.hashed = HashedLevelDAG.build(self.dag, self.keys)
        self.skip = SkipDAG(self.hashed.n)

    def build_merkle(self):
        """Bucket assignment, Merkle trees and signed roots for every level."""
        self.merkle = {
            lvl: LevelMerkle.build([self.dag.elements[nid].compute_full_hash() for nid in nodes],
                                   self.k, self.keys)
            for lvl, nodes in self.dag.levels.items()
        }

    def sign_all_paths(self):
        """Signed path proof for every element already in the DAG."""
        for nid, lvl in self.dag.level_map.items():
            sign_element_path(self.dag.elements[nid], lvl, self.hashed, self.keys)

    def build(self):
        self.build_skip_dag()
        self.build_merkle()
        self.sign_all_paths()
        return self

    # -- Algorithm 2 ----------------------------------------------------------
    def insert(self, x, j: int):
        """InsertIntoSkipDAG(x, j, GS, SK)."""
        if j > self.skip.n:
            self.skip.extend(j)
        hx = x.compute_full_hash()
        self.hashed.add_to_level(j, hx)
        return sign_element_path(x, j, self.hashed, self.keys)

    def insert_merkle(self, x, j: int):
        if j not in self.merkle:
            self.merkle[j] = LevelMerkle.build([], self.k, self.keys)
        self.merkle[j].insert(x.compute_full_hash())

    # -- Algorithm 3 ----------------------------------------------------------
    def verify_path(self, x) -> bool:
        """Phases 1-2: reconstruct the path to L_j and verify the signed path hash."""
        j = x.proof.get("level")
        if j is None or not 1 <= j <= self.skip.n:
            return False
        path = reconstruct_path(self.skip, j)
        if path[-1] != j:
            return False
        return self.keys.verify(path_hash(path, self.hashed), x.proof["signed_path"])

    def verify_membership(self, x) -> bool:
        """Phase 3: Merkle membership of x in L_j."""
        merkle = self.merkle.get(x.proof.get("level"))
        return merkle is not None and verify_merkle_membership(x, merkle, self.keys)

    def verify_existence(self, x) -> bool:
        """VerifyExistence(x, GS, PK)."""
        return self.verify_path(x) and self.verify_membership(x)


def verify_cross_dag(x: DataArtifact, data: Verdict, event: Verdict) -> bool:
    """Section 5.4: joint verification of x in the Data DAG and of its producing
    event e_x in the Event DAG, at the same level."""
    if not data.verify_existence(x):
        return False
    e = event.dag.events.get(x.metadata.get("event_ref"))
    if e is None or not event.verify_existence(e):
        return False
    if x.proof["level"] != e.proof["level"]:
        return False
    return event.verify_membership(e)


def build_system(nodes: int, genesis: int, edges: int, k_buckets: int = 4):
    """Generates a synthetic lineage workload and builds VERDICT on both DAGs."""
    data_dag = generate_data_dag(nodes, genesis, edges)
    event_dag = extract_event_dag(data_dag)
    data_dag.partition_into_levels()
    event_dag.partition_into_levels()
    link_producing_events(data_dag, event_dag)
    return Verdict(data_dag, k_buckets=k_buckets).build(), Verdict(event_dag, k_buckets=k_buckets).build()


def main():
    parser = argparse.ArgumentParser(description="VERDICT demo: build both DAGs and verify one artifact end to end")
    parser.add_argument("--nodes", type=int, default=10, help="Number of data artifacts")
    parser.add_argument("--genesis", type=int, default=2, help="Number of genesis nodes")
    parser.add_argument("--edges", type=int, default=2, help="Max edges per node")
    parser.add_argument("--buckets", type=int, default=4, help="Buckets per level for Merkle proof")
    parser.add_argument("--seed", type=int, default=None, help="Random seed (default: unseeded)")
    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    data, event = build_system(args.nodes, args.genesis, args.edges, args.buckets)
    assert nx.is_directed_acyclic_graph(data.dag.graph) and nx.is_directed_acyclic_graph(event.dag.graph)

    for name, v in (("Data", data), ("Event", event)):
        print(f"{name} DAG: {v.dag.graph.number_of_nodes()} nodes, {v.n} levels, "
              f"{v.skip.number_of_edges()} skip edges")
        for lvl in range(1, v.n + 1):
            print(f"  Level {lvl}: |L|={len(v.dag.levels.get(lvl, ()))}  "
                  f"H(L)={v.hashed.level_hash(lvl).hex()[:16]}...  MR={v.merkle[lvl].root.hex()[:16]}...")

    artifact_id, level = random.choice(sorted(data.dag.level_map.items()))
    art = data.dag.artifacts[artifact_id]
    print(f"\nVerifying data artifact {artifact_id} (level {level}):")
    print(f"  Binary-descent path: {binary_descent_path(level)}")
    path_ok = data.verify_path(art)
    merkle_ok = data.verify_membership(art)
    cross_ok = verify_cross_dag(art, data, event)
    print(f"  Signed path verification: {path_ok}")
    print(f"  Merkle membership verification: {merkle_ok}")
    print(f"  Cross-DAG verification (event {art.metadata['event_ref']}): {cross_ok}")
    print("  --> FULL VERIFICATION:", "SUCCESS" if path_ok and merkle_ok and cross_ok else "FAILED")


if __name__ == "__main__":
    main()
