"""
Correctness checks for VERDICT (Sections 3-5 of the paper):
genuine elements verify; tampered or forged elements, tampered level state,
wrong level claims and cross-DAG inconsistencies are rejected.

Run with:  python -m pytest tests   (or)   python tests/test_verification.py
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import secure_lineage_system as s  # noqa: E402


def build(seed=7, nodes=150, genesis=8, edges=3):
    random.seed(seed)
    return s.build_system(nodes, genesis, edges, k_buckets=4)


def test_skip_dag_is_deterministic_binary():
    skip = s.SkipDAG(40)
    expected = {(i, i + 2 ** k) for i in range(1, 41) for k in range(6) if i + 2 ** k <= 40}
    assert set(skip.edges()) == expected


def test_binary_descent_path_matches_reconstruction_and_bound():
    skip = s.SkipDAG(5000)
    for j in range(1, 5001):
        path = s.binary_descent_path(j)
        assert path == s.reconstruct_path(skip, j)
        assert path[0] == 1 and path[-1] == j
        assert len(path) <= j.bit_length()          # floor(log2 j) + 1
        if j & (j - 1) == 0:
            assert len(path) == j.bit_length()      # tight for powers of two


def test_level_hash_is_order_independent_and_incremental():
    data, _ = build()
    lvl = max(data.dag.levels, key=lambda l: len(data.dag.levels[l]))
    hashes = [data.dag.artifacts[n].compute_full_hash() for n in data.dag.levels[lvl]]
    random.shuffle(hashes)
    assert s.ECMH(hashes).digest() == data.hashed.level_hash(lvl)


def test_genuine_elements_verify():
    data, event = build()
    for v in (data, event):
        for nid in v.dag.level_map:
            assert v.verify_existence(v.dag.elements[nid]), nid


def test_cross_dag_consistency_holds():
    data, event = build()
    for aid, art in data.dag.artifacts.items():
        e = event.dag.events[art.metadata["event_ref"]]
        assert data.dag.level_map[aid] == event.dag.level_map[e.id]
        assert s.verify_cross_dag(art, data, event), aid


def test_tampered_content_is_rejected():
    data, _ = build()
    art = data.dag.artifacts[sorted(data.dag.level_map)[5]]
    art.content += " (tampered)"
    assert not data.verify_membership(art)
    assert not data.verify_existence(art)


def test_forged_element_is_rejected():
    data, _ = build()
    genuine = data.dag.artifacts[sorted(data.dag.level_map)[5]]
    forged = s.DataArtifact("forged_artifact")
    forged.metadata[s.PROOF_KEY] = dict(genuine.proof)
    assert not data.verify_membership(forged)


def test_wrong_level_claim_is_rejected():
    data, _ = build()
    art = next(a for a in data.dag.artifacts.values() if a.proof["level"] > 2)
    art.proof["level"] -= 1
    assert not data.verify_path(art)


def test_tampered_level_breaks_paths_through_it():
    data, _ = build()
    top = data.n
    art = next(data.dag.artifacts[n] for n in data.dag.levels[top])
    victim = s.binary_descent_path(top)[1]           # a level on the path to the top
    other = next(iter(data.dag.levels[victim]))
    data.hashed.acc[victim].add(b"injected node")      # adversary injects a node
    del data.hashed._prefix[victim - 1:]
    assert not data.verify_path(art)
    assert data.verify_path(data.dag.artifacts[other]) is False


def test_cross_dag_level_mismatch_is_rejected():
    data, event = build()
    art = next(a for a in data.dag.artifacts.values() if a.proof["level"] > 2)
    e = event.dag.events[art.metadata["event_ref"]]
    e.proof["level"] -= 1
    assert not s.verify_cross_dag(art, data, event)


def test_insertion_algorithm2():
    data, _ = build()
    n_before = data.n
    x = s.DataArtifact("new_artifact")
    data.insert(x, n_before + 1)                        # creates a new level
    data.insert_merkle(x, n_before + 1)
    assert data.n == n_before + 1 and data.skip.n == n_before + 1
    assert data.verify_existence(x)
    y = s.DataArtifact("new_artifact_2")
    data.insert(y, 3)                                   # existing level
    data.insert_merkle(y, 3)
    assert data.verify_existence(y)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
