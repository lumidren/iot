"""A flat, vectorized copy of a fitted scikit-learn IsolationForest.

scikit-learn walks the trees one by one in Python, which costs about 15 ms per
window for 150 trees: too slow for scoring every device every 10 seconds on a
Raspberry Pi. Here all trees are packed into one set of arrays and walked
together, level by level, giving the same scores (tested to 1e-9) far faster.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


def _average_path_length(n: np.ndarray) -> np.ndarray:
    """Expected path length of an unsuccessful BST search over n points."""
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    out[n == 2] = 1.0
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    return out


def _node_depths(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    depth = np.zeros(len(left))
    stack = [0]
    while stack:
        node = stack.pop()
        for child in (left[node], right[node]):
            if child != -1:
                depth[child] = depth[node] + 1
                stack.append(child)
    return depth


class FastForest:
    def __init__(self, forest: IsolationForest):
        lefts, rights, feats, thresholds, leaf_values, roots = [], [], [], [], [], []
        offset = 0
        self.max_depth = 0
        for tree, subset in zip(forest.estimators_, forest.estimators_features_, strict=True):
            t = tree.tree_
            left, right = t.children_left, t.children_right
            leaf = left == -1
            depth = _node_depths(left, right)
            self.max_depth = max(self.max_depth, int(depth.max()))
            lefts.append(np.where(leaf, np.arange(t.node_count), left) + offset)
            rights.append(np.where(leaf, np.arange(t.node_count), right) + offset)
            feats.append(np.where(leaf, 0, np.asarray(subset)[np.maximum(t.feature, 0)]))
            thresholds.append(np.where(leaf, np.inf, t.threshold))
            # sklearn: (nodes on the decision path) + c(n_leaf) - 1 == depth + c(n_leaf)
            values = np.where(leaf, depth + _average_path_length(t.n_node_samples), 0.0)
            leaf_values.append(values)
            roots.append(offset)
            offset += t.node_count
        self.left = np.concatenate(lefts)
        self.right = np.concatenate(rights)
        self.feature = np.concatenate(feats)
        self.threshold = np.concatenate(thresholds)
        self.leaf_value = np.concatenate(leaf_values)
        self.roots = np.array(roots)
        self.denominator = len(forest.estimators_) * _average_path_length(
            np.array([forest.max_samples_]))[0]

    FIELDS = ("left", "right", "feature", "threshold", "leaf_value", "roots")

    def to_arrays(self) -> dict[str, np.ndarray]:
        """Plain arrays, safe to store (no pickle)."""
        out = {f"forest_{name}": getattr(self, name) for name in self.FIELDS}
        out["forest_meta"] = np.array([self.denominator, self.max_depth], dtype=np.float64)
        return out

    @classmethod
    def from_arrays(cls, arrays: dict[str, np.ndarray]) -> FastForest:
        forest = cls.__new__(cls)
        for name in cls.FIELDS:
            setattr(forest, name, np.asarray(arrays[f"forest_{name}"]))
        forest.denominator = float(arrays["forest_meta"][0])
        forest.max_depth = int(arrays["forest_meta"][1])
        return forest

    def score_samples(self, x: np.ndarray) -> np.ndarray:
        """Same as ``IsolationForest.score_samples`` (higher = more normal)."""
        x = np.atleast_2d(np.asarray(x, dtype=np.float32)).astype(np.float64)
        rows = np.arange(len(x))[:, None]
        nodes = np.broadcast_to(self.roots, (len(x), len(self.roots))).copy()
        for _ in range(self.max_depth):
            go_left = x[rows, self.feature[nodes]] <= self.threshold[nodes]
            nodes = np.where(go_left, self.left[nodes], self.right[nodes])
        depths = self.leaf_value[nodes].sum(axis=1)
        return -(2.0 ** (-depths / self.denominator))
