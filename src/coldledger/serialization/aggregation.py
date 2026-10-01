"""Serialization aggregation: parent/child packing of serialised units.

Three artifacts jointly maintain the ancestor invariant ("no node is an
ancestor of itself"):

* the aggregation tree (``parent`` / ``children``) - structural state;
* the scan journal (``scans``) - every attach/detach is recorded;
* the audit evidence (``evidence``) - a hash chain proving the ordered
  sequence of relationships, including the rejected-parent set that
  witnesses why an attach was blocked.

Concurrency: mounts are *serialised*. Every public mutation takes a write
lock and stages the tree, scans and evidence on private copies first. Only
when all three can be produced are the references swapped in a single
critical section; any failure leaves the previously published state
untouched, so a rejected attach can never publish half a parent/child edge.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from threading import RLock

GENESIS = "GENESIS"


class CycleError(ValueError):
    """Raised when an attach would make a node its own ancestor."""


@dataclass(frozen=True)
class Scan:
    seq: int
    at: datetime
    op: str
    parent: str | None
    child: str
    rejected: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    seq: int
    at: datetime
    op: str
    parent: str | None
    child: str
    rejected: tuple[str, ...]
    previous: str
    digest: str


def _digest(seq, op, parent, child, rejected, at, previous):
    raw = json.dumps(
        [seq, op, parent, child, list(rejected),
         at.astimezone(timezone.utc).isoformat(), previous],
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def chain_ancestors(parent, node):
    """Full ancestor chain of ``node`` (excluding the node itself)."""
    out = []
    cur = parent.get(node)
    while cur is not None:
        if cur in out:  # defensive: stored state must never be cyclic
            raise CycleError("stored tree is cyclic")
        out.append(cur)
        cur = parent.get(cur)
    return out


def chain_evidence(records):
    """Recompute every evidence digest in order; raise on a broken link."""
    previous = GENESIS
    out = []
    for e in records:
        digest = _digest(e.seq, e.op, e.parent, e.child, e.rejected, e.at, previous)
        if e.previous != previous or e.digest != digest:
            raise RuntimeError("evidence chain broken at %d" % e.seq)
        previous = digest
        out.append(digest)
    return out


class Tree:
    """Mutable parent/child forest with full transitive cycle checks."""

    def __init__(self):
        self.parent = {}
        self.children = defaultdict(set)
        self._lock = RLock()

    @staticmethod
    def _ancestors(parent, node):
        return chain_ancestors(parent, node)

    def ancestors(self, node):
        with self._lock:
            return self._ancestors(self.parent, node)

    def attach(self, parent, child):
        with self._lock:
            if parent == child:
                raise ValueError("self cycle")
            if child in self._ancestors(self.parent, parent):
                raise CycleError("cycle: %s is an ancestor of %s" % (child, parent))
            if child in self.parent:
                self.children[self.parent[child]].discard(child)
            self.parent[child] = parent
            self.children[parent].add(child)

    def detach(self, child):
        with self._lock:
            p = self.parent.pop(child, None)
            if p:
                self.children[p].discard(child)

    def descendants(self, root):
        with self._lock:
            out = set()
            q = deque([root])
            while q:
                x = q.popleft()
                for c in self.children[x]:
                    if c not in out:
                        out.add(c)
                        q.append(c)
            return out


class Aggregation:
    """Tree + scan journal + audit evidence, committed atomically."""

    def __init__(self):
        self.parent: dict[str, str] = {}
        self.children: dict[str, set[str]] = defaultdict(set)
        self.scans: list[Scan] = []
        self.evidence: list[Evidence] = []
        self._lock = RLock()

    @property
    def tree(self):
        """Structural view, kept consistent with scans and evidence."""
        with self._lock:
            t = Tree()
            t.parent = dict(self.parent)
            t.children = defaultdict(set, {k: set(v) for k, v in self.children.items()})
            return t

    def ancestors(self, node):
        with self._lock:
            return chain_ancestors(self.parent, node)

    def descendants(self, root):
        with self._lock:
            out = set()
            q = deque([root])
            while q:
                x = q.popleft()
                for c in self.children[x]:
                    if c not in out:
                        out.add(c)
                        q.append(c)
            return out

    def _commit(self, op, parent, child, rejected=(), at=None):
        """Stage tree, scan and evidence on copies, then publish together."""
        at = at or datetime.now(timezone.utc)
        with self._lock:
            new_parent = dict(self.parent)
            new_children = defaultdict(set)
            for k, v in self.children.items():
                new_children[k] = set(v)
            new_scans = list(self.scans)
            new_evidence = list(self.evidence)

            if op == "attach":
                old = new_parent.pop(child, None)
                if old is not None:
                    new_children[old].discard(child)
                new_parent[child] = parent
                new_children[parent].add(child)
            else:  # detach
                old = new_parent.pop(child, None)
                if old is not None:
                    new_children[old].discard(child)
                parent = None

            seq = len(new_scans) + 1
            scan = Scan(seq, at, op, parent if op == "attach" else None,
                        child, tuple(rejected))
            previous = new_evidence[-1].digest if new_evidence else GENESIS
            digest = _digest(seq, op, scan.parent, child, scan.rejected, at, previous)
            new_scans.append(scan)
            new_evidence.append(
                Evidence(seq, at, op, scan.parent, child, scan.rejected, previous, digest))

            # Single critical-section publish: either all three land or none.
            self.parent, self.children = new_parent, new_children
            self.scans, self.evidence = new_scans, new_evidence
            return scan

    def attach(self, parent, child, at=None):
        with self._lock:
            if parent == child:
                raise ValueError("self cycle")
            rejected = tuple(self.ancestors(parent))
            if child in rejected:
                raise CycleError(
                    "cycle: %s is an ancestor of %s" % (child, parent))
            return self._commit("attach", parent, child, rejected, at)

    def detach(self, child, at=None):
        with self._lock:
            if child not in self.parent:
                return None
            return self._commit("detach", None, child, (), at)

    def verify(self):
        """Re-check all three artifacts and their cross-consistency."""
        with self._lock:
            try:
                chain_evidence(self.evidence)
            except RuntimeError:
                return False
            parent: dict[str, str] = {}
            children: dict[str, set[str]] = defaultdict(set)
            if len(self.scans) != len(self.evidence):
                return False
            for scan, ev in zip(self.scans, self.evidence):
                if scan.seq != ev.seq or scan.op != ev.op \
                        or scan.parent != ev.parent or scan.child != ev.child \
                        or scan.rejected != ev.rejected:
                    return False
                if scan.op == "attach":
                    if scan.child in chain_ancestors(parent, scan.parent):
                        return False  # evidence would have created a cycle
                    old = parent.pop(scan.child, None)
                    if old is not None:
                        children[old].discard(scan.child)
                    parent[scan.child] = scan.parent
                    children[scan.parent].add(scan.child)
                elif scan.op == "detach":
                    old = parent.pop(scan.child, None)
                    if old is not None:
                        children[old].discard(scan.child)
                else:
                    return False
                # the rejected set recorded as evidence must be the true chain
                if tuple(chain_ancestors(parent, scan.parent)
                         if scan.op == "attach" else ()) != scan.rejected:
                    return False
            return parent == self.parent and all(
                children[k] == self.children.get(k, set())
                for k in set(children) | set(self.children))
