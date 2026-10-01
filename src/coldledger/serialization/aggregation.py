from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from threading import RLock
from typing import Iterable


GENESIS = "GENESIS"


def _digest(payload: object) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ScanRecord:
    sequence: int
    parent: str
    child: str
    old_parent: str | None
    ancestors: tuple[str, ...]
    descendants: tuple[str, ...]
    allowed: bool
    reason: str
    at: datetime
    digest: str


@dataclass(frozen=True)
class EvidenceRecord:
    sequence: int
    actor: str
    action: str
    scan_digest: str
    at: datetime
    previous: str
    digest: str


@dataclass(frozen=True)
class AuditEntry:
    scan: ScanRecord
    evidence: EvidenceRecord


class AggregationAudit:
    """Hash-linked scan and audit evidence for aggregation mounts."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = RLock()

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    @property
    def scan_records(self) -> tuple[ScanRecord, ...]:
        with self._lock:
            return tuple(entry.scan for entry in self._entries)

    @property
    def evidence(self) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(entry.evidence for entry in self._entries)

    def record(
        self,
        *,
        parent: str,
        child: str,
        old_parent: str | None,
        ancestors: Iterable[str],
        descendants: Iterable[str],
        allowed: bool,
        actor: str = "system",
        reason: str = "",
    ) -> AuditEntry:
        at = datetime.now(timezone.utc)
        with self._lock:
            sequence = len(self._entries) + 1
            scan_payload = {
                "sequence": sequence,
                "parent": parent,
                "child": child,
                "old_parent": old_parent,
                "ancestors": tuple(ancestors),
                "descendants": tuple(descendants),
                "allowed": allowed,
                "reason": reason,
                "at": at,
            }
            scan = ScanRecord(
                digest=_digest(scan_payload),
                **scan_payload,
            )
            previous = self._entries[-1].evidence.digest if self._entries else GENESIS
            action = "aggregate.attach.allowed" if allowed else "aggregate.attach.denied"
            evidence_payload = {
                "sequence": sequence,
                "actor": actor,
                "action": action,
                "scan_digest": scan.digest,
                "at": at,
                "previous": previous,
            }
            evidence = EvidenceRecord(
                digest=_digest(evidence_payload),
                **evidence_payload,
            )
            entry = AuditEntry(scan, evidence)
            self._entries.append(entry)
            return entry

    def verify(self) -> bool:
        with self._lock:
            previous = GENESIS
            for expected_sequence, entry in enumerate(self._entries, start=1):
                scan = entry.scan
                evidence = entry.evidence

                scan_payload = asdict(scan)
                scan_digest = scan_payload.pop("digest")
                if _digest(scan_payload) != scan_digest:
                    return False

                evidence_payload = asdict(evidence)
                evidence_digest = evidence_payload.pop("digest")
                if _digest(evidence_payload) != evidence_digest:
                    return False

                if scan.sequence != expected_sequence:
                    return False
                if evidence.sequence != expected_sequence:
                    return False
                if evidence.previous != previous:
                    return False
                if evidence.scan_digest != scan.digest:
                    return False

                previous = evidence.digest
            return True


class Tree:
    def __init__(self, audit: AggregationAudit | None = None) -> None:
        self.parent: dict[str, str] = {}
        self.children: defaultdict[str, set[str]] = defaultdict(set)
        self.audit = audit or AggregationAudit()
        self._lock = RLock()

    @property
    def scan_records(self) -> tuple[ScanRecord, ...]:
        return self.audit.scan_records

    @property
    def evidence_records(self) -> tuple[EvidenceRecord, ...]:
        return self.audit.evidence

    def attach(self, parent: str, child: str, actor: str = "system") -> AuditEntry:
        with self._lock:
            old_parent = self.parent.get(child)
            ancestor_chain = self._ancestors(parent)
            descendant_chain = self._descendants(child)

            if parent == child:
                reason = "self cycle"
            elif child in ancestor_chain or parent in descendant_chain:
                reason = "cycle"
            else:
                reason = ""
            allowed = not reason

            # Build the candidate before publishing the allowed audit entry.
            # A failure here leaves the current tree untouched.
            next_parent: dict[str, str] | None = None
            next_children: defaultdict[str, set[str]] | None = None
            if allowed:
                next_parent = dict(self.parent)
                next_children = defaultdict(
                    set,
                    {node: set(children) for node, children in self.children.items()},
                )
                if old_parent is not None:
                    next_children[old_parent].discard(child)
                next_parent[child] = parent
                next_children[parent].add(child)

            entry = self.audit.record(
                parent=parent,
                child=child,
                old_parent=old_parent,
                ancestors=ancestor_chain,
                descendants=descendant_chain,
                allowed=allowed,
                actor=actor,
                reason=reason,
            )
            if not allowed:
                raise ValueError(reason)

            # Both indexes are replaced inside the same serialization point.
            assert next_parent is not None
            assert next_children is not None
            self.parent = next_parent
            self.children = next_children
            return entry

    def detach(self, child: str) -> str | None:
        with self._lock:
            parent = self.parent.get(child)
            if parent is None:
                return None

            next_parent = dict(self.parent)
            next_children = defaultdict(
                set,
                {node: set(children) for node, children in self.children.items()},
            )
            next_parent.pop(child, None)
            next_children[parent].discard(child)
            self.parent = next_parent
            self.children = next_children
            return parent

    def ancestors(self, node: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._ancestors(node))

    def _ancestors(self, node: str) -> list[str]:
        out: list[str] = []
        seen = {node}
        current = self.parent.get(node)
        while current is not None:
            if current in seen:
                raise ValueError("corrupt aggregation tree")
            seen.add(current)
            out.append(current)
            current = self.parent.get(current)
        return out

    def _descendants(self, root: str) -> list[str]:
        out: list[str] = []
        q = deque([root])
        seen = {root}
        while q:
            current = q.popleft()
            for child in self.children.get(current, ()):
                if child in seen:
                    raise ValueError("corrupt aggregation tree")
                seen.add(child)
                out.append(child)
                q.append(child)
        return out

    def descendants(self, root: str) -> set[str]:
        with self._lock:
            return set(self._descendants(root))
