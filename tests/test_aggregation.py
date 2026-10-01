import threading
import unittest

from coldledger.serialization.aggregation import (
    Aggregation, Tree, CycleError, chain_ancestors, chain_evidence,
)


class TreeTests(unittest.TestCase):
    def test_two_level_ancestor_bypass(self):
        # old code only compared parent's direct parent; walk two levels
        t = Tree()
        t.attach("case", "box")
        t.attach("box", "pack")
        # re-hanging the grandparent "case" below "pack" is a 3-node cycle
        with self.assertRaises(CycleError):
            t.attach("pack", "case")
        self.assertEqual(t.parent, {"box": "case", "pack": "box"})

    def test_self_cycle(self):
        t = Tree()
        with self.assertRaises(ValueError):
            t.attach("a", "a")

    def test_reparent_moves_node(self):
        t = Tree()
        t.attach("a", "c")
        t.attach("b", "c")
        self.assertEqual(t.parent["c"], "b")
        self.assertEqual(t.children["a"], set())
        self.assertEqual(t.children["b"], {"c"})

    def test_descendants(self):
        t = Tree()
        t.attach("a", "b")
        t.attach("b", "c")
        self.assertEqual(t.descendants("a"), {"b", "c"})

    def test_ancestors(self):
        t = Tree()
        t.attach("a", "b")
        t.attach("b", "c")
        self.assertEqual(t.ancestors("c"), ["b", "a"])


class AggregationTests(unittest.TestCase):
    def _a(self):
        a = Aggregation()
        a.attach("case", "box")
        a.attach("box", "pack")
        return a

    def test_two_level_cycle_blocked(self):
        a = self._a()
        with self.assertRaises(CycleError):
            a.attach("pack", "case")
        self.assertEqual(a.parent, {"box": "case", "pack": "box"})

    def test_rejected_attach_publishes_nothing(self):
        a = self._a()
        n_scans, n_ev = len(a.scans), len(a.evidence)
        with self.assertRaises(CycleError):
            a.attach("pack", "case")
        # no half relationship: tree untouched, no scan, no evidence entry
        self.assertEqual(a.parent, {"box": "case", "pack": "box"})
        self.assertEqual(len(a.scans), n_scans)
        self.assertEqual(len(a.evidence), n_ev)
        self.assertTrue(a.verify())

    def test_evidence_records_rejected_parents(self):
        a = self._a()
        # attach a new node under pack: evidence must witness pack's ancestors
        s = a.attach("pack", "item")
        self.assertEqual(s.rejected, ("box", "case"))
        self.assertEqual(a.evidence[-1].rejected, ("box", "case"))

    def test_scans_and_evidence_cover_every_mutation(self):
        a = Aggregation()
        a.attach("a", "b")
        a.attach("b", "c")
        a.detach("c")
        ops = [(s.op, s.parent, s.child) for s in a.scans]
        self.assertEqual(ops, [
            ("attach", "a", "b"),
            ("attach", "b", "c"),
            ("detach", None, "c"),
        ])
        self.assertEqual(len(a.scans), len(a.evidence))
        self.assertTrue(a.verify())

    def test_hash_chain_tamper_detected(self):
        a = self._a()
        self.assertTrue(a.verify())
        bad = a.evidence[0]
        object.__setattr__(bad, "parent", "forged")
        self.assertFalse(a.verify())
        with self.assertRaises(RuntimeError):
            chain_evidence(a.evidence)

    def test_scan_tree_mismatch_detected(self):
        from dataclasses import replace
        a = self._a()
        # tamper the scan journal so it no longer replays to the stored tree
        a.scans[1] = replace(a.scans[1], parent="other")
        self.assertFalse(a.verify())

    def test_replay_rejects_cyclic_evidence(self):
        from dataclasses import replace
        from coldledger.serialization.aggregation import _digest
        a = self._a()
        forged = replace(a.evidence[1], parent="pack")
        a.evidence[1] = replace(
            forged,
            digest=_digest(forged.seq, forged.op, forged.parent, forged.child,
                           forged.rejected, forged.at, a.evidence[0].digest))
        # scans left as-is: scan/evidence mismatch, so evidence cannot stand alone
        self.assertFalse(a.verify())


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_cyclic_remounts_never_publish_cycle(self):
        a = Aggregation()
        for p, c in [("r", "a"), ("a", "b"), ("b", "c")]:
            a.attach(p, c)
        barrier = threading.Barrier(2)
        errors = []

        def remount(child, parent):
            barrier.wait()
            for _ in range(200):
                try:
                    a.attach(parent, child)
                    a.attach(child, parent)  # restore / attempt reverse
                except CycleError:
                    pass
                except Exception as e:  # noqa: BLE001
                    errors.append(e)

        t1 = threading.Thread(target=remount, args=("r", "c"))
        t2 = threading.Thread(target=remount, args=("c", "r"))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])
        self.assertTrue(a.verify())
        # structural invariant: no node may be its own ancestor
        for node in list(a.parent):
            self.assertNotIn(node, chain_ancestors(a.parent, node))

    def test_concurrent_attaches_are_consistent_with_journal(self):
        a = Aggregation()
        barrier = threading.Barrier(4)

        def worker(tag):
            barrier.wait()
            for i in range(100):
                a.attach("root", "%s-%d" % (tag, i))

        threads = [threading.Thread(target=worker, args=(t,)) for t in "wxyz"]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(a.scans), 400)
        self.assertEqual(len(a.evidence), 400)
        self.assertEqual(len(a.parent), 400)
        self.assertTrue(a.verify())
        self.assertTrue(chain_evidence(a.evidence))


if __name__ == "__main__":
    unittest.main()
