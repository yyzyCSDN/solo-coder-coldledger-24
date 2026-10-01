import threading
import unittest

from coldledger.serialization.aggregation import AggregationAudit, Tree


class AggregationTreeTests(unittest.TestCase):
    def test_rejects_ancestor_reattach_after_two_levels(self):
        tree = Tree()
        tree.attach("case", "pack")
        tree.attach("pack", "box")
        tree.attach("box", "item")

        with self.assertRaisesRegex(ValueError, "cycle"):
            tree.attach("item", "case")

        self.assertEqual(tree.children["item"], set())
        self.assertEqual(tree.descendants("case"), {"pack", "box", "item"})

        last_scan = tree.scan_records[-1]
        last_evidence = tree.evidence_records[-1]
        self.assertFalse(last_scan.allowed)
        self.assertEqual(last_scan.ancestors, ("box", "pack", "case"))
        self.assertEqual(last_evidence.action, "aggregate.attach.denied")
        self.assertTrue(tree.audit.verify())

    def test_rejects_descendant_reparenting_after_two_levels(self):
        tree = Tree()
        tree.attach("case", "pack")
        tree.attach("pack", "box")
        tree.attach("box", "item")

        with self.assertRaisesRegex(ValueError, "cycle"):
            tree.attach("item", "pack")

        self.assertEqual(tree.parent["pack"], "case")
        self.assertEqual(tree.scan_records[-1].descendants, ("box", "item"))
        self.assertTrue(tree.audit.verify())

    def test_reparenting_does_not_falsely_reject_current_branch(self):
        tree = Tree()
        tree.attach("case", "pack")
        tree.attach("pack", "box")
        tree.attach("old-root", "pack")

        self.assertEqual(tree.parent["pack"], "old-root")
        self.assertNotIn("pack", tree.children["case"])
        self.assertIn("pack", tree.children["old-root"])

    def test_concurrent_attempts_are_serialized_and_cannot_publish_cycle(self):
        tree = Tree()
        tree.attach("a", "b")
        tree.attach("b", "c")
        start = threading.Barrier(3)
        outcomes = []

        def mount_a_under_root():
            start.wait()
            try:
                tree.attach("root", "a")
            except ValueError as exc:
                outcomes.append(str(exc))
            else:
                outcomes.append("accepted")

        def mount_root_under_a():
            start.wait()
            try:
                tree.attach("a", "root")
            except ValueError as exc:
                outcomes.append(str(exc))
            else:
                outcomes.append("accepted")

        threads = [threading.Thread(target=mount_a_under_root), threading.Thread(target=mount_root_under_a)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join()

        self.assertCountEqual(outcomes, ["accepted", "cycle"])
        self.assertEqual(len(tree.scan_records), 4)
        self.assertFalse(
            "a" in tree.descendants("root") and "root" in tree.descendants("a")
        )
        self.assertTrue(tree.audit.verify())

    def test_audit_failure_does_not_publish_a_half_edge(self):
        class FailingAudit(AggregationAudit):
            def record(self, **kwargs):
                raise RuntimeError("audit unavailable")

        tree = Tree(FailingAudit())
        with self.assertRaises(RuntimeError):
            tree.attach("case", "pack")

        self.assertEqual(tree.parent, {})
        self.assertEqual(set(tree.children), set())
        self.assertEqual(tree.scan_records, ())


if __name__ == "__main__":
    unittest.main()
