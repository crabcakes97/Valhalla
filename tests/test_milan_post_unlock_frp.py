import hashlib
import unittest

from research.milan_post_unlock_frp import patch_payload


class MilanPostUnlockFrpResearchTests(unittest.TestCase):
    def setUp(self):
        self.expected_context = bytes.fromhex("47f2ee72934264d047f270029342")
        self.patched_context = bytes.fromhex("47f2ee72934209d047f270029342")
        self.branch_offset = 10
        self.input = b"HEAD" + self.expected_context + b"TAIL"
        self.digest = hashlib.sha256(self.input).hexdigest()

    def patch(self, data=None, **overrides):
        arguments = {
            "expected_size": len(self.input),
            "expected_sha256": self.digest,
            "branch_offset": self.branch_offset,
            "expected_context": self.expected_context,
            "patched_context": self.patched_context,
        }
        arguments.update(overrides)
        return patch_payload(self.input if data is None else data, **arguments)

    def test_changes_only_the_guarded_branch_byte(self):
        output = self.patch()

        changed = [
            index
            for index, (old, new) in enumerate(zip(self.input, output))
            if old != new
        ]
        self.assertEqual(changed, [self.branch_offset])
        self.assertEqual(output[self.branch_offset], 0x09)

    def test_refuses_a_different_payload_hash(self):
        with self.assertRaisesRegex(ValueError, "refusing input sha256"):
            self.patch(expected_sha256="0" * 64)

    def test_refuses_unexpected_surrounding_instructions(self):
        different = bytearray(self.input)
        different[4] ^= 0xFF
        different = bytes(different)

        with self.assertRaisesRegex(ValueError, "refusing bytes"):
            self.patch(
                data=different,
                expected_sha256=hashlib.sha256(different).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
