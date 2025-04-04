import unittest
import pymcl
import ecutils

class TestECUtils(unittest.TestCase):
    def setUp(self):
        # Initialize the elliptic curve group parameters
        self.base = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point
        self.modulus = pymcl.r  # Order of the group
        self.max_value = 2**20  # Maximum value for discrete log
        self.baby_steps = ecutils.build_baby_step_table(self.base, self.max_value)

    def test_baby_step_table(self):
        # Verify the baby-step table contains expected values
        m = int(self.max_value**0.5) + 1
        for j in range(m):
            current = self.base ** pymcl.Fr(str(j)) 
            self.assertIn(current, self.baby_steps)
            self.assertEqual(self.baby_steps[current], j)

    def test_discrete_log_in_gt(self):
        # Test discrete log computation for known values
        exponent = pymcl.Fr("12345")  # Example exponent
        value = self.base ** exponent  # Compute base^exponent
        computed_log = ecutils.discrete_log_in_gt(value, self.base, self.baby_steps, self.max_value)
        self.assertEqual(computed_log, exponent)

    def test_discrete_log_not_found(self):
        # Test for a value not in the range
        with self.assertRaises(ValueError):
            invalid_value = self.base ** (pymcl.Fr(str(self.max_value)) + pymcl.Fr("1"))
            ecutils.discrete_log_in_gt(invalid_value, self.base, self.baby_steps, self.max_value)

if __name__ == "__main__":
    unittest.main()
