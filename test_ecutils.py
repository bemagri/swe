import unittest
import pymcl
import ecutils

class TestECUtils(unittest.TestCase):
    def setUp(self):
        # Initialize the elliptic curve group parameters
        self.base = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point of GT
        self.modulus = pymcl.r  # Order of the group
        self.max_value = 2**24  # Maximum value for discrete log
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
        computed_log = ecutils.discrete_log(value, self.base, self.baby_steps, self.max_value)
        self.assertEqual(computed_log, exponent)

    def test_discrete_log_not_found(self):
        # Test for a value not in the range
        with self.assertRaises(ValueError):
            invalid_value = self.base ** (pymcl.Fr(str(self.max_value)) + pymcl.Fr("9999999"))
            ecutils.discrete_log(invalid_value, self.base, self.baby_steps, self.max_value)

    def test_message_to_pymcl_fr_valid(self):
        # Test conversion of a message to pymcl.Fr elements
        message = "Hello, world!"
        msg_lengths = 128  # Maximum bits for each Fr element
        fr_elements = ecutils.message_to_pymcl_fr(message, msg_lengths)
        
        # Verify the output is a list of pymcl.Fr elements
        self.assertIsInstance(fr_elements, list)
        self.assertTrue(all(isinstance(fr, pymcl.Fr) for fr in fr_elements))
        
        # Verify the reconstructed message matches the original
        reconstructed_message = ecutils.pymcl_fr_to_message(fr_elements, msg_lengths)
        self.assertEqual(reconstructed_message, message)

    def test_message_to_pymcl_fr_empty_message(self):
        # Test conversion of an empty message
        message = ""
        msg_lengths = 128
        fr_elements = ecutils.message_to_pymcl_fr(message, msg_lengths)
        
        # Verify the output is an empty list
        self.assertEqual(fr_elements, [])
        
        # Verify the reconstructed message is also empty
        reconstructed_message = ecutils.pymcl_fr_to_message(fr_elements, msg_lengths)
        self.assertEqual(reconstructed_message, message)

    def test_message_to_pymcl_fr_large_message(self):
        # Test conversion of a large message
        message = "A" * 1000  # A long message
        msg_lengths = 256
        fr_elements = ecutils.message_to_pymcl_fr(message, msg_lengths)
        
        # Verify the output is a list of pymcl.Fr elements
        self.assertIsInstance(fr_elements, list)
        self.assertTrue(all(isinstance(fr, pymcl.Fr) for fr in fr_elements))
        
        # Verify the reconstructed message matches the original
        reconstructed_message = ecutils.pymcl_fr_to_message(fr_elements, msg_lengths)
        self.assertEqual(reconstructed_message, message)

    def test_message_to_pymcl_fr_invalid_msg_lengths(self):
        # Test invalid msg_lengths (e.g., too small to fit any character)
        message = "Test"
        msg_lengths = 4  # Too small to fit any character
        with self.assertRaises(ValueError):
            ecutils.message_to_pymcl_fr(message, msg_lengths)

            
if __name__ == "__main__":
    unittest.main()

            