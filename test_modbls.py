import unittest
import modbls

class TestCalculations(unittest.TestCase):
    # Test basic signatures
    def test_sign_verify(self):
        (sk, vk) = modbls.key_gen()
        bls_signature = modbls.sign(sk, "message")
        self.assertTrue(modbls.verify(vk, "message", bls_signature), 'Correct signature does not verify.')

    def test_sign_verify_wrong_msg(self):
        (sk, vk) = modbls.key_gen()
        bls_signature = modbls.sign(sk, "message")
        self.assertFalse(modbls.verify(vk, "wessage", bls_signature), 'Signature for wrong message verifies.')
    
    def test_sign_verify_wrong_vk(self):
        (sk1, vk1) = modbls.key_gen()
        (sk2, vk2) = modbls.key_gen()
        bls_signature = modbls.sign(sk1, "message")
        self.assertFalse(modbls.verify(vk2, "message", bls_signature), 'Signature verifies for wrong key.')

    # Test aggregation of signatures
    def test_aggregate_signatures_same_msg_verify(self):
        # Generate key pairs
        (sk1, vk1) = modbls.key_gen()
        (sk2, vk2) = modbls.key_gen()

        # Sign the same message with both private keys
        sig1 = modbls.sign(sk1, "message")
        sig2 = modbls.sign(sk2, "message")

        # Aggregate the signatures
        aggregated_signature = modbls.agg_sigs([sig1, sig2], [vk1, vk2])

        # Verify the aggregated signature
        self.assertTrue(
            modbls.agg_verify(aggregated_signature, ["message", "message"], [vk1, vk2]),
            "Aggregated signature does not verify."
        )
    
    def test_aggregate_signatures_diff_msg_verify(self):
        # Generate key pairs
        (sk1, vk1) = modbls.key_gen()
        (sk2, vk2) = modbls.key_gen()

        # Sign different message with both private keys
        sig1 = modbls.sign(sk1, "message1")
        sig2 = modbls.sign(sk2, "message2")

        # Aggregate the signatures
        aggregated_signature = modbls.agg_sigs([sig1, sig2], [vk1, vk2])

        # Verify the aggregated signature
        self.assertTrue(
            modbls.agg_verify(aggregated_signature, ["message1", "message2"], [vk1, vk2]),
            "Aggregated signature does not verify."
        )

    def test_aggregate_signatures_verify_wrong_message(self):
        # Generate key pairs
        (sk1, vk1) = modbls.key_gen()
        (sk2, vk2) = modbls.key_gen()

        # Sign different message with both private keys
        sig1 = modbls.sign(sk1, "message1")
        sig2 = modbls.sign(sk2, "message2")

        # Aggregate the signatures
        aggregated_signature = modbls.agg_sigs([sig1, sig2], [vk1, vk2])

        # Verify the aggregated signature
        self.assertFalse(
            modbls.agg_verify(aggregated_signature, ["message2", "message1"], [vk1, vk2]),
            "Aggregated signature for wrong message verifies."
        )

    def test_aggregate_signatures_verify_partial_keys(self):
        # Generate key pairs
        (sk1, vk1) = modbls.key_gen()
        (sk2, vk2) = modbls.key_gen()

        # Sign different message with both private keys
        sig1 = modbls.sign(sk1, "message1")
        sig2 = modbls.sign(sk2, "message2")

        # Aggregate the signatures
        aggregated_signature = modbls.agg_sigs([sig1, sig2], [vk1, vk2])

        # Verify the aggregated signature with only one key
        self.assertFalse(
            modbls.agg_verify(aggregated_signature, ["message1"], [vk1]),
            "Aggregated signature for partial keys verify."
        )

if __name__ == '__main__':
    unittest.main()
