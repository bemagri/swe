"""Prototype implementation of signature-based witness encryption scheme.

See paper https://eprint.iacr.org/2022/433.pdf for details.
Requires pymcl library for pairing operations, see https://github.com/Jemtaly/pymcl.
"""

from typing import NamedTuple
import random
from pprint import pprint
import pymcl
import ecutils
import modbls
from time import perf_counter_ns as timer
from prettytable import *

class Ciphertext(NamedTuple):
    """Ciphertext of SWE scheme."""

    h: pymcl.G2
    c: pymcl.G2
    c0: pymcl.G2
    c1: list[pymcl.G2]  # c_j in paper
    c2: list[pymcl.GT]  # c'_i in paper
    a: list[pymcl.G2]
    t: list[pymcl.G1]


def encrypt(
    dec_threshold: int,
    ver_keys: list[pymcl.G2],
    target_message: str,
    messages: list[pymcl.Fr],
) -> Ciphertext:
    """
    Encrypt a list of messages using signature-based witness encryption (SWE)
    relative to the given verification keys and signing messages.

    :param threshold: Number of signatures required to decrypt.
    :param ver_keys: List of verification keys.
    :param target_message: Messages that needs to be signed to allow decryption.
    :param messages: List of messages to encrypt. We require each message to be in [0, 2^msg_lengths) for some msg_lengths for decryption.
    :return: Ciphertext.
    """
    coefficients: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(dec_threshold)]
    xi: list[pymcl.Fr] = [ecutils.hash_g2_to_fr(ver_keys[i]) for i in range(len(ver_keys))]
    s: list[pymcl.Fr]  = [ecutils.eval_polynomial(xi[i], coefficients) for i in range(len(ver_keys))]
    alpha: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(len(messages))]
    r: pymcl.Fr = pymcl.Fr.random()
    c: pymcl.Fr = pymcl.g2 * r
    a: list[pymcl.G2] =  [c * alpha[i] for i in range(len(messages))]
    t: list[pymcl.G1] = [pymcl.G1.hash(target_message.encode())*alpha[i] for i in range(len(messages))] 
    h: pymcl.G2 =  pymcl.g2 * pymcl.Fr.random()
    c0: pymcl.G2 = (h * r) + (pymcl.g2 * coefficients[0])
    c1: list[pymcl.G2] = [(ver_keys[i] * r) + (pymcl.g2 * s[i]) for i in range(len(ver_keys))]
    gt: pymcl.GT = pymcl.pairing(pymcl.g1, pymcl.g2)
    c2: list[pymcl.GT] = [
        pymcl.pairing(t[i], pymcl.g2 * coefficients[0]) * (gt ** messages[i])
        for i in range(len(messages))
    ]

    return Ciphertext(h, c, c0, c1, c2, a, t)


def decrypt(
    ctxt: Ciphertext,
    aggr_signature: pymcl.G1,
    ver_keys: list[pymcl.G2],
    used_vk_indices: list[int],
    msg_lengths: int,
    baby_steps_table: dict[int,pymcl.GT],
) -> list[pymcl.Fr]:
    """
    Decrypt a SWE ciphertext.

    :param ctxt: SWE ciphertext.
    :param aggr_signature: Aggregated signature on target_message from a subset of verification keys.
    :param ver_keys: List of all verification keys.
    :used_vk_indices: Sorted list of indices of ver_keys used for the signature.
    :param msg_lengths: Length of the messages such that each message is in [0, 2^msg_lengths).
    :return: List of messages.
    """

    #if len(signatures) < dec_threshold:
    #    raise ValueError("Not enough signatures to decrypt the message.")
    
    xi: list[pymcl.Fr] = [ecutils.hash_g2_to_fr(ver_keys[i]) for i in used_vk_indices] #iterate through used_vk_indices
    lag_coeffs: list[pymcl.Fr] = [modbls.compute_li(xi, i) for i in range(len(used_vk_indices))]
    c = pymcl.g2 - pymcl.g2  
    for idx, i in enumerate(used_vk_indices):
        c = c + (ctxt.c1[i] * lag_coeffs[idx]) #indexing lag_coeffs correctly

    z: list[pymcl.GT] = [
        ctxt.c2[i] * pymcl.pairing(aggr_signature, ctxt.a[i]) / pymcl.pairing(ctxt.t[i], c)
        for i in range(len(ctxt.c2))
    ]
    gt = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point of GT
    msg: list[pymcl.Fr] = [ecutils.discrete_log(z[i], gt, baby_steps_table, 2**msg_lengths) for i in range(len(z))]

    for i in range(len(msg)):
        if msg[i] is None:
            raise ValueError("Decryption failed.")

    return msg

def run_benchmark():
    # Print table with benchmark results
    msg_lengths_list = [16, 24]
    num_keys_list = [5, 10, 15, 20]
    dec_threshold_list = [3, 7, 11, 15]
    message_lengths = [32, 64, 128]  # in bytes
    iterations = 5

    # Table to store results
    table = PrettyTable()
    table.field_names = [
        "msg_lengths",
        "num_keys",
        "dec_threshold",
        "message_length (bytes)",
        "Setup Time (ms)",
        "Enc Time (ms)",
        "Sig Time (ms)",
        "Dec Time (ms)",
    ]

    for msg_lengths in msg_lengths_list:
        for num_keys in num_keys_list:
            for dec_threshold in dec_threshold_list:
                if dec_threshold > num_keys:
                    continue  # Skip invalid configurations
                for msg_len in message_lengths:
                    total_enc_time = 0
                    total_sig_time = 0
                    total_dec_time = 0

                    # Generate a random message of the specified length
                    message = "A" * msg_len
                    target_message = "target_msg"
                    msgs = ecutils.message_to_pymcl_fr(message, msg_lengths)

                    # Setup
                    start_time = timer()

                    gt = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point of GT
                    baby_steps_table = ecutils.build_baby_step_table(gt, 2**msg_lengths)

                    # Generate signing and verification keys
                    modbls_keys = [modbls.key_gen() for _ in range(num_keys)]
                    sks, ver_keys = zip(*modbls_keys)
                    sks = list(sks)
                    ver_keys = list(ver_keys)

                    end_time = timer()
                    setup_time = (end_time - start_time)

                    for _ in range(iterations):
                        # Encrypt messages
                        start_time = timer()
                        ctxt = encrypt(dec_threshold, ver_keys, target_message, msgs)
                        end_time = timer()
                        total_enc_time += (end_time - start_time)

                        # Sample a random subset of size threshold of keys to use for signing
                        used_key_indices = sorted(random.sample(range(num_keys), dec_threshold))

                        # Every key in used_key_indices signs the target message
                        start_time = timer()
                        sigs = [
                            modbls.sign(sks[used_key_indices[j]], target_message)
                            for j in range(dec_threshold)
                        ]

                        # Aggregate signatures
                        aggregated_signature = modbls.agg_sigs(
                            sigs, [ver_keys[used_key_indices[j]] for j in range(dec_threshold)]
                        )
                        end_time = timer()
                        total_sig_time += (end_time - start_time)

                        # Decrypt messages
                        start_time = timer()
                        dec_msgs = decrypt(
                            ctxt,
                            aggregated_signature,
                            ver_keys,
                            used_key_indices,
                            msg_lengths,
                            baby_steps_table,
                        )
                        end_time = timer()
                        total_dec_time += (end_time - start_time)

                    # Convert times from nanoseconds to milliseconds
                    setup_time = setup_time / 1_000_000
                    average_enc_time = total_enc_time / iterations / 1_000_000
                    average_sig_time = total_sig_time / iterations / 1_000_000
                    average_dec_time = total_dec_time / iterations / 1_000_000

                    # Add results to the table
                    table.add_row(
                        [
                            msg_lengths,
                            num_keys,
                            dec_threshold,
                            msg_len,
                            f"{setup_time:.3f}",
                            f"{average_enc_time:.3f}",
                            f"{average_sig_time:.3f}",
                            f"{average_dec_time:.3f}",
                        ]
                    )

    # Print the results table
    print(table)


def main():
    # set global parameters
    msg_lengths = 24
    num_keys = 5
    dec_threshold = 3  # number of keys required to sign messages to decrypt

    total_enc_time = 0
    total_sig_time = 0
    total_dec_time = 0

    # Set some messages and signing messages
    target_message = "msg1"
    message = "The quick brown fox jumped over the lazy dog. Hello SWE!!! This is a test message."
    msgs = ecutils.message_to_pymcl_fr(message, msg_lengths)

    # Setup
    start_time = timer()
    
    gt = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point of GT
    baby_steps_table = ecutils.build_baby_step_table(gt, 2**msg_lengths)

    # generate signing and verification keys
    modbls_keys = [modbls.key_gen() for _ in range(num_keys)]
    sks, ver_keys = zip(*modbls_keys)
    sks = list(sks)
    ver_keys = list(ver_keys)

    end_time = timer()
    setup_time = (end_time - start_time)

    iterations = 10
    for _ in range(iterations):
        # encrypt messages
        start_time = timer()

        ctxt = encrypt(dec_threshold, ver_keys, target_message, msgs)
        # print("Ciphertext:")
        # pprint(dict(ctxt._asdict()))

        end_time = timer()
        total_enc_time += (end_time - start_time)

        # sample a random subset of size threshold of keys to use for signing
        used_key_indices = sorted(random.sample(range(num_keys), dec_threshold))
        # print("Used verification key indices:")
        # print(used_key_indices)

        # every key in used_key_indices signs all messages in sign_messages
        start_time = timer()

        sigs = [modbls.sign(sks[used_key_indices[j]], target_message)
            for j in range(dec_threshold) ]

        # aggregate signatures
        aggregated_signature = modbls.agg_sigs(
            sigs, [ver_keys[used_key_indices[j]] for j in range(dec_threshold)]
        )

        end_time = timer()
        total_sig_time += (end_time - start_time)

        # decrypt messages
        start_time = timer()
        dec_msgs = decrypt(ctxt, aggregated_signature, ver_keys, used_key_indices, msg_lengths, baby_steps_table)

        end_time = timer()
        total_dec_time += (end_time - start_time)

    dec_msg = ecutils.pymcl_fr_to_message(dec_msgs, msg_lengths)
    print("Decrypted message:", dec_msg)
    print("Message size: " + str(len(dec_msg)) + " bytes")

    # convert to times from nanoseconds to milliseconds
    setup_time = setup_time / 1_000_000
    average_enc_time = total_enc_time / iterations / 1_000_000
    average_sig_time = total_sig_time / iterations / 1_000_000
    average_dec_time = total_dec_time / iterations / 1_000_000
    print(f"Setup time: {setup_time:.3f} ms")
    print(f"Average encryption time over {iterations} runs: {average_enc_time:.3f} ms")
    print(f"Average signature generation time over {iterations} runs: {average_sig_time:.3f} ms")
    print(f"Average decryption time over {iterations} runs: {average_dec_time:.3f} ms")


if __name__ == "__main__":
    #main()
    run_benchmark()
