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


class Ciphertext(NamedTuple):
    """Ciphertext of SWE scheme."""

    h: pymcl.G2
    c: pymcl.G2
    c0: pymcl.G2
    c1: list[pymcl.G2]  # c_j in paper
    c2: list[pymcl.GT]  # c'_i in paper
    a: list[pymcl.G2]
    t: list[pymcl.G1]

# Define global variables to make them accessible to other functions
BABY_STEPS_TABLE = None
gt = None
max_value = None

def setup():
    global BABY_STEPS_TABLE, gt, max_value
    gt = pymcl.pairing(pymcl.g1, pymcl.g2)  # generator point of GT
    max_value = 2**24  # Maximum value for discrete log
    BABY_STEPS_TABLE = ecutils.build_baby_step_table(gt, max_value)

def encrypt(
    dec_threshold: int,
    ver_keys: list[pymcl.G2],
    sign_messages: list[str],
    messages: list[pymcl.Fr],
) -> Ciphertext:
    """
    Encrypt a list of messages using signature-based witness encryption (SWE)
    relative to the given verification keys and signing messages.

    :param threshold: Number of signatures required to decrypt.
    :param ver_keys: List of verification keys.
    :param sign_messages: List of messages that need to be signed to allow decryption.
    :param messages: List of messages to encrypt. We require each message to be in [0, 2^msg_lengths) for some msg_lengths for decryption.
    :return: Ciphertext.
    """
    coefficients: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(dec_threshold-1)]
    xi: list[pymcl.Fr] = [ecutils.hash_g2_to_fr(ver_keys[i]) for i in range(len(ver_keys))]
    s: list[pymcl.Fr]  = [ecutils.eval_polynomial(xi[i], coefficients) for i in range(len(ver_keys))]
    alpha: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(len(messages))]
    r: pymcl.Fr = pymcl.Fr.random()
    c: pymcl.Fr = pymcl.g2 * r
    a: list[pymcl.G2] =  [c * alpha[i] for i in range(len(messages))]
    t: list[pymcl.G1] = [pymcl.G1.hash(sign_messages[i].encode())*alpha[i] for i in range(len(sign_messages))] 
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
    signatures: list[pymcl.G1],
    ver_keys: list[pymcl.G2],
    used_vk_indices: list[int],
    msg_lengths: int,
) -> list[pymcl.Fr]:
    """
    Decrypt a SWE ciphertext.

    :param ctxt: SWE ciphertext.
    :param signatures: List of signatures on sign_messages, where each signature is an aggregate signature for the same subset of verification keys.
    :param ver_keys: List of all verification keys.
    :used_vk_indices: Sorted list of indices of ver_keys used for the signatures.
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
        ctxt.c2[i] * pymcl.pairing(signatures[i], ctxt.a[i]) / pymcl.pairing(ctxt.t[i], c)
        for i in range(len(ctxt.c2))
    ]
     
    msg: list[pymcl.Fr] = [ecutils.discrete_log(z[i], gt, BABY_STEPS_TABLE, max_value) for i in range(len(z))]

    for i in range(len(msg)):
        if msg[i] is None:
            raise ValueError("Decryption failed.")

    return msg


def main():
    # set global parameters
    msg_lengths = 24
    num_keys = 4
    dec_threshold = 3  # number of keys required to sign messages to decrypt

    # Set some messages and signing messages
    msgs = [pymcl.Fr("123"), pymcl.Fr("456"), pymcl.Fr("789"), pymcl.Fr("30000")]
    sign_messages = ["msg1", "msg2", "msg3", "msg4"]

    # generate signing and verification keys
    modbls_keys = [modbls.key_gen() for _ in range(num_keys)]
    sks, ver_keys = zip(*modbls_keys)
    sks = list(sks)
    ver_keys = list(ver_keys)

    # encrypt messages
    ctxt = encrypt(dec_threshold, ver_keys, sign_messages, msgs)
    print("Ciphertext:")
    pprint(dict(ctxt._asdict()))

    # sample a random subset of size threshold of keys to use for signing
    used_key_indices = sorted(random.sample(range(num_keys), dec_threshold))
    print("Used verification key indices:")
    print(used_key_indices)

    # every key in used_key_indices signs all messages in sign_messages
    signatures = []
    for i in range(len(sign_messages)):
        sigs = [
            modbls.sign(sks[used_key_indices[j]], sign_messages[i])
            for j in range(dec_threshold)
        ]
        # aggregate signatures
        aggregated_signature = modbls.agg_sigs(
            sigs, [ver_keys[used_key_indices[j]] for j in range(dec_threshold)]
        )
        signatures.append(aggregated_signature)

    # decrypt messages
    setup() # Initialize the baby-step table and setup the global variables
    dec_msgs = decrypt(ctxt, signatures, ver_keys, used_key_indices, max_value)
    print("Decrypted messages:")
    print(dec_msgs)


if __name__ == "__main__":
    main()
