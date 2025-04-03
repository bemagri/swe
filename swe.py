"""Prototype implementation of signature-based witness encryption scheme.

See paper https://eprint.iacr.org/2022/433.pdf for details.
Requires pymcl library for pairing operations, see https://github.com/Jemtaly/pymcl.
"""
from typing import NamedTuple
import pymcl


class Ciphertext(NamedTuple):
    """Ciphertext of SWE scheme."""
    h: pymcl.G2
    c: pymcl.G2
    c0: pymcl.G2
    c1: list[pymcl.G2] # c_j in paper
    c2: list[pymcl.GT] # c'_i in paper
    a: list[pymcl.G2]
    t: list[pymcl.G1]

def encrypt(threshold: int, ver_keys: list[pymcl.G2], sign_messages: list[str], messages: list[pymcl.Fr]) -> Ciphertext:
    """
    Encrypt a list of messages using signature-based witness encryption (SWE)
    relative to the given verification keys and signing messages.

    :param threshold: Number of signatures required to decrypt.
    :param ver_keys: List of verification keys.
    :param sign_messages: List of messages that need to be signed to allow decryption.
    :param messages: List of messages to encrypt. We require each message to be in [0, 2^msg_lengths) for some msg_lengths for decryption.
    :return: Ciphertext.
    """ 
    coefficients: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(threshold-1)]
    xi: list[pymcl.Fr]  #= [pymcl.Fr.Hash Hash(ver_keys[i]) for _ in range(length(ver_keys))]
    s: list[pymcl.Fr]  = [eval_polynomial(xi[i], coefficients) for i in range(length(ver_keys))]
    alpha: list[pymcl.Fr] = [pymcl.Fr.random() for _ in range(length(messages))]
    r: pymcl.Fr = pymcl.Fr.random()
    a: list[pymcl.G2] =  [pymcl.g2**(r * alpha[i]) for i in range(length(messages))]
    t: list[pymcl.G1] #= [Hash(sign_messages[i]**alpha[i]) for i in range(length(sign_messages))] 
    h: pymcl.G2 = pymcl.G2.random()
    c0: pymcl.G2 = (h**r) * (pymcl.g2**coefficients[0])
    c1: list[pymcl.G2] = [(ver_keys[i]**r) * (pymcl.g2**s[i]) for i in range(length(ver_keys))]
    c2: list[pymcl.GT] = [pymcl.pairing(t[i], pymcl.g2**coefficients[0]) * (pymcl.gt ** messages[i]) for i in range(length(messages))]

    ct = Ciphertext(
        h=h,
        c=c0,
        c1=c1,
        c2=c2,
        a=a,
        t=t
    )

    return ct

def eval_polynomial(value: pymcl.Fr, coefficients: list[pymcl.Fr]) -> pymcl.Fr:
    """
    Evaluate a polynomial at a given value.

    :param value: The value to evaluate the polynomial at.
    :param coefficients: List of coefficients of the polynomial.
    :return: The evaluated polynomial.
    """
    result = pymcl.Fr(0)
    for i, coeff in enumerate(coefficients):
        result += coeff * (value ** i)
    return result

def decrypt(ctxt: Ciphertext, signatures: list[pymcl.G1], ver_keys: list[pymcl.G2], used_vk_indices: list[int], msg_lengths: int) -> list[pymcl.Fr]:
    """
    Decrypt a SWE ciphertext.

    :param ctxt: SWE ciphertext.
    :param signatures: List of signatures on sign_messages for a subset of verification keys.
    :param ver_keys: List of all verification keys.
    :used_vk_indices: Sorted list of indices of ver_keys used for the signatures, i.e., used_vk_indices[i] is the verification key signatures[i].
    :param msg_lengths: Length of the messages such that each message is in [0, 2^msg_lengths).
    :return: List of messages.
    """ 
    return None

def main():
    # set global parameters
    msg_lengths = 24
    num_ver_keys = 4
    num_used_ver_keys = 3

    # Set some messages and signing messages
    msgs = [pymcl.Fr("0"), pymcl.Fr("1"), pymcl.Fr("2"), pymcl.Fr("30000")]
    sign_messages = ["msg1", "msg2", "msg3", "msg4"]

    # generate signing and verification keys
    ver_keys = []

    # encrypt messages
    ctxt = encrypt(ver_keys, sign_messages, msgs)

    # set fixed subset of verification keys to use for signing
    used_vk_indices = []

    # sign messages
    sigs = []

    # decrypt messages
    dec_msgs = decrypt(ctxt, sigs, ver_keys, used_vk_indices, msg_lengths)

    print(dec_msgs)


if __name__ == "__main__":
    main()
