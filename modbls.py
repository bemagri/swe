"""Prototype implementation of BLS signature scheme with modified aggregation.

See paper https://eprint.iacr.org/2022/433.pdf for details.
Requires pymcl library for pairing operations, see https://github.com/Jemtaly/pymcl.
"""
import pymcl
import hashtofr

def key_gen() -> tuple[pymcl.Fr, pymcl.G2]:
    """
    Generate BLS key pair.

    :return: Private key and public key.
    """
    sk = pymcl.Fr.random()
    pk = pymcl.g2 * sk
    return sk, pk

def sign(sk: pymcl.Fr, message: str) -> pymcl.G1:
    """
    Sign a message using BLS signature scheme.

    :param sk: Private key.
    :param message: Message to sign.
    :return: Signature.
    """
    h = pymcl.G1.hash(message.encode())
    sig = h * sk
    return sig

def verify(vk: pymcl.G2, message: str, sig: pymcl.G1) -> bool:
    """
    Verify a BLS signature.

    :param vk: Verification key.
    :param message: Signed message.
    :param sig: Signature to verify.
    :return: True if the signature is valid, False otherwise.
    """
    h = pymcl.G1.hash(message.encode())
    return pymcl.pairing(sig, pymcl.g2) == pymcl.pairing(h, vk)

def agg_sigs(sigs: list[pymcl.G1], ver_keys: list[pymcl.G2]) -> pymcl.G1:
    """
    Aggregate a list of BLS signatures using modified aggregation method.

    :param sigs: List of signatures to aggregate.
    :param ver_keys: List of verification keys corresponding to the signatures.
    :return: Aggregated signature.
    """
    xi = [hashtofr.hash(ver_keys[i]) for i in range(len(ver_keys))]
    agg_sig = pymcl.g1 - pymcl.g1 # Initialize to neutral element of G1
    for i in range(len(ver_keys)):
        li = compute_li(xi, i)
        agg_sig += sigs[i] * li
    
    return agg_sig

def agg_verify(agg_sig: pymcl.G1, messages: list[str], ver_keys: list[pymcl.G2]) -> bool:
    """
    Verify an aggregated BLS signature obtained from modified aggregation method.

    :param agg_sig: Aggregated signature to verify.
    :param messages: List of messages corresponding to the signatures.
    :param ver_keys: List of verification keys corresponding to the signatures.
    :return: True if the aggregated signature is valid, False otherwise.
    """
    if len(messages) != len(ver_keys):
        raise ValueError("Number of messages must match number of verification keys.")
    
    xi = [hashtofr.hash(ver_keys[i]) for i in range(len(ver_keys))]
    lhs = pymcl.pairing(agg_sig, pymcl.g2)
    rhs = pymcl.pairing(pymcl.g1 - pymcl.g1, pymcl.g2 - pymcl.g2) # Initialize to neutral element of GT
    for i in range(len(messages)):
        h = pymcl.G1.hash(messages[i].encode())
        pair = pymcl.pairing(h, ver_keys[i])
        rhs *= pair ** compute_li(xi, i)
    return lhs == rhs

def compute_li(xi: list[pymcl.Fr], i: int) -> pymcl.Fr:
    """
    Compute the Lagrange coefficient for index i.

    :param xi: List of xi values.
    :param i: Index for which to compute the coefficient.
    :return: Lagrange coefficient.
    """
    li = pymcl.Fr("1")
    for j in range(len(xi)):
        if i != j:
            li *= (-xi[j]) / (xi[i] - xi[j])
    return li