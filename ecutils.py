"""Provides additional methods missing from pymcl."""
import pymcl
import hashlib
import math

def hash_g2_to_fr(value: pymcl.G2) -> pymcl.Fr:
    """
    Hash a G2 element to a Fr element.
    
    Warning: This is a naive implementation and does not provide uniformly distributed outputs.
    Consider using a method based on RFC 9380 Section 5."""
    p = pymcl.r  # modulus of the field Fr
    
    # Hash the key to bytes using SHA-256
    h = hashlib.sha256(repr(value).encode()).digest()

    # Convert to integer
    h_int = int.from_bytes(h, byteorder='big')

    # Map to 0..p-1
    x_int = (h_int % p) 

    # Convert to Fr
    x_fr = pymcl.Fr(str(x_int))

    return x_fr

def pow_fr(base: pymcl.Fr, exponent: int) -> pymcl.Fr:
    """
    Raise a Fr element to an integer power.
    
    :param base: Base Fr element.
    :param exponent: Exponent (non-negative integer).
    :return: Result of base^exponent.
    """
    if exponent == 0:
        return pymcl.Fr("1")
    elif exponent % 2 == 0:
        half = pow_fr(base, exponent // 2)
        return half * half
    else:
        half = pow_fr(base, (exponent - 1) // 2)
        return half * half * base

def eval_polynomial(value: pymcl.Fr, coefficients: list[pymcl.Fr]) -> pymcl.Fr:
    """
    Evaluate a polynomial at a given value.

    :param value: The value to evaluate the polynomial at.
    :param coefficients: List of coefficients of the polynomial.
    :return: The evaluated polynomial.
    """
    result = pymcl.Fr("0")
    for i, coeff in enumerate(coefficients):
        result += coeff * (pow_fr(value, i))
    return result

def build_baby_step_table(base: pymcl.GT, max_value: int) -> dict[int,pymcl.GT]:
    """
    Build the baby-step table for the baby-step-giant-step algorithm.

    :param base: The base point in the elliptic curve group GT.
    :param max_value: The maximum value for the discrete logarithm (e.g. 2**24).
    :return: A dictionary representing the baby-step table.
    """

    m = math.isqrt(max_value) + 1
    baby_steps = {}
    current = base / base # neutral element
    for j in range(m):
        baby_steps[current] = j
        current *= base
    
    return baby_steps

def discrete_log(value: pymcl.GT, base: pymcl.GT, baby_steps: dict, max_value: int) -> pymcl.Fr:
    """
    Compute the discrete logarithm in an elliptic curve group using the baby-step-giant-step algorithm.

    :param value: The point in the elliptic curve group GT to compute the dlog of.
    :param base: The base point in the elliptic curve group G1.
    :param modulus: The order of the elliptic curve group.
    :param baby_steps: The precomputed baby-step table.
    :return: The discrete logarithm x such that base * x = value.
    """

    # Define the maximum value for the discrete log
    m = math.isqrt(max_value) + 1

    # Compute the giant-step factor
    factor = base ** (pymcl.Fr(str(-m)))  # Negate and scale the base point

    # Perform the giant steps
    current = value
    for i in range(m):
        #print(f"Current value at step {i}: {current}")
        if current in baby_steps:
            #print(f"Match found: {current}")
            return pymcl.Fr(str(i * m + baby_steps[current]))
        current *= factor  # Elliptic curve point addition

    # If no solution is found
    raise ValueError("Discrete logarithm not found within the range.")


def message_to_pymcl_fr(message: str, msg_lengths: int) -> list[pymcl.Fr]:
    """
    Convert a message to numbers and split it into pymcl.Fr elements of no more than msg_lengths bits.

    :param message: The input message as a string.
    :param msg_lengths: The maximum number of bits for each pymcl.Fr element.
    :return: A list of pymcl.Fr elements.
    """
    # Convert the message to its byte representation
    message_bytes = message.encode()
    
    # Split the bytes into chunks that fit into msg_lengths bits
    chunk_size = msg_lengths // 8  # Convert bits to bytes
    chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

    # Convert each chunk to a pymcl.Fr element
    fr_elements = [pymcl.Fr(str(int.from_bytes(chunk, byteorder='big'))) for chunk in chunks]

    return fr_elements


def pymcl_fr_to_message(fr_elements: list[pymcl.Fr], msg_lengths: int) -> str:
    """
    Reconstruct a message string from a list of pymcl.Fr elements.

    :param fr_elements: The list of pymcl.Fr elements.
    :param msg_lengths: The maximum number of bits for each pymcl.Fr element.
    :return: The reconstructed message as a string.
    """
    # Convert each pymcl.Fr element to an integer and then to bytes
    chunk_size = msg_lengths // 8  # Convert bits to bytes
    message_bytes = b''.join(
        int(fr.__str__()).to_bytes(chunk_size, byteorder='big').lstrip(b'\x00') for fr in fr_elements
    )

    # Decode the bytes back to a string
    return message_bytes.decode()