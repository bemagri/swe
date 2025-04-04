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
    :param exponent: Exponent (integer).
    :return: Result of base^exponent.
    """
    result = pymcl.Fr("1")
    for _ in range(exponent):
        result *= base
    return result

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

def build_baby_step_table(base: pymcl.GT, max_value: int) -> dict:
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
