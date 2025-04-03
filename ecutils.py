"""Provides additional methods missing from pymcl."""
import pymcl
import hashlib

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
