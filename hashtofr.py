"""Provides a naive implementation of a hash function to map G2 elements to Fr elements."""
import pymcl
import hashlib

def hash(value: pymcl.G2) -> pymcl.Fr:
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
