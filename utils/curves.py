"""
    define utility functions for x25519 and ed25519
"""
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from nacl import encoding, signing


def ed25519_to_x25519(ed_key: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    """
    convert ed25519 private key to x25519 private key
    """
    ed_bytes = ed_key.private_bytes_raw()  # get private key in bytes form
    nacl_priv = signing.SigningKey(  # nacl private key
        seed=ed_bytes,
        encoder=encoding.RawEncoder
    )
    # x25519 key in bytes form
    x_bytes = nacl_priv.to_curve25519_private_key()._private_key
    x_key = x25519.X25519PrivateKey.from_private_bytes(x_bytes)  # x25519 key

    return x_key
