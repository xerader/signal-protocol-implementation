"""
    defines a user
"""
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from utils.curves import ed25519_to_x25519


class User:
    """
        user class
    """

    def __init__(self) -> None:
        # keys
        self.ik = None  # long term identity key
        self.prek = None  # medium term pre key (to be signed)
        self.prek_sign = None  # signature of prek using ik
        self.eprek = []  # list of one time (ephemeral) pre keys

        # basic info
        self.name = ""
        self.password = ""
        self.phone_number = ""

    def register(self, name: str, password: str, phone_number: str) -> None:
        """
            register a new user
        """
        self.name = name
        self.password = password
        self.phone_number = phone_number

        # generate keys
        ik = ed25519.Ed25519PrivateKey.generate()  # ed25519 key to use for signing
        self.prek = x25519.X25519PrivateKey.generate()  # prekey to sign
        prek_bytes = self.prek.private_bytes_raw()  # byte form of private prek
        self.prek_sign = ik.sign(prek_bytes)  # prekey signature
        self.ik = ed25519_to_x25519(ik)  # convert ed25519 to x25519

        # generate 10 epreks
        for _ in range(10):
            self.eprek.append(x25519.X25519PrivateKey.generate())


test = User()
test.register("test", "test", "test")
