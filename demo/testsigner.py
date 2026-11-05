"""A stand-in for the human's separate device, for tests and scripts. It holds an
Ed25519 PRIVATE key the gate never sees; the gate is given only the public half.
The live demo does the same job in the browser (approve.html)."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Signer:
    def __init__(self, approver_id="sam"):
        self.id = approver_id
        self._key = Ed25519PrivateKey.generate()
        self.public_raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message):
        return self._key.sign(message.encode() if isinstance(message, str) else message)

    def approve(self, gate, receipt):
        """Read the challenge off a held receipt, sign what the gate would show,
        and hand the signature back. Returns the receipt of the re-adjudication."""
        nonce = receipt["decision_basis"][-1][2].rsplit("challenge=", 1)[1]
        return gate.approve(nonce, self.id, self.sign(gate.canonical(nonce)))
