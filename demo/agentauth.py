"""Agent authentication for nominations arriving over a network.

WHAT THIS PROVES: the nomination was produced by a process holding the private key
registered for that agent principal. It authenticates the RUNTIME, not the model:
a prompt-injected model inside an honest runtime still signs. What it prevents is
a different process (a clone, another host, a model that got shell access) acting
as that principal without the key.

Keys are provisioned out of band, in a file on the Warden host. There is no network
enrollment for agents, so there is no trust-on-first-use window.
"""
import base64, hashlib, json, re, time
from kernel import verify_signature

NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
HEADER = "warden-nominate-v1"


class AuthError(Exception):
    pass


def canonical_nomination(principal, nonce, ts, output):
    """Exactly what the agent signs. The output is bound by hash, so the bytes the
    gate adjudicates are the bytes the agent signed."""
    return "\n".join([HEADER, f"principal:{principal}", f"nonce:{nonce}", f"ts:{int(ts)}",
                      f"output_sha256:{hashlib.sha256(output.encode()).hexdigest()}"])


def load_keys(path):
    """{principal: base64 raw Ed25519 public key} -> {principal: raw bytes}."""
    raw = json.load(open(path))
    keys = {}
    for p, b in raw.items():
        k = base64.b64decode(b, validate=True)
        if len(k) != 32:
            raise ValueError(f"{p}: an Ed25519 public key is 32 bytes")
        keys[p] = k
    return keys


class AgentAuth:
    def __init__(self, keys, boundary, clock=time.time, window=120):
        for p in keys:
            if boundary.principals.get(p, {}).get("kind") != "agent":
                raise ValueError(f"{p!r} has a key but is not an agent principal in the boundary")
        self.keys, self.clock, self.window = dict(keys), clock, window
        self.seen = {}      # (principal, nonce) -> expiry; spent nonces cannot be replayed

    def fingerprints(self):
        return {p: hashlib.sha256(k).hexdigest()[:16] for p, k in sorted(self.keys.items())}

    def verify(self, principal, nonce, ts, output, signature_b64):
        """Raise AuthError unless this exact nomination was signed by the registered key
        for `principal`, recently, and never before. Returns the principal."""
        pub = self.keys.get(principal) if isinstance(principal, str) else None
        if pub is None:
            raise AuthError("unknown agent")
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise AuthError("bad nonce")
        try:
            ts = float(ts)
            sig = base64.b64decode(signature_b64, validate=True)
        except (TypeError, ValueError):
            raise AuthError("malformed timestamp or signature")
        now = self.clock()
        if abs(now - ts) > self.window:
            raise AuthError("timestamp outside the accepted window")
        if not isinstance(output, str):
            raise AuthError("output must be text")
        # signature BEFORE touching the replay table, so unauthenticated callers
        # cannot fill it
        if not verify_signature(pub, sig, canonical_nomination(principal, nonce, ts, output).encode()):
            raise AuthError("signature does not verify")
        self.seen = {k: e for k, e in self.seen.items() if e > now}
        if (principal, nonce) in self.seen:
            raise AuthError("replayed nonce")
        self.seen[(principal, nonce)] = now + self.window * 2
        return principal
