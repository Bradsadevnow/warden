"""The agent side of the wire: sign a nomination and send it to a Warden service.

    python3 client.py keygen support_bot          # writes keys/support_bot.key, prints the public half
    python3 client.py send  support_bot http://10.77.77.12:8077 "reasoning...\nNOMINATE ..."

The private key never leaves the agent's machine. The service holds only the public half.
"""
import base64, json, os, secrets, sys, time, urllib.error, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from agentauth import canonical_nomination

KEYDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def keygen(principal):
    os.makedirs(KEYDIR, exist_ok=True)
    path = os.path.join(KEYDIR, f"{principal}.key")
    if os.path.exists(path):
        raise SystemExit(f"{path} exists; refusing to overwrite a private key")
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption())
    with open(path, "w") as f:
        f.write(base64.b64encode(raw).decode())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return pub_b64(k)


def pub_b64(k):
    return base64.b64encode(k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def load_key(principal):
    raw = base64.b64decode(open(os.path.join(KEYDIR, f"{principal}.key")).read())
    return Ed25519PrivateKey.from_private_bytes(raw)


class Client:
    def __init__(self, url, principal, key=None, clock=time.time):
        self.url, self.principal, self.clock = url.rstrip("/"), principal, clock
        self.key = key or load_key(principal)

    def sign(self, output, nonce=None, ts=None):
        nonce = nonce or secrets.token_urlsafe(18)
        ts = int(self.clock() if ts is None else ts)
        sig = self.key.sign(canonical_nomination(self.principal, nonce, ts, output).encode())
        return {"principal": self.principal, "nonce": nonce, "ts": ts, "output": output,
                "signature": base64.b64encode(sig).decode()}

    def post(self, body, path="/nominate"):
        req = urllib.request.Request(self.url + path, json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def nominate(self, output):
        return self.post(self.sign(output))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "keygen":
        print(json.dumps({sys.argv[2]: keygen(sys.argv[2])}))
    elif len(sys.argv) == 5 and sys.argv[1] == "send":
        code, body = Client(sys.argv[3], sys.argv[2]).nominate(sys.argv[4].replace("\\n", "\n"))
        print(code, json.dumps(body, indent=2))
    else:
        raise SystemExit(__doc__)
