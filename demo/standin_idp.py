"""A STAND-IN identity provider. LAB AND TESTS ONLY.

It exists so the login flow can be built and tested without the internet or a real
account. It is NOT an identity system: anyone who knows its passphrase can sign in as
anyone it lists. Point Warden at a real provider (Google, GitHub-via-OIDC, Microsoft)
by replacing the issuer, audience and keys in idp.json; nothing else changes.

    python3 standin_idp.py serve --issuer http://10.77.77.10:8090 --port 8090

writes idp.json (public keys only; copy it to the Warden host) and serves /authorize.
"""
import argparse, base64, html, json, os, secrets, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = os.path.dirname(os.path.abspath(__file__))
KEYFILE = os.path.join(HERE, "keys", "standin_idp.pem")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class StandIn:
    def __init__(self, issuer, audience, key=None, kid="standin-1", clock=time.time):
        self.issuer, self.audience, self.kid, self.clock = issuer, audience, kid, clock
        self.key = key or ec.generate_private_key(ec.SECP256R1())

    def jwks(self):
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
                          "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}]}

    def issue(self, sub, email, n, /, **override):
        """Mint an ID token. Anything in `override` replaces a claim (None removes it),
        so tests can build the malformed tokens an attacker would."""
        now = int(self.clock())
        claims = {"iss": self.issuer, "aud": self.audience, "sub": sub, "email": email,
                  "email_verified": True, "nonce": n, "iat": now, "exp": now + 300}
        claims.update(override)
        claims = {k: v for k, v in claims.items() if v is not None}
        return self.sign(claims)

    def sign(self, claims, header=None):
        h = {"alg": "ES256", "typ": "JWT", "kid": self.kid}
        h.update(header or {})
        signing = b64u(json.dumps(h).encode()) + "." + b64u(json.dumps(claims).encode())
        r, s = decode_dss_signature(self.key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        return signing + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def load_or_create_key():
    os.makedirs(os.path.dirname(KEYFILE), exist_ok=True)
    if os.path.exists(KEYFILE):
        return serialization.load_pem_private_key(open(KEYFILE, "rb").read(), None)
    k = ec.generate_private_key(ec.SECP256R1())
    open(KEYFILE, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    return k


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Lab sign-in</title><body style="font:16px system-ui;background:#070b14;color:#e6ecf8;max-width:380px;margin:12vh auto;padding:0 18px">
<p style="color:#ffb020;font-size:13px;letter-spacing:.1em">LAB STAND-IN IDENTITY PROVIDER. NOT A REAL LOGIN.</p>
<form method=post><input type=hidden name=nonce value="{nonce}"><input type=hidden name=redirect_uri value="{redirect}">
<p>Sign in as<br><select name=user style="font:inherit;padding:8px;width:100%">{options}</select></p>
<p>Lab passphrase<br><input type=password name=pass style="font:inherit;padding:8px;width:100%" autofocus></p>
<button style="font:inherit;padding:10px 18px">Sign in</button></form>{err}"""


def make_handler(idp, users, passphrase):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _page(self, nonce, redirect, err=""):
            opts = "".join(f"<option value={html.escape(u)}>{html.escape(u)} ({html.escape(e)})</option>" for u, (e, _) in users.items())
            b = PAGE.format(nonce=html.escape(nonce), redirect=html.escape(redirect), options=opts,
                            err=f"<p style=color:#ff5468>{html.escape(err)}</p>" if err else "").encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
            if u.path == "/jwks":
                b = json.dumps(idp.jwks()).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b); return
            if u.path != "/authorize" or q.get("client_id", [""])[0] != idp.audience:
                self.send_response(400); self.end_headers(); return
            self._page(q.get("nonce", [""])[0], q.get("redirect_uri", [""])[0])

        def do_POST(self):
            f = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            nonce, redirect, user = (f.get(k, [""])[0] for k in ("nonce", "redirect_uri", "user"))
            if not secrets.compare_digest(f.get("pass", [""])[0], passphrase) or user not in users:
                return self._page(nonce, redirect, "wrong passphrase")
            if not redirect.startswith(("http://", "https://")):
                self.send_response(400); self.end_headers(); return
            email, sub = users[user]
            tok = idp.issue(sub, email, nonce)
            self.send_response(302); self.send_header("Location", redirect + "#id_token=" + tok); self.end_headers()
    return H


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["serve"])
    ap.add_argument("--issuer", required=True)
    ap.add_argument("--audience", default="warden-lab")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--users", default='{"sam": ["sam@lab.test", "standin-sub-sam"]}')
    a = ap.parse_args()
    idp = StandIn(a.issuer, a.audience, load_or_create_key())
    users = {u: tuple(v) for u, v in json.loads(a.users).items()}
    passphrase = os.environ.get("STANDIN_PASSPHRASE") or secrets.token_urlsafe(9)
    cfg = {"issuer": a.issuer, "audience": a.audience, "authorize_url": a.issuer + "/authorize", "jwks": idp.jwks()}
    json.dump(cfg, open(os.path.join(HERE, "idp.json"), "w"), indent=1)
    print(f"stand-in IdP on :{a.port}  issuer={a.issuer}  wrote idp.json (public keys only)")
    print(f"lab passphrase: {passphrase}   (set STANDIN_PASSPHRASE to choose one)", flush=True)
    ThreadingHTTPServer((a.host, a.port), make_handler(idp, users, passphrase)).serve_forever()
