"""Who is this person? Verify an OpenID Connect ID token and map it to a human principal.

This answers ONE question: which person logged in. It does not authorize anything
by itself. Approving a held action still needs that person's enrolled device key
and a signature over the exact action. A stolen token alone cannot approve; a
stolen device key alone cannot approve.

What is checked, on every token: it is signed by a key the issuer published (RS256 or
ES256 only; `none` and symmetric algorithms are refused, and the key's type must match
the algorithm), it was issued by the issuer we trust, it is addressed to this app, it
has not expired and was not issued in the future, it carries the one-time nonce we
issued for this login, and the provider says the email is verified.
"""
import base64, json, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ALLOWED_ALGS = ("RS256", "ES256")


class OIDCError(Exception):
    pass


def b64u(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _int(s):
    return int.from_bytes(b64u(s), "big")


def public_key_from_jwk(jwk):
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if kty == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    raise OIDCError("unsupported key type")


class Verifier:
    def __init__(self, issuer, audience, jwks, clock=time.time, leeway=30, max_age=600):
        """`jwks` is {"keys": [...]} or a callable returning it (so a real provider's
        rotating keys can be fetched). `max_age` bounds how old the login may be."""
        self.issuer, self.audience, self.clock = issuer, audience, clock
        self.leeway, self.max_age = leeway, max_age
        self._jwks = jwks

    def _keys(self):
        j = self._jwks() if callable(self._jwks) else self._jwks
        return {k["kid"]: k for k in j.get("keys", []) if "kid" in k}

    def verify(self, token, nonce):
        """Return the claims, or raise OIDCError. `nonce` is the one this login was issued."""
        try:
            h64, p64, s64 = token.split(".")
            header, claims = json.loads(b64u(h64)), json.loads(b64u(p64))
            sig = b64u(s64)
        except (ValueError, AttributeError, TypeError):
            raise OIDCError("not a well-formed token")
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise OIDCError("not a well-formed token")

        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:                      # refuses none, HS256, and anything exotic
            raise OIDCError(f"algorithm {alg!r} is not accepted")
        jwk = self._keys().get(header.get("kid"))
        if jwk is None:
            raise OIDCError("signed by a key the issuer does not publish")
        want = {"RS256": "RSA", "ES256": "EC"}[alg]
        if jwk.get("kty") != want:                       # a key cannot be used under the wrong algorithm
            raise OIDCError("key type does not match the algorithm")
        key = public_key_from_jwk(jwk)
        signing_input = (h64 + "." + p64).encode()
        try:
            if alg == "RS256":
                key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            else:
                if len(sig) != 64:
                    raise OIDCError("bad signature")
                key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                           signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise OIDCError("signature does not verify")

        now = self.clock()
        if claims.get("iss") != self.issuer:
            raise OIDCError("wrong issuer")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.audience not in auds or (len(auds) > 1 and claims.get("azp") != self.audience):
            raise OIDCError("token is for a different app")
        for k in ("exp", "iat"):
            if not isinstance(claims.get(k), (int, float)) or isinstance(claims.get(k), bool):
                raise OIDCError(f"missing or bad {k}")
        if claims["exp"] + self.leeway < now:
            raise OIDCError("token expired")
        if claims["iat"] - self.leeway > now:
            raise OIDCError("token issued in the future")
        if now - claims["iat"] > self.max_age:
            raise OIDCError("login is too old; sign in again")
        if not nonce or claims.get("nonce") != nonce:
            raise OIDCError("nonce does not match this login")
        if claims.get("email_verified") is not True:
            raise OIDCError("the provider has not verified this email")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OIDCError("token has no subject")
        if not isinstance(claims.get("email"), str) or "@" not in claims["email"]:
            raise OIDCError("token has no email")
        return claims


class Identities:
    """Maps a verified login to a human principal. The boundary says which email belongs
    to whom (`login:` on a human principal). On first use the provider's stable subject
    id is remembered, and after that the SAME subject must come back: an email that gets
    reassigned at the provider does not inherit the person's authority."""

    def __init__(self, boundary):
        self.by_email = {d["login"].lower(): p for p, d in boundary.principals.items() if d.get("login")}
        self.subjects = {}        # principal -> (issuer, sub)

    def principal_for(self, claims):
        p = self.by_email.get(claims["email"].lower())
        if p is None:
            raise OIDCError("this login is not mapped to anyone here")
        bound = self.subjects.setdefault(p, (claims["iss"], claims["sub"]))
        if bound != (claims["iss"], claims["sub"]):
            raise OIDCError("this email is bound to a different account at the provider")
        return p
