"""Human identity: token verification, login, and what a session can and cannot do.
No model, no internet. The identity provider is the stand-in; everything the verifier
checks is attacked here with tokens an adversary could actually build."""
import base64, copy, hashlib, hmac, json, tempfile, threading, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
import yaml
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import agent, agentauth, client, invariants, kernel, oidc, server, tools
from standin_idp import StandIn, b64u
from testsigner import Signer

SPEC = yaml.safe_load(open("boundary.yaml"))
ISS, AUD = "https://idp.lab.test", "warden-lab"
NOW = 1_800_000_000
ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1; print("PASS", name)
    else:
        fail += 1; print("FAIL", name)


def refused(fn):
    try: fn()
    except oidc.OIDCError: return True
    return False


idp = StandIn(ISS, AUD, clock=lambda: NOW)
ver = oidc.Verifier(ISS, AUD, idp.jwks(), clock=lambda: NOW)
good = lambda **o: idp.issue("sub-sam", "sam@lab.test", "n1", **o)

# ---- the verifier ------------------------------------------------------------------
check("a good token verifies", ver.verify(good(), "n1")["email"] == "sam@lab.test")

def forge(header, claims, key=None, sig=None):
    h = b64u(json.dumps(header).encode()); p = b64u(json.dumps(claims).encode())
    return h + "." + p + "." + (sig if sig is not None else "")
claims = {"iss": ISS, "aud": AUD, "sub": "sub-sam", "email": "sam@lab.test", "email_verified": True,
          "nonce": "n1", "iat": NOW, "exp": NOW + 300}

check("alg none is refused", refused(lambda: ver.verify(forge({"alg": "none", "kid": "standin-1"}, claims), "n1")))
check("alg NONE variants are refused", refused(lambda: ver.verify(forge({"alg": "None"}, claims), "n1")))
# the classic confusion: HS256 signed with the issuer's PUBLIC key bytes as the secret
pub_bytes = json.dumps(idp.jwks()["keys"][0]).encode()
h = b64u(json.dumps({"alg": "HS256", "kid": "standin-1"}).encode()); p = b64u(json.dumps(claims).encode())
mac = b64u(hmac.new(pub_bytes, (h + "." + p).encode(), hashlib.sha256).digest())
check("HS256 signed with the public key is refused", refused(lambda: ver.verify(h + "." + p + "." + mac, "n1")))
check("a key cannot be used under the wrong algorithm",
      refused(lambda: ver.verify(idp.sign(claims, {"alg": "RS256"}), "n1")))
check("wrong issuer refused", refused(lambda: ver.verify(good(iss="https://evil.test"), "n1")))
check("token for another app refused", refused(lambda: ver.verify(good(aud="someone-else"), "n1")))
check("multi-audience without azp refused", refused(lambda: ver.verify(good(aud=[AUD, "other"]), "n1")))
check("multi-audience with our azp accepted", ver.verify(good(aud=[AUD, "other"], azp=AUD), "n1")["sub"] == "sub-sam")
check("expired token refused", refused(lambda: ver.verify(good(exp=NOW - 120), "n1")))
check("token issued in the future refused", refused(lambda: ver.verify(good(iat=NOW + 3600, exp=NOW + 7200), "n1")))
check("a login that is too old refused", refused(lambda: ver.verify(good(iat=NOW - 3600, exp=NOW + 60), "n1")))
check("wrong nonce refused", refused(lambda: ver.verify(good(), "n2")))
check("missing nonce refused", refused(lambda: ver.verify(good(nonce=None), "n1")))
check("empty expected nonce refused", refused(lambda: ver.verify(good(nonce=""), "")))
check("unverified email refused", refused(lambda: ver.verify(good(email_verified=False), "n1")))
check("email_verified as a string refused", refused(lambda: ver.verify(good(email_verified="true"), "n1")))
check("missing exp refused", refused(lambda: ver.verify(good(exp=None), "n1")))
check("missing subject refused", refused(lambda: ver.verify(good(sub=None), "n1")))

tok = good(); h, p, s = tok.split(".")
swapped = json.loads(base64.urlsafe_b64decode(p + "==")); swapped["email"] = "attacker@lab.test"
check("tampered payload refused", refused(lambda: ver.verify(h + "." + b64u(json.dumps(swapped).encode()) + "." + s, "n1")))
other = StandIn(ISS, AUD)                                           # same kid, different key
check("signed by a key the issuer never published refused",
      refused(lambda: ver.verify(other.issue("sub-sam", "sam@lab.test", "n1", iat=NOW, exp=NOW + 300), "n1")))
check("unknown key id refused", refused(lambda: ver.verify(idp.sign(claims, {"kid": "nope"}), "n1")))
for junk in ("", "a.b", "a.b.c", "....", "x" * 50, None):
    check(f"malformed token {str(junk)[:8]!r} refused", refused(lambda j=junk: ver.verify(j, "n1")))
rsa_idp = rsa.generate_private_key(65537, 2048)                      # an RSA key under RS256 is accepted by design
import base64 as _b
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
nums = rsa_idp.public_key().public_numbers()
jwk = {"kty": "RSA", "kid": "rsa-1", "n": b64u(nums.n.to_bytes(256, "big")), "e": b64u(nums.e.to_bytes(3, "big"))}
hh = b64u(json.dumps({"alg": "RS256", "kid": "rsa-1"}).encode()); pp = b64u(json.dumps(claims).encode())
rs = b64u(rsa_idp.sign((hh + "." + pp).encode(), padding.PKCS1v15(), hashes.SHA256()))
check("a real RS256 token verifies",
      oidc.Verifier(ISS, AUD, {"keys": [jwk]}, clock=lambda: NOW).verify(hh + "." + pp + "." + rs, "n1")["sub"] == "sub-sam")

# ---- who a login maps to ---------------------------------------------------------------
b = kernel.Boundary(copy.deepcopy(SPEC))
ids = oidc.Identities(b)
c = lambda **o: {"iss": ISS, "sub": "sub-sam", "email": "sam@lab.test", **o}
check("a known email maps to its person", ids.principal_for(c()) == "sam")
check("email case does not matter", ids.principal_for(c(email="SAM@Lab.Test")) == "sam")
check("an unknown email maps to no one", refused(lambda: ids.principal_for(c(email="x@lab.test"))))
check("the same email under a different provider account is refused",
      refused(lambda: ids.principal_for(c(sub="someone-else"))))
try:
    s2 = copy.deepcopy(SPEC); s2["principals"]["pat"] = {"kind": "human", "groups": ["supervisors"], "login": "sam@lab.test"}
    kernel.Boundary(s2); dup = False
except kernel.BoundaryError: dup = True
check("two people cannot share a login", dup)
try:
    s2 = copy.deepcopy(SPEC); s2["principals"]["support_bot"]["login"] = "bot@lab.test"
    kernel.Boundary(s2); agent_login = False
except kernel.BoundaryError: agent_login = True
check("an agent cannot have a login", agent_login)

# ---- over HTTP: login, enrolment, approval -------------------------------------------------
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
KEYS = {"support_bot": Ed25519PrivateKey.generate()}


def start(spec=SPEC):
    bnd = kernel.Boundary(copy.deepcopy(spec))
    server.APPROVERS.clear(); server.LOGINS.clear(); server.LOGIN_SESSIONS.clear()
    server.SESSION["gate"] = kernel.Gate(bnd, tools.seed(), tools.REGISTRY, principal=None, approvers=server.APPROVERS)
    server.SESSION["turns"] = 0
    server.AUTH = agentauth.AgentAuth({p: base64.b64decode(client.pub_b64(k)) for p, k in KEYS.items()}, bnd)
    server.IDP = oidc.Verifier(ISS, AUD, idp_live.jwks(), clock=lambda: server.clock())
    server.IDENT = oidc.Identities(bnd)
    server.IDP_CFG = {"issuer": ISS, "audience": AUD, "authorize_url": ISS + "/authorize"}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def call(url, path, body=None):
    req = urllib.request.Request(url + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


idp_live = StandIn(ISS, AUD)                                          # real clock, for the live server
def login_as(url, sub="sub-sam", email="sam@lab.test", **o):
    nonce = call(url, "/login/start")[1]["nonce"]
    return nonce, idp_live.issue(sub, email, nonce, **o)

httpd, url = start()
a = client.Client(url, "support_bot", KEYS["support_bot"])
REFUND = "bigger\nNOMINATE what=orders/A-1002 verb=issue_refund args=order_id:A-1002;amount_cents:4000"

code, st = call(url, "/login/start")
check("login start gives a one-time nonce and where to log in", code == 200 and st["nonce"] and st["client_id"] == AUD)
nonce, token = login_as(url)
code, r = call(url, "/login", {"nonce": nonce, "id_token": token})
check("a valid login gives a session for the right person", code == 200 and r["principal"] == "sam" and r["enrolled"] is False)
sam_session = r["session"]
check("the same login cannot be replayed", call(url, "/login", {"nonce": nonce, "id_token": token})[0] == 401)
n2, _ = login_as(url); _, t_other = login_as(url)
check("a token minted for a different nonce is refused", call(url, "/login", {"nonce": n2, "id_token": t_other})[0] == 401)
check("and that nonce is spent either way", call(url, "/login", {"nonce": n2, "id_token": idp_live.issue("sub-sam", "sam@lab.test", n2)})[0] == 401)
n3, _ = login_as(url)
check("an unknown nonce is refused", call(url, "/login", {"nonce": "made-up", "id_token": idp_live.issue("sub-sam", "sam@lab.test", "made-up")})[0] == 401)
check("someone the boundary does not know cannot log in",
      call(url, "/login", {"nonce": n3, "id_token": idp_live.issue("sub-x", "stranger@lab.test", n3)})[0] == 401)
nE, tE = login_as(url, iat=0, exp=1)
check("an expired token cannot log in", call(url, "/login", {"nonce": nE, "id_token": tE})[0] == 401)

dev = Signer("sam")
b64 = lambda x: base64.b64encode(x).decode()
check("enrolling with no session is refused", call(url, "/enroll", {"public_key": b64(dev.public_raw)})[0] == 401)
check("enrolling with a made-up session is refused", call(url, "/enroll", {"session": "x" * 32, "public_key": b64(dev.public_raw)})[0] == 401)
check("the old no-login enrolment is gone", call(url, "/enroll", {"principal": "sam", "public_key": b64(dev.public_raw)})[0] == 401)
check("enrolling with a session works", call(url, "/enroll", {"session": sam_session, "public_key": b64(dev.public_raw)})[0] == 200)
intruder = Signer("sam")
check("a key cannot be swapped once enrolled", call(url, "/enroll", {"session": sam_session, "public_key": b64(intruder.public_raw)})[0] == 400)

code, held = a.nominate(REFUND)
check("the agent's refund is held", held["receipt"]["decision"] == "HOLD")
pend = call(url, "/approval/state")[1]["pending"][0]
sign = lambda s: b64(s.sign(pend["canonical"]))
check("approving with no session is refused (a stolen device key is not enough)",
      call(url, "/approve", {"nonce": pend["nonce"], "signature": sign(dev)})[0] == 401)
check("approving with a session but the wrong key is refused (a stolen session is not enough)",
      call(url, "/approve", {"session": sam_session, "nonce": pend["nonce"], "signature": sign(intruder)})[0] == 400)
check("the request cannot name a different approver",
      call(url, "/approve", {"session": sam_session, "approver": "support_bot", "nonce": pend["nonce"], "signature": sign(intruder)})[0] == 400)
exp = server.LOGIN_SESSIONS[sam_session]["expires"]; server.LOGIN_SESSIONS[sam_session]["expires"] = 0
check("an expired session cannot approve", call(url, "/approve", {"session": sam_session, "nonce": pend["nonce"], "signature": sign(dev)})[0] == 401)
check("and is dropped", sam_session not in server.LOGIN_SESSIONS)
n4, t4 = login_as(url); sam_session = call(url, "/login", {"nonce": n4, "id_token": t4})[1]["session"]
code, r = call(url, "/approve", {"session": sam_session, "nonce": pend["nonce"], "signature": sign(dev)})
check("login + device key + signature approves", code == 200 and r["receipt"]["decision"] == "ACCEPT")
check("the audit is clean", invariants.audit(server.SESSION["gate"].receipts, server.SESSION["gate"].state,
                                             server.SESSION["turns"], server.SESSION["gate"].approvers) == [])
httpd.shutdown()

# two people: only the agent's OWNER can approve, whatever they hold
spec2 = copy.deepcopy(SPEC)
spec2["principals"]["pat"] = {"kind": "human", "groups": ["supervisors"], "name": "Pat", "login": "pat@lab.test"}
httpd, url = start(spec2)
a = client.Client(url, "support_bot", KEYS["support_bot"])
sessions, devs = {}, {}
for who, email in (("sam", "sam@lab.test"), ("pat", "pat@lab.test")):
    n, t = login_as(url, sub="sub-" + who, email=email)
    sessions[who] = call(url, "/login", {"nonce": n, "id_token": t})[1]["session"]
    devs[who] = Signer(who); call(url, "/enroll", {"session": sessions[who], "public_key": b64(devs[who].public_raw)})
a.nominate(REFUND)
pend = call(url, "/approval/state")[1]["pending"][0]
check("only the owner is offered the approval", pend["approvers"] == ["sam"])
code, r = call(url, "/approve", {"session": sessions["pat"], "nonce": pend["nonce"], "signature": b64(devs["pat"].sign(pend["canonical"]))})
check("another logged-in person with a valid key cannot approve", code == 400)
code, r = call(url, "/approve", {"session": sessions["pat"], "nonce": pend["nonce"], "signature": b64(devs["sam"].sign(pend["canonical"]))})
check("nor with the owner's signature, from their own session", code == 400)
code, r = call(url, "/approve", {"session": sessions["sam"], "nonce": pend["nonce"], "signature": b64(devs["sam"].sign(pend["canonical"]))})
check("the owner can", code == 200 and r["receipt"]["decision"] == "ACCEPT")
httpd.shutdown()

# no identity provider configured: fail closed
httpd, url = start()
server.IDP = None
check("login off -> /login/start is unavailable", call(url, "/login/start")[0] == 503)
check("login off -> nobody can enroll", call(url, "/enroll", {"session": "x", "public_key": b64(dev.public_raw)})[0] == 401)
check("login off -> nobody can approve", call(url, "/approve", {"session": "x", "nonce": "x", "signature": b64(b"x" * 64)})[0] == 401)
httpd.shutdown()

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
