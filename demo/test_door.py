"""The door log: what is recorded when a caller is turned away before the gate, and what
must never be recorded. No model. Run: python test_door.py"""
import base64, json, threading, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import agent, agentauth, client, invariants, kernel, oidc, server, tools
from standin_idp import StandIn

ok = fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1; print("PASS", name)
    else: fail += 1; print("FAIL", name)

ISS, AUD = "https://idp.lab.test", "warden-lab"
bot, rogue = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
idp = StandIn(ISS, AUD)
b64 = lambda x: base64.b64encode(x).decode()


def start():
    server.SESSION["gate"] = agent.new_gate(server.APPROVERS); server.SESSION["turns"] = 0
    server.LOGINS.clear(); server.LOGIN_SESSIONS.clear(); server.DOOR.clear(); server.DOOR_STATS["total"] = 0
    server.AUTH = agentauth.AgentAuth({"support_bot": base64.b64decode(client.pub_b64(bot))}, agent.BOUNDARY)
    server.IDP = oidc.Verifier(ISS, AUD, idp.jwks(), clock=lambda: server.clock())
    server.IDENT = oidc.Identities(agent.BOUNDARY)
    server.IDP_CFG = {"issuer": ISS, "audience": AUD, "authorize_url": ISS + "/authorize"}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def call(url, path, body=None):
    req = urllib.request.Request(url + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, json.load(e)


httpd, url = start()
g = lambda: server.SESSION["gate"]
A = client.Client(url, "support_bot", bot)
GOOD = "why\nNOMINATE what=orders/A-1001 verb=lookup_order args=order_id:A-1001"
codes = lambda: [e["code"] for e in server.DOOR]

# a clean request leaves nothing at the door
check("an accepted request is not logged at the door", A.nominate(GOOD)[0] == 200 and len(server.DOOR) == 0)

# each way of being turned away is recorded with its own reason
body = A.sign(GOOD); body["signature"] = b64(b"x" * 64)
A.post(body)
check("a bad signature is recorded", codes()[-1] == "bad_signature")
body = A.sign(GOOD); A.post(body); A.post(body)
check("a replay is recorded", codes()[-1] == "replay")
A.post(A.sign(GOOD, ts=A.clock() - 3600))
check("a stale request is recorded", codes()[-1] == "stale")
client.Client(url, "root", rogue).nominate(GOOD)
check("an unknown agent is recorded", codes()[-1] == "unknown_agent")
client.Client(url, "support_bot", rogue).nominate(GOOD)
check("a clone with the wrong key is recorded as a bad signature", codes()[-1] == "bad_signature")
check("the claimed identity is kept", [e["claimed"] for e in server.DOOR][-1] == "support_bot")
check("the source address is kept", server.DOOR[-1]["ip"] == "127.0.0.1")
check("every entry says what kind of door it was", {e["kind"] for e in server.DOOR} == {"agent"})

# the other doors
call(url, "/login", {"nonce": "made-up", "id_token": "aaa.bbb.ccc"})
check("a failed login is recorded", server.DOOR[-1]["kind"] == "login")
call(url, "/enroll", {"public_key": b64(b"k" * 32)})
check("enrolling without signing in is recorded", server.DOOR[-1]["code"] == "no_session")
call(url, "/approve", {"nonce": "n", "signature": b64(b"x" * 64)})
check("approving without signing in is recorded", server.DOOR[-1]["kind"] == "approve" and server.DOOR[-1]["code"] == "no_session")

# the gate never saw any of it
check("none of the refusals created a receipt (only the two that were valid did)", len(g().receipts) == 2)
check("the audit is clean", invariants.audit(g().receipts, g().state, server.SESSION["turns"], g().approvers) == [])

# nothing secret is written down
secret_sig = b64(b"S" * 64)
body = A.sign(GOOD); body["signature"] = secret_sig; A.post(body)
call(url, "/login", {"nonce": "NONCE-SHOULD-NOT-APPEAR", "id_token": "TOKEN.SHOULD.NOTAPPEAR"})
call(url, "/approve", {"session": "SESSION-SHOULD-NOT-APPEAR", "nonce": "N", "signature": b64(b"x" * 64)})
dump = json.dumps(list(server.DOOR))
check("no signature, token, nonce or session is ever stored",
      not any(s in dump for s in (secret_sig, "NONCE-SHOULD-NOT-APPEAR", "TOKEN.SHOULD", "SESSION-SHOULD-NOT-APPEAR", body["nonce"])))

# the claimed name is attacker text: cleaned and bounded
A.post({**A.sign(GOOD), "principal": "evil\x00\n<script>" + "A" * 200})
e = server.DOOR[-1]
check("control characters are stripped from what they claimed", "\x00" not in e["claimed"] and "\n" not in e["claimed"])
check("what they claimed is truncated", len(e["claimed"]) <= 40)
A.post({**A.sign(GOOD), "principal": {"x": 1}})
check("a non-text claim is stored as nothing", server.DOOR[-1]["claimed"] is None)

# local-only controls reached from another host
orig = server.H._local
server.H._local = lambda self: False
before = json.dumps(g().state, sort_keys=True)
code, _ = call(url, "/reset", {})
server.H._local = orig
check("a remote /reset is refused", code == 403)
check("and recorded", server.DOOR[-1]["kind"] == "local_only")
check("and nothing was reset", json.dumps(g().state, sort_keys=True) == before and len(g().receipts) == 2)

# it shows up in /state for the dashboard
d = call(url, "/state")[1]["door"]
check("the dashboard can read it", d["total"] == server.DOOR_STATS["total"] and len(d["recent"]) > 0)
check("and every row has a time", all(isinstance(r["ts"], float) for r in d["recent"]))

# a flood cannot grow memory
for _ in range(560):
    server.door("agent", "bad_signature", "support_bot", "flood", "127.0.0.1")
check("the log is bounded", len(server.DOOR) == 500)
check("but the total keeps counting", server.DOOR_STATS["total"] > 560)

# a reset of the world does not erase who knocked
server.reset()
check("resetting the demo keeps the door log", len(server.DOOR) == 500)
httpd.shutdown()

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
