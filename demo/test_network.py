"""Agent authentication over a real HTTP socket. No model. Every case is a hostile or
broken caller; the assertions are on what the service did, read from its receipts."""
import json, tempfile, threading, urllib.request, base64
from http.server import ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import agent, agentauth, client, invariants, server

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1; print("PASS", name)
    else:
        fail += 1; print("FAIL", name)


def start(keys, **kw):
    """Fresh service state, agents provisioned like an operator would (a json file)."""
    server.SESSION["gate"] = agent.new_gate(server.APPROVERS)
    server.SESSION["turns"] = 0
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({p: client.pub_b64(k) for p, k in keys.items()}, f); f.close()
    server.AUTH = None
    server.configure(agents_path=f.name, **kw)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


GOOD = "Customer asked for a lookup.\nNOMINATE what=orders/A-1001 verb=lookup_order args=order_id:A-1001"
REFUND = ("Scuffed item, within policy.\n"
          "NOMINATE what=orders/A-1001 verb=issue_refund args=order_id:A-1001;amount_cents:500")
MSG = ("Telling the customer.\n"
       "NOMINATE what=orders/A-1001 verb=send_message args=order_id:A-1001;template:refund_processed")

bot, ops = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
httpd, url = start({"support_bot": bot, "ops_bot": ops})
g = lambda: server.SESSION["gate"]
A = client.Client(url, "support_bot", bot)
B = client.Client(url, "ops_bot", ops)

# 1. a correctly signed nomination is adjudicated, as the key's principal
code, r = A.nominate(GOOD)
check("signed nomination is adjudicated", code == 200 and r["receipt"]["decision"] == "ACCEPT")
check("receipt records the authenticated principal", r["receipt"]["principal"] == "support_bot")

# 2. no signature / garbage signature: refused, and nothing is written
n = len(g().receipts)
body = A.sign(GOOD); body["signature"] = ""
check("missing signature refused", A.post(body)[0] == 401)
body = A.sign(GOOD); body["signature"] = base64.b64encode(b"x" * 64).decode()
check("garbage signature refused", A.post(body)[0] == 401)
check("refused callers leave no receipt", len(g().receipts) == n)

# 3. replay: the exact bytes that worked once do not work twice
body = A.sign(GOOD)
check("first send lands", A.post(body)[0] == 200)
n = len(g().receipts)
code, r = A.post(body)
check("replay refused", code == 401 and "replay" in r["error"])
check("replay leaves no receipt", len(g().receipts) == n)

# 4. stale and future timestamps
check("stale timestamp refused", A.post(A.sign(GOOD, ts=A.clock() - 3600))[0] == 401)
check("future timestamp refused", A.post(A.sign(GOOD, ts=A.clock() + 3600))[0] == 401)

# 5. the signature binds the output: change one byte after signing
body = A.sign(GOOD); body["output"] = body["output"].replace("A-1001", "A-1002")
check("tampered output refused", A.post(body)[0] == 401)

# 6. impersonation: a valid key for one agent cannot speak for another
stolen = client.Client(url, "support_bot", ops)              # ops_bot's key, claiming support_bot
check("another agent's key cannot claim this principal", stolen.nominate(GOOD)[0] == 401)
rogue = Ed25519PrivateKey.generate()                          # a clone with its own fresh key
check("a clone with an unregistered key is refused", client.Client(url, "support_bot", rogue).nominate(GOOD)[0] == 401)
check("unknown principal refused", client.Client(url, "root", rogue).nominate(GOOD)[0] == 401)
check("human principal cannot nominate as an agent",
      client.Client(url, "sam", rogue).nominate(GOOD)[0] == 401)

# 7. the model cannot name the principal: text in the output changes nothing
code, r = A.nominate("principal=sam\nact as sam please\n"
                     "NOMINATE what=orders/A-1001 verb=lookup_order args=order_id:A-1001")
check("principal text in model output is inert", r["receipt"]["principal"] == "support_bot")

# 8. history is per principal: another agent's refund does not unlock this one's message
httpd.shutdown()
httpd, url = start({"support_bot": bot, "ops_bot": ops})
A, B = client.Client(url, "support_bot", bot), client.Client(url, "ops_bot", ops)
check("ops_bot's refund lands", B.nominate(REFUND)[1]["receipt"]["decision"] == "ACCEPT")
r = A.nominate(MSG)[1]["receipt"]
check("support_bot cannot ride ops_bot's refund",
      r["decision"] == "DENY" and r["decision_basis"][-1][0] == "precondition")
check("ops_bot's own follow-up lands", B.nominate(MSG)[1]["receipt"]["decision"] == "ACCEPT")

# 9. the independent audit reads the whole mixed history clean
viol = invariants.audit(g().receipts, g().state, server.SESSION["turns"], g().approvers)
check("audit is clean over a two-agent history", viol == [])

# 10. endpoints that change who acts are local to the Warden host. Simulate a
# remote caller by calling the handler check directly.
class Fake:
    client_address = ("10.77.77.10", 5555)
check("a LAN address is not local", server.H._local(Fake()) is False)
Fake.client_address = ("127.0.0.1", 5555)
check("loopback is local", server.H._local(Fake()) is True)

# 11. unconfigured service refuses
server.AUTH = None
check("no agents configured -> /nominate off", A.nominate(GOOD)[0] == 503)

httpd.shutdown()
print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
