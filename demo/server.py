"""Live demo server. Nothing is pre-recorded.

Every /turn is a real call to LM Studio and a real adjudication by the same
kernel.py the tests use. The page cannot show you a receipt that did not just
happen.
"""
import base64, collections, hashlib, ipaddress, json, os, re, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import agent, agentauth, invariants, kernel, lm, oidc, tools

LOCK = threading.Lock()
APPROVERS = {}      # id -> raw public key. Survives /reset; only PUBLIC keys live here.
SESSION = {"gate": agent.new_gate(APPROVERS), "turns": 0}
# Agent public keys, provisioned out of band on this host (WARDEN_AGENTS=path to json).
# None means /nominate is off. There is no network enrollment for agents.
AUTH = None

# HUMAN LOGIN. A person proves who they are through an identity provider (OIDC). That
# earns a short session. A session lets them enroll ONE device key (once) and approve
# with it; it never approves anything on its own. Without an IdP configured nobody can
# log in, so nobody can enroll or approve over HTTP: it fails closed.
IDP = None              # oidc.Verifier
IDENT = None            # oidc.Identities
IDP_CFG = {}
LOGINS = {}             # one-time nonce -> expiry
LOGIN_SESSIONS = {}     # session token -> {"principal", "expires"}
LOGIN_TTL, SESSION_TTL, MAX_LOGINS = 300, 900, 200
clock = time.time


def configure(agents_path=None, approvers_path=None, window=120, idp_path=None):
    global AUTH, IDP, IDENT, IDP_CFG
    if approvers_path and os.path.exists(approvers_path):
        for p, k in agentauth.load_keys(approvers_path).items():
            SESSION["gate"].enroll(p, k)      # refuses agents and unknown names
            APPROVERS[p] = k
    if agents_path:
        AUTH = agentauth.AgentAuth(agentauth.load_keys(agents_path), agent.BOUNDARY, window=window)
    if idp_path:
        IDP_CFG = json.load(open(idp_path))
        IDP = oidc.Verifier(IDP_CFG["issuer"], IDP_CFG["audience"], IDP_CFG["jwks"], clock=lambda: clock())
        IDENT = oidc.Identities(agent.BOUNDARY)


def session_principal(token):
    """The person a live session belongs to, or None. Expired sessions are dropped."""
    now = clock()
    for t in [t for t, s in LOGIN_SESSIONS.items() if s["expires"] < now]:
        del LOGIN_SESSIONS[t]
    s = LOGIN_SESSIONS.get(token) if isinstance(token, str) else None
    return s["principal"] if s else None


def reset():
    with LOCK:
        SESSION["gate"] = agent.new_gate(APPROVERS)
        SESSION["turns"] = 0


def approval_state():
    g = SESSION["gate"]
    now = g.clock()
    return {"approvers": {i: hashlib.sha256(k).hexdigest()[:16] for i, k in sorted(g.approvers.items())},
            "login": IDP is not None,
            "now": now, "boundary": g.boundary_hash(),
            "pending": [{"nonce": n, "canonical": g.canonical(n), "expires": p["expires"],
                         "approvers": p["approvers"], "holds": p["holds"]}
                        for n, p in g.pending.items() if p["expires"] > now]}


def attempt_analysis(model_output):
    """Did the model actually REACH for something the boundary forbids?

    Distinguishes 'the gate refused it' from 'the model never asked' -- which
    are completely different facts, and only the first is prevention.
    """
    spec = invariants.SPEC["verbs"]
    reached = []
    for line in model_output.splitlines():
        m = kernel.NOMINATION.match(line.strip())
        if not m:
            continue
        verb = m.group("verb")
        d = spec.get(verb)
        if d is None:
            reached.append(f"undeclared verb {verb}"); continue
        if not d["permitted"]:
            reached.append(f"unauthorized verb {verb}"); continue
        for part in m.group("args").split(";"):
            if ":" not in part:
                continue
            k, v = (x.strip() for x in part.split(":", 1))
            rule = d["args"].get(k)
            if rule and rule["type"] == "int" and re.fullmatch(r"-?\d+", v):
                if "max" in rule and int(v) > rule["max"]:
                    reached.append(f"{verb} {k}={v} over the declared max {rule['max']}")
    return reached


def out_of_scope_writes(g):
    """Paths that changed anywhere across the receipted history and are not
    inside the declared state scope or removed records. Derived from the
    recorded states, not asserted."""
    seq = [tools.seed()] + [r["state_after"] for r in g.receipts]
    stray = set()
    for before, after in zip(seq, seq[1:]):
        for p in kernel.changed_paths(before, after):
            parts = p.split("/")
            if not any(g.b.in_scope("/".join(parts[:i])) for i in range(1, len(parts) + 1)):
                stray.add(p)
    return len(stray)


def prevented(g):
    """Mechanical facts about what did NOT happen. Derived from the receipts and
    the declaration, not from anyone's reading of intent."""
    named_denied = collections.Counter()
    for r in g.receipts:
        if r["decision"] != "ACCEPT":
            for line in r["rationale"].splitlines():
                m = kernel.NOMINATION.match(line.strip())
                if m:
                    named_denied[m.group("verb")] += 1
    executed = collections.Counter(r["claim"]["verb"] for r in g.receipts
                                   if r["decision"] == "ACCEPT" and r["claim"])
    ceiling = invariants.SPEC["verbs"]["issue_refund"]["args"]["amount_cents"]["max"]
    moved = sum(o["refunded_cents"] for o in g.state["orders"].values())
    breach = sum(max(0, o["refunded_cents"] - ceiling) for o in g.state["orders"].values())
    worst = max(((oid, o["refunded_cents"]) for oid, o in g.state["orders"].items()),
                key=lambda x: x[1], default=(None, 0))
    book_inv = next((i for i in invariants.SPEC.get("invariants", [])
                     if i.get("aggregate") == "sum" and i["field"] == "refunded_cents"), None)
    book_cap = book_inv["vs_value"] if book_inv else None
    book_used = sum(o["refunded_cents"] for o in g.state["orders"].values())
    free_text = sum(1 for m in g.state.get("outbox", []) if "template" not in m)
    return {"book_cap_cents": book_cap, "book_used_cents": book_used,
            "free_text_messages": free_text,
            "messages_sent": len(g.state.get("outbox", [])),
            "cumulative_breach_cents": breach,
            "ceiling_cents": ceiling,
            "worst_order": worst[0], "worst_total_cents": worst[1],
            "never_executed": [v for v, d in invariants.SPEC["verbs"].items()
                               if not d["permitted"] and executed[v] == 0],
            "cancellations": executed["cancel_order"],
            "denied_nominations": dict(named_denied),
            "money_moved_cents": moved,
            "over_ceiling_actions": sum(
                1 for r in g.receipts if r["decision"] == "ACCEPT" and r["claim"]
                and r["claim"]["verb"] == "issue_refund"
                and r["claim"]["args"]["amount_cents"] > ceiling),
            "out_of_scope_writes": out_of_scope_writes(g)}


def by_principal(g):
    """Per-actor tallies over the whole receipted history, derived, not tracked."""
    out = {p: {"kind": d["kind"], "groups": sorted(g.b.effective_groups[p]),
               "ACCEPT": 0, "DENY": 0, "HOLD": 0, "last_ts": None,
               "key": (AUTH.fingerprints().get(p) if AUTH else None)}
           for p, d in g.b.principals.items() if d["kind"] == "agent"}
    for r in g.receipts:
        p = out.get(r["principal"])
        if p is not None:
            p[r["decision"]] += 1
            p["last_ts"] = r["ts"]
    return out


def _fmt(arg, v):
    return "$%.2f" % (v / 100) if arg.endswith("_cents") else str(v)


def permissions(b, principal):
    """What this agent may do, in plain words, derived from the compiled policy and
    the declared verbs. Nothing here is written by hand, so it cannot drift from what
    the gate enforces."""
    nm = lambda p: b.principals[p].get("name", p)
    out = []
    for verb, spec in b.verbs.items():
        label = spec.get("label") or verb.replace("_", " ").capitalize()
        row = lambda level, note: out.append({"action": label, "level": level, "note": note})
        if not spec["permitted"]:
            row("no", "Nobody is allowed to do this."); continue
        rules = [r for r in b.rules if principal in r["to"] and verb in r["verbs"]]
        if any(r["effect"] == "deny" and r["when"] is None and r["what"] is None for r in rules):
            row("no", "Turned off for this agent."); continue
        if not any(r["effect"] == "allow" for r in rules):
            row("no", "Not part of this agent's job."); continue
        extra = []
        for k, rule in spec["args"].items():
            if rule.get("type") == "int" and "max" in rule:
                extra.append(f"Never more than {_fmt(k, rule['max'])} at a time.")
        req = spec.get("requires")
        if req and req.get("immediately"):
            extra.append("Only straight after: " + (b.verbs[req["verb"]].get("label") or req["verb"]) + ".")
        holds = [r for r in rules if r["effect"] == "hold"]
        level, note = "yes", ""
        for r in holds:
            who = " or ".join(sorted(nm(p) for p in r["approvers"].get(principal, ())))
            w = r["when"]
            if w is None:
                level, note = "ask", f"{who} must approve each time."
            elif w["op"] == ">":
                note = f"Up to {_fmt(w['arg'], w['value'])} on its own. Above that, {who} must approve."
            else:
                level, note = "ask", f"Some cases need {who} to approve."
        out.append({"action": label, "level": level, "note": " ".join([note] + extra).strip()})
    return out


def agents_view(g):
    b, out = g.b, []
    for p, d in b.principals.items():
        if d["kind"] != "agent":
            continue
        o = d.get("owner")
        out.append({"id": p, "name": d.get("name", p), "job": d.get("job", ""),
                    "domain": b.spec.get("domain", ""), "owner": o,
                    "owner_name": b.principals[o].get("name", o) if o else None,
                    "authenticated": bool(AUTH and p in AUTH.keys),
                    "permissions": permissions(b, p)})
    return out


def snapshot():
    g = SESSION["gate"]
    viol = invariants.audit(g.receipts, g.state, SESSION["turns"], g.approvers)
    return {"state": g.state,
            "by_principal": by_principal(g),
            "agents": agents_view(g),
            "names": {p: d.get("name", p) for p, d in g.b.principals.items()},
            "boundary_hash": g.boundary_hash(),
            "total_receipts": len(g.receipts),
            "now": g.clock(),
            "turns": SESSION["turns"],
            "admitted": sum(1 for r in g.receipts if r["decision"] == "ACCEPT"),
            "denied": sum(1 for r in g.receipts if r["decision"] == "DENY"),
            "held": sum(1 for r in g.receipts if r["decision"] == "HOLD"),
            "violations": viol,
            "boundary": g.attestation(),
            "pending_approvals": len(g.pending),
            "prevented": prevented(g),
            "receipts": g.receipts[-40:]}


def _page(handler, name):
    b = open(os.path.join(os.path.dirname(__file__), name), "rb").read()
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(b)))
    handler.end_headers()
    handler.wfile.write(b)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            b = open(os.path.join(os.path.dirname(__file__), "ui.html"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif self.path == "/approve":
            _page(self, "approve.html")
        elif self.path == "/dashboard":
            _page(self, "dashboard.html")
        elif self.path == "/login/start":
            self._login_start()
        elif self.path == "/approval/state":
            with LOCK:
                self._send(approval_state())
        elif self.path == "/state":
            with LOCK:
                self._send(snapshot())
        elif self.path == "/boundary":
            self._send({"yaml": open(os.path.join(os.path.dirname(__file__),
                                                  "boundary.yaml")).read()})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send({"error": "body is not JSON"}, 400)
        if self.path == "/nominate":
            return self._nominate(body)
        if self.path == "/login":
            return self._login(body)
        if self.path == "/enroll":
            return self._enroll(body)
        if self.path == "/approve":
            return self._approve(body)
        # Everything below resets the world or runs the model inside this process.
        # None of it is reachable from another host.
        if self.path in ("/reset", "/turn") and not self._local():
            return self._send({"error": "this endpoint is local to the Warden host"}, 403)
        if self.path == "/reset":
            reset()
            with LOCK:
                return self._send(snapshot())
        if self.path != "/turn":
            return self._send({"error": "not found"}, 404)
        text = (body.get("text") or "").strip()
        if not text:
            return self._send({"error": "empty"}, 400)
        try:
            # The model call is slow and takes no lock; only adjudication does, so
            # the approval screen stays responsive while a turn is in flight.
            raw = lm.complete(agent.SYSTEM, text, temperature=body.get("temperature", 0.4))
            with LOCK:
                g = SESSION["gate"]
                before = json.loads(json.dumps(g.state))
                receipt = g.adjudicate(raw)
                SESSION["turns"] += 1
                snap = snapshot()
            self._send({"user": text, "model_output": raw, "receipt": receipt,
                        "reached_for_forbidden": attempt_analysis(raw),
                        "state_before": before, **snap})
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 502)

    def _local(self):
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def _nominate(self, body):
        """An agent's nomination from the network. The principal is whoever's key
        verifies; nothing in the model output can change it."""
        if AUTH is None:
            return self._send({"error": "agent authentication is not configured"}, 503)
        try:
            with LOCK:
                who = AUTH.verify(body.get("principal"), body.get("nonce"), body.get("ts"),
                                  body.get("output"), body.get("signature"))
                g = SESSION["gate"]
                receipt = g.adjudicate(body["output"], principal=who)
                SESSION["turns"] += 1
            self._send({"receipt": receipt})
        except agentauth.AuthError as e:
            self._send({"error": f"authentication failed: {e}"}, 401)

    # ---- human login -------------------------------------------------------
    def _login_start(self):
        """Hand out a one-time nonce. The identity provider must put it in the token, so
        a token captured from an earlier login cannot be replayed into a new one."""
        if IDP is None:
            return self._send({"error": "login is not configured"}, 503)
        with LOCK:
            now = clock()
            for n in [n for n, e in LOGINS.items() if e < now]:
                del LOGINS[n]
            if len(LOGINS) >= MAX_LOGINS:
                return self._send({"error": "too many logins in progress"}, 429)
            nonce = secrets.token_urlsafe(18)
            LOGINS[nonce] = now + LOGIN_TTL
        self._send({"nonce": nonce, "authorize_url": IDP_CFG.get("authorize_url"),
                    "client_id": IDP_CFG["audience"]})

    def _login(self, body):
        if IDP is None:
            return self._send({"error": "login is not configured"}, 503)
        try:
            with LOCK:
                nonce = body.get("nonce")
                exp = LOGINS.pop(nonce, None) if isinstance(nonce, str) else None   # single use, win or lose
                if exp is None or exp < clock():
                    raise oidc.OIDCError("unknown or expired login")
                who = IDENT.principal_for(IDP.verify(str(body.get("id_token", "")), nonce))
                token = secrets.token_urlsafe(24)
                LOGIN_SESSIONS[token] = {"principal": who, "expires": clock() + SESSION_TTL}
                g = SESSION["gate"]
                self._send({"session": token, "principal": who,
                            "name": g.b.principals[who].get("name", who),
                            "enrolled": who in g.approvers, "expires": clock() + SESSION_TTL})
        except oidc.OIDCError as e:
            self._send({"error": f"login failed: {e}"}, 401)

    def _enroll(self, body):
        """Enroll the logged-in person's device key. Their identity comes from the login
        session, never from the request, and a person who already has a key cannot swap
        it. The private key never reaches this process."""
        try:
            with LOCK:
                who = session_principal(body.get("session"))
                if who is None:
                    return self._send({"error": "sign in first"}, 401)
                pub = base64.b64decode(body["public_key"], validate=True)
                SESSION["gate"].enroll(who, pub)
                APPROVERS[who] = pub
                return self._send(approval_state())
        except (KeyError, ValueError, kernel.AuthzError) as e:
            self._send({"error": str(e)}, 400)

    def _approve(self, body):
        """Approving needs BOTH a live login session (who) and a signature from that
        person's enrolled device key over the exact action (which device, which action).
        The approver is whoever the session belongs to; the request cannot name one."""
        try:
            sig = base64.b64decode(body["signature"], validate=True)
            with LOCK:
                who = session_principal(body.get("session"))
                if who is None:
                    return self._send({"error": "sign in first"}, 401)
                g = SESSION["gate"]
                receipt = g.approve(str(body["nonce"]), who, sig)
                SESSION["turns"] += 1          # the release is a receipted attempt
                self._send({"receipt": receipt, **approval_state()})
        except (KeyError, ValueError, kernel.AuthzError) as e:
            self._send({"error": str(e)}, 400)


if __name__ == "__main__":
    # WARDEN_HOST=0.0.0.0 to serve other machines. WARDEN_AGENTS=agents.json turns on
    # /nominate. WARDEN_APPROVERS=approvers.json pre-enrolls human keys.
    host = os.environ.get("WARDEN_HOST", "127.0.0.1")
    port = int(os.environ.get("WARDEN_PORT", "8077"))
    configure(os.environ.get("WARDEN_AGENTS"), os.environ.get("WARDEN_APPROVERS"),
              idp_path=os.environ.get("WARDEN_IDP"))
    print(f"warden on http://{host}:{port}   approval screen on /approve   "
          f"agents: {sorted(AUTH.fingerprints()) if AUTH else 'none (/nominate off)'}   "
          f"login: {IDP_CFG.get('issuer') if IDP else 'off (nobody can enroll or approve)'}")
    ThreadingHTTPServer((host, port), H).serve_forever()
