"""Live demo server. Nothing is pre-recorded.

Every /turn is a real call to LM Studio and a real adjudication by the same
kernel.py the tests use. The page cannot show you a receipt that did not just
happen.
"""
import base64, collections, hashlib, ipaddress, json, os, re, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import agent, agentauth, invariants, kernel, lm, tools

LOCK = threading.Lock()
APPROVERS = {}      # id -> raw public key. Survives /reset; only PUBLIC keys live here.
SESSION = {"gate": agent.new_gate(APPROVERS), "turns": 0}
# Agent public keys, provisioned out of band on this host (WARDEN_AGENTS=path to json).
# None means /nominate is off. There is no network enrollment for agents.
AUTH = None


def configure(agents_path=None, approvers_path=None, window=120):
    global AUTH
    if approvers_path and os.path.exists(approvers_path):
        for p, k in agentauth.load_keys(approvers_path).items():
            SESSION["gate"].enroll(p, k)      # refuses agents and unknown names
            APPROVERS[p] = k
    if agents_path:
        AUTH = agentauth.AgentAuth(agentauth.load_keys(agents_path), agent.BOUNDARY, window=window)


def reset():
    with LOCK:
        SESSION["gate"] = agent.new_gate(APPROVERS)
        SESSION["turns"] = 0


def approval_state():
    g = SESSION["gate"]
    now = g.clock()
    return {"approvers": {i: hashlib.sha256(k).hexdigest()[:16] for i, k in sorted(g.approvers.items())},
            "enrollable": [p for p, d in g.b.principals.items()
                           if d["kind"] == "human" and p not in g.approvers],
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


def snapshot():
    g = SESSION["gate"]
    viol = invariants.audit(g.receipts, g.state, SESSION["turns"], g.approvers)
    return {"state": g.state,
            "by_principal": by_principal(g),
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
        if self.path == "/approve":
            return self._approve(body)
        # Everything below changes who can act or what the world looks like, or runs
        # the model inside this process. None of it is reachable from another host.
        if self.path in ("/reset", "/enroll", "/turn") and not self._local():
            return self._send({"error": "this endpoint is local to the Warden host"}, 403)
        if self.path == "/reset":
            reset()
            with LOCK:
                return self._send(snapshot())
        if self.path == "/enroll":
            return self._enroll(body)
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

    def _enroll(self, body):
        """First-use enrolment of a human principal's PUBLIC key. The gate refuses
        agents, unknown names and any principal that already has a key. The private
        key never reaches this process."""
        try:
            pub = base64.b64decode(body["public_key"], validate=True)
            with LOCK:
                SESSION["gate"].enroll(str(body["principal"]), pub)
                APPROVERS.update(SESSION["gate"].approvers)
                return self._send(approval_state())
        except (KeyError, ValueError, kernel.AuthzError) as e:
            self._send({"error": str(e)}, 400)

    def _approve(self, body):
        try:
            sig = base64.b64decode(body["signature"], validate=True)
            with LOCK:
                g = SESSION["gate"]
                receipt = g.approve(str(body["nonce"]), str(body["approver"]), sig)
                SESSION["turns"] += 1          # the release is a receipted attempt
                self._send({"receipt": receipt, **approval_state()})
        except (KeyError, ValueError, kernel.AuthzError) as e:
            self._send({"error": str(e)}, 400)


if __name__ == "__main__":
    # WARDEN_HOST=0.0.0.0 to serve other machines. WARDEN_AGENTS=agents.json turns on
    # /nominate. WARDEN_APPROVERS=approvers.json pre-enrolls human keys.
    host = os.environ.get("WARDEN_HOST", "127.0.0.1")
    port = int(os.environ.get("WARDEN_PORT", "8077"))
    configure(os.environ.get("WARDEN_AGENTS"), os.environ.get("WARDEN_APPROVERS"))
    print(f"warden on http://{host}:{port}   approval screen on /approve   "
          f"agents: {sorted(AUTH.fingerprints()) if AUTH else 'none (/nominate off)'}")
    ThreadingHTTPServer((host, port), H).serve_forever()
