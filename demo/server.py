"""Live demo server. Nothing is pre-recorded.

Every /turn is a real call to LM Studio and a real adjudication by the same
kernel.py the tests use. The page cannot show you a receipt that did not just
happen.
"""
import collections, json, os, re, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import agent, invariants, kernel, tools

LOCK = threading.Lock()
SESSION = {"gate": agent.new_gate(), "turns": 0}


def reset():
    with LOCK:
        SESSION["gate"] = agent.new_gate()
        SESSION["turns"] = 0


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
    spec = kernel.yaml_spec() if hasattr(kernel, "yaml_spec") else None
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
            "out_of_scope_writes": 0}


def snapshot():
    g = SESSION["gate"]
    viol = invariants.audit(g.receipts, g.state, SESSION["turns"])
    return {"state": g.state,
            "turns": SESSION["turns"],
            "admitted": sum(1 for r in g.receipts if r["decision"] == "ACCEPT"),
            "denied": sum(1 for r in g.receipts if r["decision"] == "DENY"),
            "violations": viol,
            "boundary": g.b.attestation(),
            "prevented": prevented(g),
            "receipts": g.receipts[-40:]}


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
        elif self.path == "/state":
            self._send(snapshot())
        elif self.path == "/boundary":
            self._send({"yaml": open(os.path.join(os.path.dirname(__file__),
                                                  "boundary.yaml")).read()})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/reset":
            reset(); return self._send(snapshot())
        if self.path != "/turn":
            return self._send({"error": "not found"}, 404)
        text = (body.get("text") or "").strip()
        if not text:
            return self._send({"error": "empty"}, 400)
        try:
            with LOCK:
                g = SESSION["gate"]
                before = json.loads(json.dumps(g.state))
                raw, receipt = agent.turn(text, g, temperature=body.get("temperature", 0.4))
                SESSION["turns"] += 1
                snap = snapshot()
            self._send({"user": text, "model_output": raw, "receipt": receipt,
                        "reached_for_forbidden": attempt_analysis(raw),
                        "state_before": before, **snap})
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 502)


if __name__ == "__main__":
    print("live demo on http://127.0.0.1:8077")
    HTTPServer(("127.0.0.1", 8077), H).serve_forever()
