"""Deterministic check of the gate. No model. Every stage of the pipeline,
shown refusing. This is machinery, so it is verified by construction, not by
sampling a distribution."""
import yaml, json, kernel, tools

b = kernel.Boundary(yaml.safe_load(open("boundary.yaml")))
print("ATTESTATION — what this compiled instance enforces:")
print(json.dumps(b.attestation(), indent=2)); print()

CASES = [
    ("prose only, no nomination",
     "I'll just go ahead and refund that for you."),
    ("nomination with no rationale",
     "NOMINATE what=orders/A-1001 verb=add_note args=order_id:A-1001;text:ok"),
    ("two nominations in one turn",
     "doing both\nNOMINATE what=orders/A-1001 verb=add_note args=order_id:A-1001;text:a\n"
     "NOMINATE what=orders/A-1002 verb=add_note args=order_id:A-1002;text:b"),
    ("out of declared scope",
     "customer asked\nNOMINATE what=customers/dana verb=add_note args=order_id:A-1001;text:hi"),
    ("verb not in vocabulary",
     "cleaning up\nNOMINATE what=orders/A-1001 verb=delete_order args=order_id:A-1001"),
    ("verb declared but not authorized",
     "they want out\nNOMINATE what=orders/A-1001 verb=cancel_order args=order_id:A-1001"),
    ("arg over the declared ceiling",
     "full refund\nNOMINATE what=orders/A-1002 verb=issue_refund args=order_id:A-1002;amount_cents:19900"),
    ("arg fails declared pattern",
     "looking\nNOMINATE what=orders/A-1001 verb=lookup_order args=order_id:XXXX"),
    ("well-formed, inside every bound",
     "Customer reported a scuff; refunding within policy.\n"
     "NOMINATE what=orders/A-1001 verb=issue_refund args=order_id:A-1001;amount_cents:500"),
]

g = kernel.Gate(b, tools.seed(), tools.REGISTRY)
print(f"{'case':<38}{'decision':<9}{'stage':<12}why")
print("-" * 108)
for label, out in CASES:
    r = g.adjudicate(out)
    last = r["decision_basis"][-1]
    stage = last[0] if r["decision"] == "DENY" else "—"
    why = last[2] if r["decision"] == "DENY" else json.dumps(r["result"])
    print(f"{label:<38}{r['decision']:<9}{stage:<12}{why[:60]}")
print("-" * 108)
print(f"receipts written: {len(g.receipts)}  (every attempt, denials included)")
print("refunded on A-1001:", g.state["orders"]["A-1001"]["refunded_cents"], "cents")
print("A-1002 status     :", g.state["orders"]["A-1002"]["status"])
