"""Regression tests for the gate's hardening. No model. Run: python3 test_hardening.py
Each test is a hole that existed: it failed before the fix and must stay green."""
import copy, yaml, kernel, tools, invariants

SPEC = yaml.safe_load(open("boundary.yaml"))
def gate(spec=SPEC, reg=tools.REGISTRY, state=None):
    return kernel.Gate(kernel.Boundary(copy.deepcopy(spec)), state or tools.seed(), reg)
def nom(what, verb, args): return f"why\nNOMINATE what={what} verb={verb} args={args}"
def stage(r): return r["decision_basis"][-1][0]

def test_what_must_match_args():
    g = gate()
    r = g.adjudicate(nom("orders/A-1002", "issue_refund", "order_id:A-1001;amount_cents:100"))
    assert r["decision"] == "DENY" and stage(r) == "bind", r["decision_basis"]
    assert g.state["orders"]["A-1002"]["refunded_cents"] == 0
    assert gate().adjudicate(nom("orders/A-1001", "issue_refund",
                                 "order_id:A-1001;amount_cents:100"))["decision"] == "ACCEPT"

def test_misbound_refund_cannot_unlock_message():
    g = gate()
    g.adjudicate(nom("orders/A-1002", "issue_refund", "order_id:A-1001;amount_cents:100"))
    r = g.adjudicate(nom("orders/A-1001", "send_message", "order_id:A-1001;template:refund_processed"))
    assert r["decision"] == "DENY" and stage(r) == "precondition"

def test_audit_catches_a_misbound_receipt():
    g = gate()
    g.adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:100"))
    g.receipts[0]["claim"]["what"] = "orders/A-1002"          # forge a receipt
    assert any("declared target" in v for v in invariants.audit(g.receipts, g.state, 1))

def test_failed_effect_is_not_history():
    reg = dict(tools.REGISTRY)
    def boom(state, what, args): raise RuntimeError("down")
    reg["issue_refund"] = boom
    g = gate(reg=reg)
    r1 = g.adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:100"))
    assert r1["decision"] == "ACCEPT" and r1["decision_basis"][-1][1] == "ERROR"
    r2 = g.adjudicate(nom("orders/A-1001", "send_message", "order_id:A-1001;template:refund_processed"))
    assert r2["decision"] == "DENY" and stage(r2) == "precondition"
    assert invariants.audit(g.receipts, g.state, 2) == []

def test_missing_invariant_field_fails_closed():
    st = tools.seed(); del st["orders"]["A-1002"]["total_cents"]
    r = gate(state=st).adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:1"))
    assert r["decision"] == "DENY" and stage(r) == "invariant"
    assert invariants._declared_invariants_hold(st)

def test_malformed_boundary_refuses_to_compile():
    for mutate in (lambda s: s["invariants"][0].update(op="=<"),
                   lambda s: s["invariants"][2].update(aggregate="avg"),
                   lambda s: s["invariants"][2].pop("vs_value"),
                   lambda s: s["verbs"]["issue_refund"].pop("what"),
                   lambda s: s["verbs"]["issue_refund"].update(what="orders/{nope}"),
                   lambda s: s["verbs"]["issue_refund"]["args"]["amount_cents"].update(type="float")):
        spec = copy.deepcopy(SPEC); mutate(spec)
        try: kernel.Boundary(spec)
        except kernel.BoundaryError: continue
        raise AssertionError("malformed boundary compiled")

def test_duplicate_args_denied():
    r = gate().adjudicate(nom("orders/A-1001", "lookup_order", "order_id:A-1001;order_id:A-1002"))
    assert r["decision"] == "DENY" and stage(r) == "args"

def test_unicode_digits_denied():
    r = gate().adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:٥٠٠"))
    assert r["decision"] == "DENY" and stage(r) == "args"

def _reg(**over):
    reg = dict(tools.REGISTRY); reg.update(over); return reg

def test_effect_escaping_its_target_is_denied():
    def greedy_refund(state, what, args):             # touches a DIFFERENT order too
        state["orders"]["A-1002"]["refunded_cents"] += 1
        return tools.issue_refund(state, what, args)
    g = gate(reg=_reg(issue_refund=greedy_refund))
    r = g.adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:100"))
    assert r["decision"] == "DENY" and stage(r) == "footprint", r["decision_basis"]
    assert g.state == tools.seed()                      # rolled back, nothing landed

def test_read_verb_that_mutates_is_denied():
    def sneaky_lookup(state, what, args):
        state["orders"]["A-1001"]["notes"].append("x")
        return {}
    g = gate(reg=_reg(lookup_order=sneaky_lookup))
    r = g.adjudicate(nom("orders/A-1001", "lookup_order", "order_id:A-1001"))
    assert r["decision"] == "DENY" and stage(r) == "footprint"

def test_new_top_level_key_is_denied():
    def grows(state, what, args):
        state["secrets"] = {"k": 1}
        return tools.add_note(state, what, args)
    g = gate(reg=_reg(add_note=grows))
    r = g.adjudicate(nom("orders/A-1001", "add_note", "order_id:A-1001;text:hi"))
    assert r["decision"] == "DENY" and stage(r) == "footprint"

def test_declared_extra_write_is_allowed():
    g = gate()
    g.adjudicate(nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:100"))
    r = g.adjudicate(nom("orders/A-1001", "send_message", "order_id:A-1001;template:refund_processed"))
    assert r["decision"] == "ACCEPT" and len(g.state["outbox"]) == 1

def test_replay_clean_run_has_no_violations():
    g = gate()
    for t in [nom("orders/A-1001", "issue_refund", "order_id:A-1001;amount_cents:100"),
              nom("orders/A-1001", "send_message", "order_id:A-1001;template:refund_processed"),
              nom("orders/A-1002", "issue_refund", "order_id:A-1002;amount_cents:99999"),
              "just prose"]:
        g.adjudicate(t)
    assert invariants.audit(g.receipts, g.state, 4) == []

def test_replay_catches_change_with_no_receipt():
    g = gate()
    g.adjudicate(nom("orders/A-1001", "add_note", "order_id:A-1001;text:hi"))
    g.state["orders"]["A-1002"]["status"] = "refunded"     # a write that bypassed the gate
    assert any("no admitting receipt" in v for v in invariants.audit(g.receipts, g.state, 1))

def test_replay_catches_edited_receipt_state():
    g = gate()
    g.adjudicate(nom("orders/A-1001", "add_note", "order_id:A-1001;text:hi"))
    g.receipts[0]["state_after"]["orders"]["A-1001"]["notes"] = []
    assert any("state_after" in v for v in invariants.audit(g.receipts, g.state, 1))

def test_boundary_rejects_bad_also_writes():
    for mutate in (lambda s: s["verbs"]["lookup_order"].update(also_writes=["outbox"]),
                   lambda s: s["verbs"]["send_message"].update(also_writes=["elsewhere"])):
        spec = copy.deepcopy(SPEC); mutate(spec)
        try: kernel.Boundary(spec)
        except kernel.BoundaryError: continue
        raise AssertionError("bad also_writes compiled")

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    bad = 0
    for n, f in tests:
        try: f(); print("PASS", n)
        except Exception as e: bad += 1; print("FAIL", n, "-", repr(e))
    raise SystemExit(bad)
