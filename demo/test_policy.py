"""Identity and policy tests. No model. Run: python test_policy.py"""
import copy, yaml, kernel, tools, invariants
from testsigner import Signer

SPEC = yaml.safe_load(open("boundary.yaml"))


def gate(spec=SPEC, principal="support_bot", approvers=None):
    return kernel.Gate(kernel.Boundary(copy.deepcopy(spec)), tools.seed(), tools.REGISTRY,
                       principal=principal, approvers=approvers or {})

import contextlib

@contextlib.contextmanager
def audited_under(spec):
    """The audit reads boundary.yaml. A test that edits the spec in memory points it there."""
    saved, invariants.SPEC = invariants.SPEC, spec
    try: yield
    finally: invariants.SPEC = saved

def edit(fn):
    spec = copy.deepcopy(SPEC); fn(spec); return spec

def refund(amount, order="A-1002"):
    return (f"why\nNOMINATE what=orders/{order} verb=issue_refund "
            f"args=order_id:{order};amount_cents:{amount}")
def lookup(order="A-1001"):
    return f"why\nNOMINATE what=orders/{order} verb=lookup_order args=order_id:{order}"
def stage(r): return r["decision_basis"][-1][0]
def must_not_compile(spec):
    try: kernel.Boundary(spec)
    except kernel.BoundaryError: return
    raise AssertionError("malformed policy compiled")


# ---- who is acting ----------------------------------------------------------
def test_no_principal_fails_closed():
    r = gate(principal=None).adjudicate(lookup())
    assert r["decision"] == "DENY" and stage(r) == "policy"

def test_unknown_principal_fails_closed():
    r = gate(principal="mallory").adjudicate(lookup())
    assert r["decision"] == "DENY" and stage(r) == "policy"

def test_a_principal_in_no_group_is_denied():
    spec = edit(lambda s: s["principals"].update(ghost={"kind": "agent", "groups": []}))
    r = gate(spec, "ghost").adjudicate(lookup())
    assert r["decision"] == "DENY" and "no policy rule allows" in r["decision_basis"][-1][2]

def test_the_model_cannot_name_the_principal():
    # no grammar slot exists for it; an attempt in prose or args is not a nomination
    g = gate(principal="support_bot")
    r = g.adjudicate("principal=sam\nNOMINATE what=orders/A-1001 verb=lookup_order "
                     "args=order_id:A-1001;principal:sam")
    assert r["decision"] == "DENY" and stage(r) == "args"
    assert all(x["principal"] == "support_bot" for x in g.receipts)

# ---- precedence and inheritance -----------------------------------------------
def test_deny_beats_allow():
    spec = edit(lambda s: s["policy"].append(
        {"id": "no-lookups", "effect": "deny", "to": ["group:support"], "verbs": ["lookup_order"]}))
    r = gate(spec).adjudicate(lookup())
    assert r["decision"] == "DENY" and "no-lookups" in r["decision_basis"][-1][2]

def test_inheritance_a_supervisor_is_also_support():
    spec = edit(lambda s: s["policy"].__setitem__(0, {**s["policy"][0], "to": ["group:support"]}))
    assert gate(spec, "sam").adjudicate(lookup())["decision"] == "ACCEPT"

def test_inheritance_does_not_flow_downward():
    spec = edit(lambda s: s["policy"].append(
        {"id": "sup-only", "effect": "deny", "to": ["group:supervisors"], "verbs": ["add_note"]}))
    note = "why\nNOMINATE what=orders/A-1001 verb=add_note args=order_id:A-1001;text:hi"
    assert gate(spec, "sam").adjudicate(note)["decision"] == "DENY"
    assert gate(spec, "support_bot").adjudicate(note)["decision"] == "ACCEPT"

def test_policy_cannot_widen_the_boundary():
    spec = edit(lambda s: s["policy"].append(
        {"id": "sneaky", "effect": "allow", "to": ["group:support"], "verbs": ["cancel_order"]}))
    r = gate(spec).adjudicate("why\nNOMINATE what=orders/A-1001 verb=cancel_order args=order_id:A-1001")
    assert r["decision"] == "DENY" and stage(r) == "verb-auth"

def test_a_resource_pattern_restricts_a_rule():
    def narrow(s):
        s["policy"][0] = {**s["policy"][0], "what": ["orders/A-1001"]}
    g = gate(edit(narrow))
    assert g.adjudicate(lookup("A-1001"))["decision"] == "ACCEPT"
    assert g.adjudicate(lookup("A-1002"))["decision"] == "DENY"

# ---- holds -----------------------------------------------------------------
def test_hold_is_not_a_denial_and_not_an_execution():
    g = gate(approvers={"sam": Signer("sam").public_raw})
    r = g.adjudicate(refund(4000))
    assert r["decision"] == "HOLD" and r["result"] is None and r["claim"] is None
    assert g.state == tools.seed()
    assert invariants.audit(g.receipts, g.state, 1, g.approvers) == []

def test_a_human_is_not_asked_to_sign_what_would_be_refused_anyway():
    def hold_msgs(s):
        s["policy"].append({"id": "hold-msgs", "effect": "hold", "to": ["group:support"],
                            "verbs": ["send_message"], "approvers": ["group:supervisors"]})
    g = gate(edit(hold_msgs))
    r = g.adjudicate("why\nNOMINATE what=orders/A-1001 verb=send_message "
                     "args=order_id:A-1001;template:order_status")
    assert r["decision"] == "DENY" and stage(r) == "precondition" and not g.pending

def test_holds_are_conjunctive_and_approvers_intersect():
    def two(s):
        s["principals"]["pat"] = {"kind": "human", "groups": ["supervisors"]}
        s["principals"]["lee"] = {"kind": "human", "groups": ["supervisors"]}
        s["policy"].append({"id": "second-look", "effect": "hold", "to": ["group:support"],
                            "verbs": ["issue_refund"], "when": {"arg": "amount_cents", "op": ">", "value": 3000},
                            "approvers": ["pat", "lee"]})
    g = gate(edit(two))
    r = g.adjudicate(refund(4000))
    p = next(iter(g.pending.values()))
    assert sorted(p["holds"]) == ["large-refund-needs-a-supervisor", "second-look"]
    assert p["approvers"] == ["lee", "pat"]                # supervisors AND {pat, lee}; sam is not in both
    small = gate(edit(two)); small.adjudicate(refund(2800))
    assert next(iter(small.pending.values()))["holds"] == ["large-refund-needs-a-supervisor"]

def test_signer_must_satisfy_every_applicable_hold():
    def two(s):
        s["principals"]["pat"] = {"kind": "human", "groups": ["supervisors"]}
        s["policy"].append({"id": "second-look", "effect": "hold", "to": ["group:support"],
                            "verbs": ["issue_refund"], "when": {"arg": "amount_cents", "op": ">", "value": 3000},
                            "approvers": ["pat"]})
    sam, pat = Signer("sam"), Signer("pat")
    spec = edit(two)
    g = gate(spec, approvers={"sam": sam.public_raw, "pat": pat.public_raw})
    held = g.adjudicate(refund(4000))
    try: sam.approve(g, held)
    except kernel.AuthzError: pass
    else: raise AssertionError("sam alone satisfied a hold that names only pat")
    assert pat.approve(g, held)["decision"] == "ACCEPT"
    with audited_under(spec):
        assert invariants.audit(g.receipts, g.state, 2, g.approvers) == []

# ---- the audit re-derives policy on its own ------------------------------------
def test_audit_flags_an_action_the_policy_never_allowed():
    g = gate()
    g.adjudicate(lookup())
    g.receipts[0]["principal"] = "mallory"
    assert any("outside policy" in v for v in invariants.audit(g.receipts, g.state, 1, {}))

def test_audit_flags_a_forged_approver():
    sam = Signer("sam")
    g = gate(approvers={"sam": sam.public_raw})
    sam.approve(g, g.adjudicate(refund(4000)))
    forged = copy.deepcopy(g.receipts)
    ok = next(r for r in forged if r["decision"] == "ACCEPT")
    ok["principal"] = "sam"                                # now sam "approved" sam's own action
    assert any("own action" in v for v in invariants._authz_violations(forged, g.approvers))

# ---- the declaration refuses to compile when it is wrong -----------------------
def test_malformed_policy_refuses_to_compile():
    for mutate in (
        lambda s: s["groups"].update(a={"includes": ["b"]}, b={"includes": ["a"]}),         # cycle
        lambda s: s["principals"]["sam"].update(groups=["nope"]),                           # unknown group
        lambda s: s["principals"]["sam"].update(kind="robot"),
        lambda s: s["policy"][0].update(effect="permit"),
        lambda s: s["policy"][0].update(verbs=["teleport"]),
        lambda s: s["policy"][0].update(to=["group:nope"]),
        lambda s: s["policy"][0].update(to=["nobody"]),
        lambda s: s["policy"][1].update(approvers=["support_bot"]),                         # an agent can't hold-approve
        lambda s: s["policy"][1].pop("approvers"),
        lambda s: s["policy"][0].update(approvers=["sam"]),                                 # only holds name approvers
        lambda s: s["policy"][1]["when"].update(arg="order_id"),
        lambda s: s["policy"][1]["when"].update(op="~"),
        lambda s: s["policy"][1].update(id="support-day-to-day"),                           # duplicate id
        lambda s: s["verbs"]["issue_refund"].update(authorization={"always": True}),        # old form
    ):
        must_not_compile(edit(mutate))

def test_policy_is_part_of_the_signed_digest():
    other = edit(lambda s: s["policy"][0].update(verbs=["lookup_order"]))
    assert kernel.Boundary(SPEC).digest() != kernel.Boundary(other).digest()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    bad = 0
    for n, f in tests:
        try: f(); print("PASS", n)
        except Exception as e: bad += 1; print("FAIL", n, "-", repr(e))
    raise SystemExit(bad)
