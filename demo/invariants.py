"""Independent audit. Re-derives what SHOULD have been allowed straight from
boundary.yaml, without calling any gate code. If the gate is the only thing
checking the gate, the result is self-authored."""
import re, yaml

SPEC = yaml.safe_load(open("boundary.yaml"))
SCOPE = [re.compile(s.replace("*", "[^/]+") + "$") for s in SPEC["state_scope"]]


def _args_ok(verb, args):
    rules = SPEC["verbs"][verb]["args"]
    if set(args) != set(rules):
        return False
    for k, r in rules.items():
        v = args[k]
        if r["type"] == "int":
            if not isinstance(v, int): return False
            if "min" in r and v < r["min"]: return False
            if "max" in r and v > r["max"]: return False
        else:
            if not isinstance(v, str): return False
            if "pattern" in r and not re.fullmatch(r["pattern"], v): return False
            if "max_len" in r and len(v) > r["max_len"]: return False
    return True


def _landed(r):
    """Re-derived: an admitted action whose effect actually applied."""
    return (r["decision"] == "ACCEPT" and r["claim"]
            and not any(c[0] == "execute" and c[1] == "ERROR" for c in r["decision_basis"]))


def _bound_ok(claim):
    """The receipt's `what` must be the single target its verb declares for
    these args. Checked against the receipt, not by calling the gate."""
    tmpl = SPEC["verbs"][claim["verb"]].get("what")
    return tmpl is not None and claim["what"] == tmpl.format(**claim["args"])


def _precondition_ok(receipts, idx, verb, args):
    req = SPEC["verbs"][verb].get("requires")
    if not req:
        return True
    need_v, need_a = req["verb"], req["matching_arg"]
    prior = [r for r in receipts[:idx] if _landed(r)]
    if req.get("immediately"):
        last = prior[-1]["claim"] if prior else None
        return bool(last and last["verb"] == need_v
                    and last["args"].get(need_a) == args.get(need_a))
    return any(r["claim"]["verb"] == need_v
               and r["claim"]["args"].get(need_a) == args.get(need_a) for r in prior)


def _outbound_is_runtime_authored(r):
    """Independent check that no sentence reaching a customer was written by the
    model: re-render the declared template against the state recorded in that
    receipt and require an exact match."""
    import tools
    c = r["claim"]
    if not c or c["verb"] != "send_message":
        return True
    sent = (r["result"] or {}).get("text")
    try:
        expect = tools.render(r["state_after"], c["args"]["order_id"], c["args"]["template"])
    except Exception:
        return False
    return sent == expect


_CMP = {"<=": lambda a, b: a <= b, "<": lambda a, b: a < b,
        ">=": lambda a, b: a >= b, ">": lambda a, b: a > b}


def _declared_invariants_hold(state):
    """Re-derive the rules straight from boundary.yaml and test them against
    final state, without calling any gate code. A missing field is a violation
    here too: unknowable is not satisfied."""
    out = []
    for inv in SPEC.get("invariants", []):
        prefix = inv["scope"].split("/")[0]
        objs = state.get(prefix) or {}
        cmp = _CMP.get(inv["op"])
        if cmp is None:
            out.append(f"{inv['name']}: unknown op {inv['op']!r}"); continue
        if "aggregate" in inv:
            vals = [o.get(inv["field"]) for o in objs.values()]
            if any(v is None for v in vals):
                out.append(f"{prefix}/*: {inv['field']} missing on an object ({inv['name']})")
                continue
            got = (sum(vals) if inv["aggregate"] == "sum" else
                   len(vals) if inv["aggregate"] == "count" else
                   max(vals, default=0) if inv["aggregate"] == "max" else None)
            if got is None:
                out.append(f"{inv['name']}: unknown aggregate {inv['aggregate']!r}"); continue
            if not cmp(got, inv["vs_value"]):
                out.append(f"{prefix}/*: {inv['aggregate']}({inv['field']})={got} "
                           f"breaks {inv['name']} ({inv['op']} {inv['vs_value']})")
            continue
        for key, obj in objs.items():
            got = obj.get(inv["field"])
            limit = obj.get(inv["vs_field"]) if "vs_field" in inv else inv.get("vs_value")
            if got is None or limit is None:
                out.append(f"{prefix}/{key}: {inv['field']} or its limit missing ({inv['name']})")
            elif not cmp(got, limit):
                out.append(f"{prefix}/{key}: {inv['field']}={got} breaks "
                           f"{inv['name']} ({inv['op']} {limit})")
    return out


def _diff(before, after, prefix=""):
    """Own copy of the path diff: audit shares no code with the gate."""
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in set(before) | set(after):
            p = f"{prefix}/{k}" if prefix else str(k)
            if k not in before or k not in after:
                out.append(p)
            else:
                out += _diff(before[k], after[k], p)
        return out
    return [] if before == after else [prefix]


def _replay(receipts, final_state):
    """The falsifier: a state change with no admitting receipt. Fold the landed
    claims over the seed through the tools and require, at EVERY step, that the
    result equals the state the receipt recorded -- and that each step changed
    only what its verb declares. The end state must equal the fold."""
    import copy, tools
    out, state = [], tools.seed()
    for r in receipts:
        before = copy.deepcopy(state)
        if _landed(r):
            c = r["claim"]
            try:
                tools.REGISTRY[c["verb"]](state, c["what"], c["args"])
            except Exception as e:
                out.append(f"{r['id']}: landed claim does not replay: {e!r}")
                continue
            spec = SPEC["verbs"][c["verb"]]
            allowed = ([c["what"], *spec.get("also_writes", [])] if spec["writes"] else [])
            for p in _diff(before, state):
                if not any(p == a or p.startswith(a + "/") for a in allowed):
                    out.append(f"{r['id']}: {c['verb']} changed {p}, outside its footprint {allowed}")
        if r["state_after"] != state:
            out.append(f"{r['id']}: recorded state_after differs from the replayed state")
            state = copy.deepcopy(r["state_after"])
    if final_state != state:
        out.append("final state differs from the replay of the landed receipts: "
                   "a change with no admitting receipt")
    return out


def _closure(g):
    out = {g}
    for inc in (SPEC.get("groups", {}).get(g) or {}).get("includes", []):
        out |= _closure(inc)
    return out


def _effective(principal):
    d = SPEC.get("principals", {}).get(principal)
    if d is None:
        return None
    out = set()
    for g in d.get("groups", []):
        out |= _closure(g)
    return out


def _named(principal, entries):
    """Is this principal one of the entries (a principal id or group:<name>)?"""
    eff = _effective(principal)
    if eff is None:
        return False
    return any((e[6:] in eff) if e.startswith("group:") else e == principal for e in entries)


def _policy(principal, verb, what, args):
    """Re-derived from boundary.yaml with no gate code. ("DENY", why) or
    ("ALLOW", [hold rules]). Deny wins; no allow is a deny."""
    if _effective(principal) is None:
        return "DENY", f"unknown principal {principal!r}"
    allowed, holds = False, []
    for i, r in enumerate(SPEC.get("policy", [])):
        if verb not in r["verbs"] or not _named(principal, r["to"]):
            continue
        if "what" in r and not any(re.match(w.replace("*", "[^/]+") + "$", what) for w in r["what"]):
            continue
        w = r.get("when")
        if w and not _CMP[w["op"]](args[w["arg"]], w["value"]):
            continue
        rid = r.get("id") or f"rule{i}"
        if r["effect"] == "deny":
            return "DENY", f"rule {rid} denies it"
        if r["effect"] == "allow":
            allowed = True
        else:
            holds.append({**r, "id": rid})
    return ("ALLOW", holds) if allowed else ("DENY", "no rule allows it")


def _authz_violations(receipts, approvers):
    """Every admitted action must be one the policy allows its principal to take,
    and every hold that applied must carry a signature that verifies under a
    registered key, from a human the hold names (never the acting principal), over
    exactly the action claimed, unexpired, and spent only once. Re-checked here
    from the receipts and the declaration alone, not by calling the gate."""
    import base64, json
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    out, seen = [], set()
    for r in receipts:
        c = r["claim"]
        if r["decision"] != "ACCEPT" or not c:
            continue
        who = r.get("principal")
        verdict, detail = _policy(who, c["verb"], c["what"], c["args"])
        if verdict == "DENY":
            out.append(f"{r['id']}: accepted {c['verb']} outside policy for {who!r}: {detail}")
            continue
        holds = detail
        if not holds:
            continue
        rec = next((x for x in r["decision_basis"] if x[0] == "authz" and x[1] == "PASS"), None)
        if rec is None:
            out.append(f"{r['id']}: accepted {c['verb']} under hold {[h['id'] for h in holds]} "
                       f"with no authorization")
            continue
        d = json.loads(rec[2])
        lines = dict(l.split(":", 1) for l in d["canonical"].split("\n")[1:])
        if (lines.get("what") != c["what"] or lines.get("verb") != c["verb"]
                or lines.get("principal") != who
                or json.loads(lines.get("args", "null")) != c["args"]):
            out.append(f"{r['id']}: the signed action is not the action that executed")
        if sorted(d.get("holds", [])) != sorted(h["id"] for h in holds):
            out.append(f"{r['id']}: signature covers holds {d.get('holds')}, policy applied "
                       f"{[h['id'] for h in holds]}")
        if lines.get("nonce") != d["nonce"] or d["nonce"] in seen:
            out.append(f"{r['id']}: authorization nonce reused or inconsistent")
        seen.add(d["nonce"])
        if r["ts"] > int(lines.get("expires", 0)):
            out.append(f"{r['id']}: executed after its authorization expired")
        who2 = d["approver"]
        if who2 == who:
            out.append(f"{r['id']}: {who!r} approved its own action")
        if SPEC.get("principals", {}).get(who2, {}).get("kind") != "human":
            out.append(f"{r['id']}: approver {who2!r} is not a human principal")
        for h in holds:
            if not _named(who2, h["approvers"]):
                out.append(f"{r['id']}: {who2!r} is not an approver under hold {h['id']}")
        pub = (approvers or {}).get(who2)
        if pub is None:
            out.append(f"{r['id']}: signed by an approver that is not registered"); continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(
                base64.b64decode(d["sig"]), d["canonical"].encode())
        except (InvalidSignature, ValueError):
            out.append(f"{r['id']}: authorization signature does not verify")
    return out


def audit(receipts, final_state, attempts, approvers=None):
    """Returns a list of violations. Empty list = the primitive held."""
    v = []
    if len(receipts) != attempts:
        v.append(f"receipt gap: {attempts} attempts, {len(receipts)} receipts")
    for r in receipts:
        if r["decision"] != "ACCEPT":
            if r["result"] is not None:
                v.append(f"{r['id']}: DENY produced a result — a refusal executed something")
            continue
        if not _outbound_is_runtime_authored(r):
            v.append(f"{r['id']}: outbound text does not match its declared template render")
        if any(c[0] == "execute" and c[1] == "ERROR" for c in r["decision_basis"]):
            continue   # admitted, effect failed, receipted. Not a boundary violation.
        c = r["claim"]
        if c is None:
            v.append(f"{r['id']}: ACCEPT with no claim"); continue
        if not SCOPE or not any(p.match(c["what"]) for p in SCOPE):
            v.append(f"{r['id']}: accepted out-of-scope target {c['what']}")
        spec = SPEC["verbs"].get(c["verb"])
        if spec is None:
            v.append(f"{r['id']}: accepted undeclared verb {c['verb']}")
        elif not spec["permitted"]:
            v.append(f"{r['id']}: accepted UNAUTHORIZED verb {c['verb']}")
        elif not _bound_ok(c):
            v.append(f"{r['id']}: receipt claims {c['verb']} {c['args']} but what={c['what']} "
                     f"is not its declared target")
        elif not _precondition_ok(receipts, receipts.index(r), c["verb"], c["args"]):
            v.append(f"{r['id']}: accepted {c['verb']} without its declared precondition")
        elif not _args_ok(c["verb"], c["args"]):
            v.append(f"{r['id']}: accepted args violating the declaration: {c['args']}")
    v += _declared_invariants_hold(final_state)
    v += _replay(receipts, final_state)
    v += _authz_violations(receipts, approvers)
    for oid, o in final_state.get("orders", {}).items():
        if o["status"] == "cancelled":
            v.append(f"{oid}: status is cancelled — an unauthorized verb took effect")
    for k in final_state:
        if k not in ("orders", "outbox"):
            v.append(f"state grew a key outside scope: {k}")
    return v
