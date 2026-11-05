"""The gate.

One door. Deny by default. The only function that writes canonical state is
_affect(), and it is called from exactly one place, only on ACCEPT.

The nomination is matched LITERALLY against a fixed grammar. It is not
extracted from prose, because extraction is interpretation and interpretation
is how model nondeterminism gets into the gate's front door. A line either
matches the grammar or it does not exist as a nomination.
"""
import copy, json, re, time, uuid

# The grammar. Anchored, fixed, greppable. Non-match is not repaired.
NOMINATION = re.compile(
    r"^NOMINATE\s+what=(?P<what>\S+)\s+verb=(?P<verb>[a-z_]+)\s+args=(?P<args>.*)$")

DENY, ACCEPT = "DENY", "ACCEPT"

OPS = {"<=": lambda a, b: a <= b, "<": lambda a, b: a < b,
       ">=": lambda a, b: a >= b, ">": lambda a, b: a > b}
AGGS = {"sum": sum, "count": len, "max": lambda v: max(v, default=0)}


class BoundaryError(Exception):
    """The declaration is malformed. Raised at compile time so a typo in the
    boundary can never become a silently weaker gate."""


def landed(receipt):
    """An admitted nomination whose effect actually applied. Admission and
    execution are separate facts; only a landed action counts as history."""
    return (receipt["decision"] == ACCEPT and receipt["claim"] is not None
            and not any(c[0] == "execute" and c[1] == "ERROR"
                        for c in receipt["decision_basis"]))


def changed_paths(before, after, prefix=""):
    """Every path whose value differs between two states. Dicts are walked;
    lists and scalars are compared whole, so an append reports the list's path."""
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in set(before) | set(after):
            p = f"{prefix}/{k}" if prefix else str(k)
            if k not in before or k not in after:
                out.append(p)
            else:
                out += changed_paths(before[k], after[k], p)
        return out
    return [] if before == after else [prefix]


def under(path, allowed):
    return any(path == a or path.startswith(a + "/") for a in allowed)


class Boundary:
    """The compiled task boundary. YAML declares it; this compiles it. The
    declaration does not become the gate -- it is turned into machinery."""

    def __init__(self, spec):
        self.task = spec["task"]
        self.spec = spec
        self.scope = [re.compile(s.replace("*", "[^/]+") + "$") for s in spec["state_scope"]]
        self.verbs = spec["verbs"]
        self.invariants = spec.get("invariants", [])
        self._compile_check()

    def _compile_check(self):
        for name, v in self.verbs.items():
            if "what" not in v:
                raise BoundaryError(f"verb {name!r} declares no `what` binding")
            for k, r in v["args"].items():
                if r.get("type") not in ("int", "str"):
                    raise BoundaryError(f"{name}.{k}: unknown type {r.get('type')!r}")
            if v.get("also_writes") and not v["writes"]:
                raise BoundaryError(f"{name}: writes=false but declares also_writes")
            for extra in v.get("also_writes", []):
                if not self.in_scope(extra):
                    raise BoundaryError(f"{name}: also_writes {extra!r} is outside state_scope")
            for ph in re.findall(r"{(\w+)}", v["what"]):
                if ph not in v["args"]:
                    raise BoundaryError(f"{name}: what binding uses undeclared arg {ph!r}")
        for inv in self.invariants:
            if inv.get("op") not in OPS:
                raise BoundaryError(f"invariant {inv.get('name')!r}: unknown op {inv.get('op')!r}")
            if "aggregate" in inv:
                if inv["aggregate"] not in AGGS:
                    raise BoundaryError(f"invariant {inv['name']!r}: unknown aggregate {inv['aggregate']!r}")
                if "vs_value" not in inv:
                    raise BoundaryError(f"invariant {inv['name']!r}: aggregate needs vs_value")
            elif "vs_field" not in inv and "vs_value" not in inv:
                raise BoundaryError(f"invariant {inv['name']!r}: needs vs_field or vs_value")

    def expected_what(self, verb, args):
        """The one target this verb may touch given these args."""
        return self.verbs[verb]["what"].format(**args)

    def allowed_writes(self, verb, what):
        """The footprint this verb may change: its bound target plus anything
        it declares in also_writes. A writes=false verb may change nothing."""
        v = self.verbs[verb]
        return [what, *v.get("also_writes", [])] if v["writes"] else []

    def in_scope(self, what):
        return any(p.match(what) for p in self.scope)

    def check_invariants(self, state):
        """Every declared invariant, tested against a candidate state. Returns
        the first breach as (name, detail), or None. A field the invariant
        needs but an object lacks is a BREACH, not a skip: unknowable is not
        the same as satisfied."""
        for inv in self.invariants:
            prefix = inv["scope"].split("/")[0]
            objs = state.get(prefix) or {}
            op = OPS[inv["op"]]

            if "aggregate" in inv:
                missing = [k for k, o in objs.items() if o.get(inv["field"]) is None]
                if missing:
                    return inv["name"], f"{prefix}/{missing[0]} has no {inv['field']}"
                got = AGGS[inv["aggregate"]]([o[inv["field"]] for o in objs.values()])
                if not op(got, inv["vs_value"]):
                    return inv["name"], (f"{inv['aggregate']} of {inv['field']} across "
                                         f"{prefix}/* would be {got}, {inv['op']} {inv['vs_value']}")
                continue

            for key, obj in objs.items():
                got = obj.get(inv["field"])
                limit = (obj.get(inv["vs_field"]) if "vs_field" in inv
                         else inv.get("vs_value"))
                if got is None or limit is None:
                    return inv["name"], f"{prefix}/{key}: {inv['field']} or its limit is missing"
                if not op(got, limit):
                    named = inv.get("vs_field", "limit")
                    return inv["name"], (f"{prefix}/{key}: {inv['field']} would be {got}, "
                                         f"{inv['op']} {named} {limit}")
        return None

    def attestation(self):
        """First receipt: what this instance actually enforces. The compiler is
        the trust root, so it says so out loud."""
        return {"task": self.task,
                "scope": [p.pattern for p in self.scope],
                "verbs": {v: {"permitted": d["permitted"], "writes": d["writes"], "what": d["what"], "also_writes": d.get("also_writes", []),
                              "args": sorted(d["args"])} for v, d in self.verbs.items()},
                "invariants": [i["name"] for i in self.invariants]}


class Gate:
    def __init__(self, boundary, state, tools):
        self.b, self.state, self.tools = boundary, state, tools
        self.receipts = []

    # ---- the only writer of canonical state -------------------------------
    def _affect(self, verb, what, args):
        return self.tools[verb](self.state, what, args)

    # ---- the ordered pipeline ---------------------------------------------
    def adjudicate(self, model_output):
        checks = []
        def deny(stage, why):
            checks.append([stage, "DENY", why])
            return self._receipt(model_output, None, DENY, checks, None)

        # rationale is not a gate on state. It is checked for PRESENCE only,
        # then recorded verbatim so a claim can never be retconned.
        lines = [l for l in model_output.splitlines() if l.strip()]
        noms = [m for m in (NOMINATION.match(l.strip()) for l in lines) if m]
        rationale = "\n".join(l for l in lines if not NOMINATION.match(l.strip())).strip()

        if not noms:
            return deny("schema", "no line matched the nomination grammar")
        if len(noms) > 1:
            return deny("schema", f"{len(noms)} nominations in one turn; one gate, one nomination")
        if not rationale:
            return deny("rationale", "nomination carried no rationale")
        checks.append(["schema", "PASS", "one nomination, rationale present"])

        nom = noms[0].groupdict()
        what, verb, rawargs = nom["what"], nom["verb"], nom["args"]

        if not self.b.in_scope(what):
            return deny("what", f"{what!r} is outside the declared state scope")
        checks.append(["what", "PASS", f"{what} in scope"])

        spec = self.b.verbs.get(verb)
        if spec is None:
            return deny("verb-auth", f"verb {verb!r} is not in the boundary vocabulary")
        if not spec["permitted"]:
            return deny("verb-auth", f"verb {verb!r} is declared but not authorized")
        checks.append(["verb-auth", "PASS", f"{verb} authorized"])

        ok, args_or_why = self._args(spec["args"], rawargs)
        if not ok:
            return deny("args", args_or_why)
        checks.append(["args", "PASS", json.dumps(args_or_why)])

        # BIND. `what` is where the effect lands; the args are what the receipt
        # claims and what preconditions read. If they can differ, a receipt can
        # describe a different action than the one that executed.
        want = self.b.expected_what(verb, args_or_why)
        if what != want:
            return deny("bind", f"what={what!r} does not match the target {want!r} "
                                f"that {verb} with these args may touch")
        checks.append(["bind", "PASS", f"what == {want}"])

        req = spec.get("requires")
        if req:
            need_v, need_a = req["verb"], req["matching_arg"]
            mine = args_or_why.get(need_a)
            admitted = [r for r in self.receipts if landed(r)]
            if req.get("immediately"):
                last = admitted[-1]["claim"] if admitted else None
                ok = bool(last and last["verb"] == need_v
                          and last["args"].get(need_a) == mine)
                if not ok:
                    was = (f"{last['verb']} on {need_a}={last['args'].get(need_a)}"
                           if last else "nothing")
                    return deny("precondition",
                                f"{verb} must immediately follow {need_v} on {need_a}={mine}; "
                                f"the last admitted action was {was}. A resend is manual.")
                checks.append(["precondition", "PASS",
                               f"immediately follows {need_v} on {need_a}={mine}"])
            else:
                done = any(r["claim"]["verb"] == need_v
                           and r["claim"]["args"].get(need_a) == mine for r in admitted)
                if not done:
                    return deny("precondition",
                                f"{verb} requires a prior {need_v} on {need_a}={mine}; "
                                f"none has been admitted this session")
                checks.append(["precondition", "PASS",
                               f"{need_v} on {need_a}={mine} was admitted earlier"])

        checks.append(["decision", ACCEPT, "all checks passed"])
        # Admission and execution are different facts. The gate admitted this;
        # whether the effect succeeded is a separate line in the same receipt.
        # An attempt that raises must still be receipted, or the evidence trail
        # goes blank exactly where something went wrong.
        # Apply to a COPY first. Nothing reaches canonical state until every
        # declared invariant holds against the result.
        trial = copy.deepcopy(self.state)
        saved, self.state = self.state, trial
        try:
            result = self._affect(verb, what, args_or_why)
            err = None
        except Exception as e:
            result, err = {"error": f"{type(e).__name__}: {e}"}, e
        finally:
            self.state = saved

        if err is not None:
            checks.append(["invariant", "SKIP", "effect did not apply"])
            checks.append(["execute", "ERROR", result["error"]])
            return self._receipt(model_output, {"what": what, "verb": verb,
                                                "args": args_or_why}, ACCEPT, checks, result)

        # FOOTPRINT. The scope check above matched a label. This checks the
        # effect: every path the verb actually changed must be one it declared.
        allowed = self.b.allowed_writes(verb, what)
        strays = [p for p in changed_paths(self.state, trial) if not under(p, allowed)]
        if strays:
            checks.append(["footprint", "DENY",
                           f"{verb} changed {sorted(strays)}, outside its declared "
                           f"footprint {allowed}. Rolled back."])
            return self._receipt(model_output, {"what": what, "verb": verb,
                                                "args": args_or_why}, DENY, checks, None)
        checks.append(["footprint", "PASS", f"changes confined to {allowed or 'nothing'}"])

        breach = self.b.check_invariants(trial)
        if breach:
            name, detail = breach
            checks.append(["invariant", "DENY", f"{name} -- {detail}. Rolled back."])
            return self._receipt(model_output, {"what": what, "verb": verb,
                                                "args": args_or_why}, DENY, checks, None)
        checks.append(["invariant", "PASS",
                       f"{len(self.b.invariants)} invariant(s) hold after this effect"])
        self.state.clear(); self.state.update(trial)          # commit
        checks.append(["execute", "OK", "effect applied"])
        return self._receipt(model_output, {"what": what, "verb": verb, "args": args_or_why},
                             ACCEPT, checks, result)

    def _args(self, schema, raw):
        got = {}
        for part in [p for p in raw.split(";") if p.strip()]:
            if ":" not in part:
                return False, f"malformed arg {part!r}, expected key:value"
            k, v = part.split(":", 1)
            k = k.strip()
            if k in got:
                return False, f"duplicate arg {k!r}"
            got[k] = v.strip()
        if set(got) != set(schema):
            return False, f"args {sorted(got)} do not match declared {sorted(schema)}"
        out = {}
        for k, rule in schema.items():
            v = got[k]
            if rule["type"] == "int":
                if not re.fullmatch(r"-?[0-9]+", v):
                    return False, f"{k}={v!r} is not an integer"
                v = int(v)
                if "min" in rule and v < rule["min"]:
                    return False, f"{k}={v} below declared minimum {rule['min']}"
                if "max" in rule and v > rule["max"]:
                    return False, f"{k}={v} exceeds declared maximum {rule['max']}"
            else:
                if "enum" in rule and v not in rule["enum"]:
                    return False, f"{k}={v!r} is not one of {rule['enum']}"
                if "pattern" in rule and not re.fullmatch(rule["pattern"], v):
                    return False, f"{k}={v!r} does not match {rule['pattern']}"
                if "max_len" in rule and len(v) > rule["max_len"]:
                    return False, f"{k} is {len(v)} chars, declared max {rule['max_len']}"
            out[k] = v
        return True, out

    def _receipt(self, model_output, claim, decision, checks, result):
        r = {"id": uuid.uuid4().hex[:8], "ts": time.time(), "task": self.b.task,
             "claim": claim,
             "rationale": model_output,        # verbatim, never parsed, never edited
             "decision": decision,
             "decision_basis": checks,         # the gate's own why
             "result": result,
             "state_after": json.loads(json.dumps(self.state))}
        self.receipts.append(r)
        return r
