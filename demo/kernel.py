"""The gate.

One door. Deny by default. The only function that writes canonical state is
_affect(), and it is called from exactly one place, only on ACCEPT.

The nomination is matched LITERALLY against a fixed grammar. It is not
extracted from prose, because extraction is interpretation and interpretation
is how model nondeterminism gets into the gate's front door. A line either
matches the grammar or it does not exist as a nomination.
"""
import base64, copy, hashlib, json, re, secrets, time, uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# The grammar. Anchored, fixed, greppable. Non-match is not repaired.
NOMINATION = re.compile(
    r"^NOMINATE\s+what=(?P<what>\S+)\s+verb=(?P<verb>[a-z_]+)\s+args=(?P<args>.*)$")

DENY, ACCEPT, HOLD = "DENY", "ACCEPT", "HOLD"

OPS = {"<=": lambda a, b: a <= b, "<": lambda a, b: a < b,
       ">=": lambda a, b: a >= b, ">": lambda a, b: a > b}
AGGS = {"sum": sum, "count": len, "max": lambda v: max(v, default=0)}


class BoundaryError(Exception):
    """The declaration is malformed. Raised at compile time so a typo in the
    boundary can never become a silently weaker gate."""


class AuthzError(Exception):
    """An approval that does not verify. Raised to the caller, never to the model."""


AUTHZ_TTL = 120          # seconds a challenge, and the grant it becomes, stays valid
MAX_PENDING = 20


def canonical_action(boundary_hash, principal, what, verb, args, nonce, expires):
    """The exact bytes a human signs. Domain-separated and bound to the compiled
    boundary and policy, WHO is acting, the one action, a single-use nonce and an
    expiry. The approval screen renders THESE lines, so what is shown is what is
    signed."""
    return "\n".join(["warden-authz-v2", f"boundary:{boundary_hash}", f"principal:{principal}",
                      f"what:{what}",
                      f"verb:{verb}",
                      "args:" + json.dumps(args, sort_keys=True, separators=(",", ":")),
                      f"nonce:{nonce}", f"expires:{expires}"])


def verify_signature(public_raw, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


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
        self._compile_policy()

    # ---- identity and policy: compiled to flat sets, never interpreted live ----
    def _compile_policy(self):
        """Groups, principals and rules are resolved here, once. Inheritance
        (`includes`) is flattened and cycle-checked, group references become
        member sets, and every reference is validated. Nothing about a group is
        looked up at decision time."""
        groups = self.spec.get("groups", {})
        closure = {}

        def close(g, trail=()):
            if g in trail:
                raise BoundaryError(f"group inheritance cycle through {g!r}")
            if g not in groups:
                raise BoundaryError(f"unknown group {g!r}")
            out = {g}
            for inc in (groups[g] or {}).get("includes", []):
                out |= close(inc, trail + (g,))
            return out

        for g in groups:
            closure[g] = close(g)
        self.principals = self.spec.get("principals", {})
        self.effective_groups = {}
        for p, d in self.principals.items():
            if d.get("kind") not in ("human", "agent"):
                raise BoundaryError(f"principal {p!r}: kind must be human or agent")
            eff = set()
            for g in d.get("groups", []):
                if g not in groups:
                    raise BoundaryError(f"principal {p!r}: unknown group {g!r}")
                eff |= closure[g]
            self.effective_groups[p] = eff
        if "owner" in self.principals or "owner" in groups:
            raise BoundaryError("`owner` is reserved: it names an agent's owner in a hold rule")
        logins = {}
        for p, d in self.principals.items():
            if "login" in d:
                e = d["login"]
                if d["kind"] != "human" or not isinstance(e, str) or "@" not in e:
                    raise BoundaryError(f"principal {p!r}: `login` is a person's email, and only humans have one")
                if e.lower() in logins:
                    raise BoundaryError(f"principal {p!r}: login {e!r} already belongs to {logins[e.lower()]!r}")
                logins[e.lower()] = p
        for p, d in self.principals.items():
            o = d.get("owner")
            if o is not None and (d["kind"] != "agent" or
                                  self.principals.get(o, {}).get("kind") != "human"):
                raise BoundaryError(f"principal {p!r}: an owner must be a human, and only agents have one")

        def members(entries, where):
            out = set()
            for e in entries:
                if e.startswith("group:"):
                    if e[6:] not in groups:
                        raise BoundaryError(f"{where}: unknown group {e!r}")
                    out |= {p for p, eff in self.effective_groups.items() if e[6:] in eff}
                elif e in self.principals:
                    out.add(e)
                else:
                    raise BoundaryError(f"{where}: unknown principal {e!r}")
            return out

        self.rules, seen = [], set()
        for i, r in enumerate(self.spec.get("policy", [])):
            rid = r.get("id") or f"rule{i}"
            where = f"policy rule {rid!r}"
            if rid in seen:
                raise BoundaryError(f"{where}: duplicate id")
            seen.add(rid)
            if r.get("effect") not in ("allow", "hold", "deny"):
                raise BoundaryError(f"{where}: effect must be allow, hold or deny")
            if not r.get("to") or not r.get("verbs"):
                raise BoundaryError(f"{where}: needs `to` and `verbs`")
            for v in r["verbs"]:
                if v not in self.verbs:
                    raise BoundaryError(f"{where}: unknown verb {v!r}")
            w = r.get("when")
            if w is not None:
                if w.get("op") not in OPS or not isinstance(w.get("value"), int):
                    raise BoundaryError(f"{where}: `when` needs a known op and an int value")
                for v in r["verbs"]:
                    if self.verbs[v]["args"].get(w.get("arg"), {}).get("type") != "int":
                        raise BoundaryError(f"{where}: `when` arg {w.get('arg')!r} is not an int arg of {v}")
            to = members(r["to"], where)
            # approvers, resolved PER ACTING AGENT. The word `owner` means "whoever
            # that agent's owner is", so one rule can cover many agents and each is
            # approved by its own responsible person.
            approvers = {}
            if r["effect"] == "hold":
                entries = list(r.get("approvers", []))
                fixed = {p for p in members([e for e in entries if e != "owner"], where)
                         if self.principals[p]["kind"] == "human"}
                for p in sorted(to):
                    if self.principals[p]["kind"] != "agent":
                        continue            # people never act through the gate
                    mine = set(fixed)
                    if "owner" in entries and self.principals[p].get("owner"):
                        mine.add(self.principals[p]["owner"])
                    if not mine:
                        raise BoundaryError(f"{where}: agent {p!r} would have no human to approve it")
                    approvers[p] = mine
            elif "approvers" in r:
                raise BoundaryError(f"{where}: only a hold names approvers")
            self.rules.append({
                "id": rid, "effect": r["effect"], "to": to,
                "verbs": set(r["verbs"]), "when": w, "approvers": approvers,
                "ttl": int(r.get("ttl", AUTHZ_TTL)),
                "what": [re.compile(s.replace("*", "[^/]+") + "$") for s in r["what"]] if "what" in r else None})

    def evaluate(self, principal, verb, what, args):
        """The policy decision for one nomination. Returns ("DENY", why) or
        ("ALLOW", [hold rules]). Deny beats everything; with no allow the answer
        is deny; surviving hold rules are conjunctive, so the human must satisfy
        every one."""
        if principal not in self.principals:
            return DENY, f"{principal!r} is not a known principal"
        allowed, holds = False, []
        for r in self.rules:
            if principal not in r["to"] or verb not in r["verbs"]:
                continue
            if r["what"] is not None and not any(p.match(what) for p in r["what"]):
                continue
            w = r["when"]
            if w is not None and not OPS[w["op"]](args[w["arg"]], w["value"]):
                continue
            if r["effect"] == "deny":
                return DENY, f"rule {r['id']} denies {verb} for {principal}"
            if r["effect"] == "allow":
                allowed = True
            else:
                if not r["approvers"].get(principal):
                    return DENY, f"rule {r['id']} holds {verb} but nobody can approve it for {principal}"
                holds.append(r)
        if not allowed:
            return DENY, f"no policy rule allows {principal} to {verb}"
        return "ALLOW", holds

    def _compile_check(self):
        for name, v in self.verbs.items():
            if "what" not in v:
                raise BoundaryError(f"verb {name!r} declares no `what` binding")
            for k, r in v["args"].items():
                if r.get("type") not in ("int", "str"):
                    raise BoundaryError(f"{name}.{k}: unknown type {r.get('type')!r}")
            if "authorization" in v:
                raise BoundaryError(f"{name}: `authorization` moved into `policy` as a hold rule")
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
                "digest": self.digest(),
                "scope": [p.pattern for p in self.scope],
                "verbs": {v: {"permitted": d["permitted"], "writes": d["writes"], "what": d["what"],
                              "also_writes": d.get("also_writes", []),
                              "args": sorted(d["args"])} for v, d in self.verbs.items()},
                "invariants": [i["name"] for i in self.invariants],
                "principals": {p: {"kind": d["kind"], "groups": sorted(self.effective_groups[p])}
                               for p, d in self.principals.items()},
                "policy": [{"id": r["id"], "effect": r["effect"], "verbs": sorted(r["verbs"]),
                            "to": sorted(r["to"]),
                            "approvers": {p: sorted(s) for p, s in sorted(r["approvers"].items())}}
                           for r in self.rules]}

    def digest(self):
        """Hash of the ENTIRE declaration, limits included. A signature bound to
        this cannot be reused under a boundary with different numbers."""
        return hashlib.sha256(json.dumps(self.spec, sort_keys=True).encode()).hexdigest()


class Gate:
    def __init__(self, boundary, state, tools, principal=None, approvers=None, clock=time.time):
        self.b, self.state, self.tools = boundary, state, tools
        # WHO is acting. Set by the runtime that authenticated the session, never by
        # the model, and never present in the nomination grammar. None fails closed.
        self.principal = principal
        self.receipts = []
        self.approvers = dict(approvers or {})   # id -> raw 32-byte Ed25519 PUBLIC key
        self.clock = clock                       # the gate's clock, never the agent's
        self.pending = {}                        # nonce -> a held nomination awaiting a signature
        self.grants = {}                         # action key -> a verified signature
        self.used = set()                        # nonces already spent

    # ---- human authorization ----------------------------------------------
    def attestation(self):
        att = self.b.attestation()
        att["approvers"] = {i: hashlib.sha256(k).hexdigest()[:16]
                            for i, k in sorted(self.approvers.items())}
        return att

    def boundary_hash(self):
        return hashlib.sha256(json.dumps(self.attestation(), sort_keys=True).encode()).hexdigest()

    def enroll(self, approver_id, public_raw):
        """Register a public key. Never overwrites: a key cannot be swapped."""
        if self.b.principals.get(approver_id, {}).get("kind") != "human":
            raise AuthzError(f"{approver_id!r} is not a human principal")
        if approver_id in self.approvers:
            raise AuthzError(f"approver {approver_id!r} is already enrolled")
        if len(public_raw) != 32:
            raise AuthzError("an Ed25519 public key is 32 bytes")
        self.approvers[approver_id] = public_raw

    @staticmethod
    def _akey(principal, what, verb, args):
        return json.dumps([principal, what, verb, args], sort_keys=True)

    def _challenge(self, what, verb, args, output, holds):
        now = self.clock()
        self.pending = {n: p for n, p in self.pending.items() if p["expires"] > now}
        key = self._akey(self.principal, what, verb, args)
        for n, p in self.pending.items():
            if p["key"] == key:
                return n
        if len(self.pending) >= MAX_PENDING:
            return None
        nonce = secrets.token_urlsafe(12)
        self.pending[nonce] = {"principal": self.principal, "what": what, "verb": verb,
                               "args": args, "key": key, "holds": [r["id"] for r in holds],
                               "approvers": sorted(set.intersection(
                                   *(r["approvers"][self.principal] for r in holds))),
                               "expires": int(now) + min(r["ttl"] for r in holds),
                               "bh": self.boundary_hash(), "output": output}
        return nonce

    def canonical(self, nonce):
        p = self.pending[nonce]
        return canonical_action(p["bh"], p["principal"], p["what"], p["verb"], p["args"],
                                nonce, p["expires"])

    def approve(self, nonce, approver_id, signature):
        """Verify a signature over a held challenge, record it as a grant, and put
        the SAME nomination back through the whole pipeline. Approval is not a
        decision: the gate still adjudicates, and every other check still applies."""
        p = self.pending.get(nonce)
        if p is None or p["expires"] < self.clock():
            raise AuthzError("unknown or expired challenge")
        if p["bh"] != self.boundary_hash():
            raise AuthzError("challenge was issued under a different boundary")
        pub = self.approvers.get(approver_id)
        if pub is None:
            raise AuthzError("unknown approver")
        if approver_id == p["principal"]:
            raise AuthzError("a principal cannot approve its own action")
        if approver_id not in p["approvers"]:
            raise AuthzError(f"{approver_id!r} is not an approver for rule(s) {p['holds']}")
        msg = self.canonical(nonce)
        if not verify_signature(pub, signature, msg.encode()):
            raise AuthzError("signature does not verify")
        self.grants[p["key"]] = {"nonce": nonce, "approver": approver_id, "holds": p["holds"],
                                 "expires": p["expires"],
                                 "sig": base64.b64encode(signature).decode(), "canonical": msg}
        del self.pending[nonce]
        return self.adjudicate(p["output"], principal=p["principal"])

    def _valid_grant(self, what, verb, args):
        """A grant is spent only if it verifies NOW against this exact nomination."""
        g = self.grants.get(self._akey(self.principal, what, verb, args))
        if not g or g["nonce"] in self.used or self.clock() > g["expires"]:
            return None
        want = canonical_action(self.boundary_hash(), self.principal, what, verb, args,
                                g["nonce"], g["expires"])
        pub = self.approvers.get(g["approver"])
        if want != g["canonical"] or pub is None:
            return None
        if not verify_signature(pub, base64.b64decode(g["sig"]), want.encode()):
            return None
        return g

    # ---- the only writer of canonical state -------------------------------
    def _affect(self, verb, what, args):
        return self.tools[verb](self.state, what, args)

    # ---- the ordered pipeline ---------------------------------------------
    def adjudicate(self, model_output, principal=None):
        """`principal` is set by whoever AUTHENTICATED the caller (the service),
        for this one call. Callers must serialize calls; the gate is not reentrant."""
        if principal is None:
            return self._adjudicate(model_output)
        saved, self.principal = self.principal, principal
        try:
            return self._adjudicate(model_output)
        finally:
            self.principal = saved

    def _adjudicate(self, model_output):
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

        # POLICY. Who may do this. Deny beats everything, and the absence of an
        # allow is a deny. Hold rules that apply are noted here and enforced after
        # the preconditions, so a human is never asked to sign something that
        # would have been refused anyway.
        verdict, detail = self.b.evaluate(self.principal, verb, what, args_or_why)
        if verdict == DENY:
            return deny("policy", detail)
        holds = detail
        checks.append(["policy", "PASS", f"{self.principal} may {verb}"
                       + (f"; hold by {[r['id'] for r in holds]}" if holds else "")])

        req = spec.get("requires")
        if req:
            need_v, need_a = req["verb"], req["matching_arg"]
            mine = args_or_why.get(need_a)
            # history is per principal: another agent's refund never unlocks this one
            admitted = [r for r in self.receipts
                        if landed(r) and r["principal"] == self.principal]
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

        # HOLD. A hold rule that applies needs a human signature over exactly this
        # action. Without one the nomination is held, not executed, and a challenge
        # is issued; the signature arrives out of band via approve(), never inside
        # model output.
        if holds:
            g = self._valid_grant(what, verb, args_or_why)
            if g is None or set(g["holds"]) != {r["id"] for r in holds}:
                nonce = self._challenge(what, verb, args_or_why, model_output, holds)
                if nonce is None:
                    return deny("hold", f"{verb} needs a human signature and too many "
                                        f"approvals are already pending")
                checks.append(["hold", "HOLD",
                               f"{verb} needs a human signature from one of "
                               f"{self.pending[nonce]['approvers']} under {self.pending[nonce]['holds']}. "
                               f"challenge={nonce}"])
                return self._receipt(model_output, None, HOLD, checks, None)
            self.used.add(g["nonce"])
            checks.append(["authz", "PASS", json.dumps(
                {"nonce": g["nonce"], "approver": g["approver"], "holds": g["holds"],
                 "sig": g["sig"], "canonical": g["canonical"]}, sort_keys=True)])

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
        r = {"id": uuid.uuid4().hex[:8], "ts": self.clock(), "task": self.b.task, "principal": self.principal,
             "claim": claim,
             "rationale": model_output,        # verbatim, never parsed, never edited
             "decision": decision,
             "decision_basis": checks,         # the gate's own why
             "result": result,
             "state_after": json.loads(json.dumps(self.state))}
        self.receipts.append(r)
        return r
