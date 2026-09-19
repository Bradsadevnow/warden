# Order of work

Framework first. The CRM is #todo after it.

---

## NOW — framework

Things that make this a mechanism framework rather than a demo with a config file.

- [ ] **Split the kernel from the domain.** `kernel.py` already knows nothing about
      orders, which is right. `boundary.yaml`, `tools.py` and the prompt compiler in
      `agent.py` are still fused to this one domain. Until they separate, "domain
      agnostic" is a claim rather than a fact.
- [ ] **Time-windowed constraints.** Velocity and rate limits are not expressible —
      nothing in the model has a clock. "No more than N refunds per hour" is the next
      constraint class after book limits, and the one finance asks for immediately.
- [ ] **Entitlements / object-level authorization.** `what` is matched against a scope
      pattern, not against a relationship. Nothing can say "this order belongs to that
      customer." This is the single most common real-world agent failure (OWASP API #1)
      and the boundary language cannot currently express it at all.
- [ ] **Make the compiler the trust root, honestly.** `Boundary.attestation()` reports
      what the instance enforces. It should be the first receipt in the ledger, so the
      run is anchored to the rules it claims to have been run under.

### Known limits, deliberately unfixed (keep them in the demo)

- **A precondition is an incentive.** `send_message` requires an `issue_refund`
  immediately prior; the model issues a token refund purely to unlock the verb and
  states the reasoning plainly. Aggregate caps bound how much it can spend doing this,
  which is containment, not a fix. Transcript: `demo/evidence/one_cent_key.json`.
- **Content semantics.** Solved for outbound by removing free text, not by inspecting
  it. Does not generalise to a verb that genuinely needs prose.

---

## #todo — CRM (after the framework)

Ten fake customers with return accounts and order history. The CRM layer itself is
ordinary SWE. What matters is what it forces the boundary language to express.

**What it buys, in priority order:**

1. **A hierarchy of aggregates.** Today: per-object and flat book-wide sum. A CRM gives
   order -> customer -> book, i.e. position -> account -> firm. Scoping an aggregate by
   a parent key is a real extension, and it is the third thing a risk person checks.
2. **Entitlements.** With ten customers, the interesting attack is refunding Y's order
   into X's return account. This is where the entitlement gap above becomes visible
   rather than theoretical. Expect this to be the best find in the build.
3. **New risk shapes per verb.** Store credit vs refund-to-card are different rails with
   different limits. Editing contact details is a PII write with no money attached.
   Merging duplicate records is destructive and irreversible. Each stress-tests whether
   the boundary language generalises or just happens to fit refunds.

**Design the fixture to exercise constraint classes, not to look realistic.** A plausible
CRM that makes no new gap reachable is wasted work. Shape the ten deliberately:

- one customer with many small orders -> velocity, and the per-customer aggregate
- one with a single large order -> per-order vs book tension
- two with near-identical names -> the wrong-entity attack
- one with a return already in flight -> a state machine, so "close an already-closed
  return" becomes expressible
- one with zero history -> the empty-referent case that crashed a tool earlier

**Open decisions, to settle before writing any of it:**

- **Does the boundary get an actor?** Today it declares what *the agent* may do. A CRM
  invites "this operator may refund up to $X, a supervisor up to $Y" — role-based limits.
  Real finance shape, significant addition. It is the difference between a permission
  system and a limit system, and it changes the shape of `boundary.yaml`, so it is the
  first question.
- **One money verb or two** (card vs store credit)? Two composes better for limits and
  doubles the verb surface.
- **Returns as a state machine** (requested -> approved -> received -> refunded)? Makes
  `requires` do real work beyond the one-step window, and it is where "approve your own
  return" lives.

**Deliberately not building:** no database, no auth, no login. Seed function in memory,
reset button, session-scoped. Persistence is plumbing that proves nothing — being able
to reset and attack it again is the demo's value.
