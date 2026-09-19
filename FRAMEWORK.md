# The mechanism

Running notes. An extraction of what `demo/kernel.py` does, without the domain.

---

## The invariant

**Canonical state changes only through a nomination that passed every declared check.**

That is the whole gate. Everything else is either how that is enforced, or a
consequence of it.

Enforced by three structural facts, not by rules:

- **One writer.** `Gate._affect` is the only code that touches canonical state, and it
  is called from exactly one place.
- **Deny returns, accept falls through.** Every check can only deny. ACCEPT is not a
  thing any stage can grant; it is what is left when nothing denied.
- **Trial then commit.** The effect applies to a deep copy. The copy replaces canonical
  state only if every declared invariant holds against the result. On breach it is
  discarded.

**To falsify:** find a state change with no admitting receipt, or a receipt whose checks
did not all pass. `invariants.py` looks for exactly this, re-derived from the declaration
without calling gate code — because a gate that grades itself establishes nothing.

---

## What "passed every declared check" means

An ordered pipeline. Each stage may only deny.

```
schema        one nomination, matched literally against a fixed grammar;
              rationale present
what          target inside declared scope
verb-auth     verb exists in the vocabulary AND is permitted
args          arg names exact; types, patterns, ranges, enums satisfied
precondition  required prior admitted action exists (optionally immediately)
--- effect applies to a copy ---
invariant     every declared invariant holds against the RESULTING state
--- copy commits ---
```

Two orderings are load-bearing:

- **The invariant stage runs after the effect, on a copy.** You cannot know whether a
  transaction breaches an aggregate until you apply it.
- **Admission and execution are separate facts.** A nomination can be admitted and its
  effect still fail. Both go in the same receipt. An attempt that raises is still
  receipted, or the trail goes blank exactly where something went wrong.

The nomination is matched **literally**, never extracted from surrounding prose.
Extraction is interpretation, and interpretation is how the producer's nondeterminism
reaches the decision. Everything that is not a nomination is rationale: checked for
presence, recorded verbatim, never parsed, never transmitted, never used in a decision.

---

## The question, six ways

| domain | the question | canonical state | a verb | an invariant |
|---|---|---|---|---|
| Money | can this transaction occur? | accounts, orders | `issue_refund` | aggregate exposure <= cap |
| Evidence | can this claim enter the corpus? | admitted corpus | `admit_claim` | no admitted claim without a citation |
| Memory | can this state be written? | memory store | `write_memory` | nothing canonical below N confirmations |
| Claims | can this assertion be admitted? | assertion set | `assert_proposition` | no assertion whose support is not in the corpus |
| Research | can this result join the chain? | evidence chain | `add_result` | every result references an admitted method |
| AI agents | can this action become an effect? | application state | any | whatever the boundary declares |

The evidence rows are not analogy. In a governed evidence graph an edge is a nomination,
typed-and-cited-and-confidence-rated is the admission check, and retaining the negative
findings is receipt-on-denial.

---

## To instantiate

Supply six things. Nothing else changes.

1. State shape
2. Scope — which paths are writable
3. Verb vocabulary with exact arg schemas
4. Effect functions — one per verb, the only code touching state
5. Invariants over resulting state
6. Preconditions *(optional)* — ordering over admitted history

---

## What it does not do

A control that does not do what its name implies is the failure this exists to prevent.

- **Does not make the producer correct.** It bounds what an incorrect producer can cause.
  Nondeterminism on the propose side is total and deliberately untouched.
- **Does not evaluate content.** It decides which verb with which args, and has nothing
  to say about whether text is true. Outbound wording was closed by removing free text —
  the runtime renders from state — not by inspecting it. That does not generalise to a
  verb that needs prose.
- **No clock.** No velocity or rate limits.
- **No entitlements.** `what` matches a scope pattern, not a relationship. It cannot say
  "this order belongs to that customer."
- **Does not detect instrumental compliance.** A precondition that requires an action
  creates an incentive to perform that action for its own sake. Measured: the producer
  issued a token refund purely to unlock a gated verb, and said so
  (`demo/evidence/one_cent_key.json`). Aggregate caps bound the cost. Containment, not a fix.

---

## Not built

Time-windowed constraints. Entitlement checks on `what`. Attestation as the first receipt
so a run is anchored to the rules it ran under. Actor/role-scoped limits. Kernel/domain
separation — `kernel.py` is domain-agnostic, but `boundary.yaml`, `tools.py` and the
prompt compiler in `agent.py` are still fused to one domain, so that separation is a
claim and not yet a fact.
