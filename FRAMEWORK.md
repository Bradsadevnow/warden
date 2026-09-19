# The mechanism

Running notes. This is an extraction of what `demo/kernel.py` actually does, stated
without the order-support domain. Every claim below names where it is enforced. Where
something is not built, it says so. Nothing here is a description of what governance
ought to be.

---

## 1. The question

Six domains, one question:

| domain | the question |
|---|---|
| Money | can this transaction occur? |
| Evidence | can this claim enter the governed corpus? |
| Memory | can this state be written? |
| Claims | can this assertion be admitted? |
| Research | can this result become part of the evidence chain? |
| AI agents | can this proposed action become an effect? |

The verb differs. The mechanism does not. In each case something nondeterministic
proposes, and something deterministic decides whether the proposal becomes real.

---

## 2. The parts

**Producer.** Anything that proposes and cannot be trusted to be correct: a model, a
researcher, an extractor, a user, another system. The producer's nondeterminism is not
reduced. It is *bounded on the write side only*.

**Nomination.** A proposal in a fixed grammar: `{what, verb, args}`. `what` names the
target in state. `verb` names an action. `args` are the parameters.
It is matched **literally**, never extracted from surrounding text
(`kernel.py:NOMINATION`). Extraction is interpretation, and interpretation is how the
producer's nondeterminism reaches the decision.

**Rationale.** Everything the producer emitted that was not a nomination. Checked for
*presence* and recorded **verbatim**. Never parsed, never transmitted, never used in a
decision. It exists so a claim cannot be retconned.

**Boundary.** A declaration, compiled into machinery at load (`Boundary.__init__`). It
declares, and is the only source of:
- `state_scope` — which paths may be written
- `verbs` — the complete action space; each with `permitted`, `writes`, and an arg schema
- `requires` — ordering preconditions over *admitted* history
- `invariants` — predicates over *resulting* state, per-object or aggregated

**Gate.** An ordered pipeline of named stages. Each stage may only **deny**. None may
grant (`Gate.adjudicate`).

**Effect.** One function per verb, the only code that touches canonical state
(`tools.py`). Called from exactly one place, `Gate._affect`.

**Receipt.** Written for every attempt, including denials and execution failures. Carries
the claim, the verbatim rationale, the decision, the per-stage check trace, the result,
and the resulting state.

**Audit.** Re-derives every rule from the declaration *without calling gate code*
(`invariants.py`). A gate that grades itself establishes nothing.

---

## 3. The pipeline

```
producer output
      |
      v
  schema        one nomination, matched literally; rationale present
  what          target is inside declared scope
  verb-auth     verb exists in the vocabulary AND is permitted
  args          arg names exact, types/patterns/ranges/enums satisfied
  precondition  required prior admitted action exists (optionally immediately)
      |
      v
  TRIAL: apply effect to a deep copy of state
      |
      v
  invariant     every declared invariant holds against the RESULTING state
      |
      v
  commit        copy replaces canonical state
  receipt       written on every path above, denials included
```

Two facts about this ordering that are load-bearing:

- **The invariant stage runs after the effect, on a copy.** You cannot know whether a
  transaction breaches an aggregate until you apply it. The effect is applied
  provisionally, tested, and discarded on breach (`kernel.py`, `trial` / `copy.deepcopy`).
- **Admission and execution are separate facts.** A nomination can be admitted and its
  effect still fail. Both go in the same receipt, on different lines. An attempt that
  raises is still receipted — otherwise the evidence trail goes blank exactly where
  something went wrong.

---

## 4. The properties

These are the engineering claims. Each can be violated, and each names how you would
detect the violation.

**P1 — Write monopoly.** Canonical state changes only through `_affect`, which is called
from one site, only after `decision = ACCEPT` and `invariant = PASS`.
*Violated if:* any other code path mutates state. *Detected by:* grep for assignment to
the state object outside `tools.py`.

**P2 — Total receipting.** Every adjudication produces a receipt. There is no path
through `adjudicate` that returns without `_receipt`.
*Violated if:* an attempt leaves no record. *Detected by:* `attempts == len(receipts)`,
asserted in `invariants.audit`.

**P3 — Inert non-match.** Producer output that does not match the grammar yields no
claim and no effect, and no repair is attempted.
*Violated if:* the gate tries to interpret near-misses. *Detected by:* feeding it a
template placeholder — `check.py` does this.

**P4 — Deny-monotonicity.** Every stage may only deny. ACCEPT is reachable only by
falling through all stages. No stage grants an authority a later stage would refuse.
*Violated if:* any check returns ACCEPT early. *Detected by:* structure — deny returns,
accept falls through.

**P5 — Invariant closure.** Committed state satisfies every declared invariant.
*Violated if:* an effect commits before invariants are tested. *Detected by:* the audit
re-testing final state, validated against known positives.

**P6 — Declaration completeness.** Admission rules come only from the boundary
declaration. The audit re-derives them from the same file without calling gate code.
*Violated if:* a rule lives in code but not in the declaration. *Detected by:* the audit
disagreeing with the gate.

---

## 5. Instantiating it

A domain must supply exactly six things:

1. **State shape** — what canonical state is
2. **Scope** — which paths within it are writable
3. **Verb vocabulary** — with exact arg schemas
4. **Effect functions** — one per verb, the only code touching state
5. **Invariants** — predicates over resulting state
6. **Preconditions** *(optional)* — ordering requirements over admitted history

The producer supplies nominations. Nothing else changes.

| domain | canonical state | a verb | an invariant |
|---|---|---|---|
| Money | accounts, orders | `issue_refund` | aggregate exposure <= cap |
| Evidence | admitted corpus | `admit_claim` | no admitted claim without a citation |
| Memory | memory store | `write_memory` | nothing canonical below N confirmations |
| Claims | assertion set | `assert_proposition` | no assertion whose support is not in the corpus |
| Research | evidence chain | `add_result` | every result references an admitted method |
| AI agents | application state | any | whatever the task boundary declares |

The evidence and claims rows are not analogy. In a governed evidence graph, an edge is a
nomination; typed-and-cited-and-confidence-rated is the admission check; and retaining
the negative findings is receipt-on-denial.

---

## 6. What the mechanism does not do

Stated because a control that does not do what its name implies is the failure this whole
thing exists to prevent.

- **It does not make the producer correct.** It bounds what an incorrect producer can
  cause. Nondeterminism on the propose side is total and deliberately untouched.
- **It does not evaluate content.** The gate decides *which verb with which args*. It has
  nothing to say about whether text is true. Outbound wording was closed by removing free
  text — the runtime renders from state — not by inspecting it. That does not generalise
  to a verb that genuinely needs prose.
- **It does not express time.** No velocity or rate limits. Nothing in the model has a
  clock.
- **It does not check entitlements.** `what` is matched against a scope pattern, not
  against a relationship. It cannot say "this order belongs to that customer."
- **It does not detect instrumental compliance.** A precondition that requires an action
  creates an incentive to perform that action for its own sake. Measured: the producer
  issued a token refund purely to unlock a gated verb, and said so
  (`demo/evidence/one_cent_key.json`). Aggregate caps bound the cost of doing this. That
  is containment, not a fix.

---

## 7. Not built yet

- Time-windowed constraints
- Entitlement/relationship checks on `what`
- Attestation as the first receipt in the ledger — `Boundary.attestation()` exists and is
  returned by the server, but nothing anchors a run to the rules it claims to have run under
- Kernel/domain separation — `kernel.py` is domain-agnostic; `boundary.yaml`, `tools.py`
  and the prompt compiler in `agent.py` are still fused to one domain
- Actor/role-scoped limits
