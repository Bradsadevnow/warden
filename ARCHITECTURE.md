# Warden — Governance Kernel Architecture

*Designed 2026-09-15 (Brad Bates, with Claude / Fable / GPT as thinking partners).*
*The abstract governance primitive that Chelys, the runtime, and halcyon are each one instance of.*

---

## The problem it solves

Small (and large) models fail in an agent loop not by being wrong, but by being **dishonest under
pressure** — they fabricate execution ("all tests passed"), invent bugs in correct code, and claim
constraint satisfaction that isn't there. You cannot make a model honest by asking it to be. You can only
make the *boundary* it crosses honest.

The naive fix — add governance checkpoints everywhere — is self-defeating: **any gate that produces a
task-graded outcome becomes a failstate the model learns to produce as a "valid" completion.** Governance
density manufactures the very failures it tries to prevent.

## The core principles

1. **One gate per task.** Not many gates — one membrane with an ordered internal validation *pipeline*.
   Safety scales by **task decomposition** (smaller atomic tasks, one gate each), never by gate density.

2. **Deny-by-default + write-monopoly = one door.** `affect(verb, args)` is the *sole* writer of canonical
   state, and it fires only on ACCEPT. So state can *only* change through an authorized, validated
   nomination. "Where do the other gates go — nowhere" becomes **structural, not preference**: there is no
   other path to gate. Model nondeterminism is total on the propose side and **zero** on the commit side.

3. **Nominations are a GREPPABLE SCHEMA, not extracted.** Extraction = interpretation = nondeterminism
   leaking into the gate's front door. The model emits a fixed grammar the gate matches *literally*;
   non-match = deny (inert, not gameable). Post-hoc grep — **never** grammar-constrained decoding, which
   would constrain the model's generation and manufacture failstates. The model's output splits by
   *construction*: the greppable nomination (actionable) + everything else (rationale, verbatim, never parsed).

4. **"Why" is not a state-gate — it is the receipt.** `rationale = raw model_output`, evaluated at
   admission for *presence* (deny if absent) but written to the trail **unchanged** — attributable to the
   model, un-retconnable. State safety is carried by *what* (validated vs canonical state) + verb-auth +
   args + deny-default. Because the why doesn't write state, even a judgment-based evaluation can't endanger
   determinism. **Every attempt is receipted, including rejects** — fabrication you can't prevent, you also
   can't hide or disown.

## The gate

```
                           MODEL
                            │  claim
                            ▼
              ┌─────────────────────────┐
              │          GATE           │
              │   schema validation     │
              │   what evaluation       │   ← validated against canonical state
              │   verb authorization    │
              │   argument validation   │
              │      ACCEPT / REJECT     │
              │            │            │
              │     affect(verb, args)  │   ← the SOLE writer, fires only on ACCEPT
              └────────────┼────────────┘
                    ┌──────┴──────┐
                    ▼             ▼
             CANONICAL STATE    RECEIPT { claim, rationale, decision, affect, result }
```

## The data structures

```
NOMINATION { what, verb, args }                      # extracted-free: model emits this as a greppable schema
ADMISSION  { nomination, decision, ...check-trace }  # the gate's decision + why IT decided (deterministic checks)
RECEIPT    { claim: nomination,                       # what was proposed
             rationale: model_output,                 # what the model actually said, VERBATIM (immutable)
             decision, affect, result }               # accept/reject, the write performed, the outcome
```

Two "why"s live in the record and stay apart: the model's **rationale** (verbatim) and the gate's
**decision-basis** (which checks passed). The gap between them is where you catch a model that reasons one
way but is admitted for another — and where you catch your own gate rubber-stamping.

## Instantiated around a declared task boundary

The runtime is **not** a general agent with governance bolted on. Each instance is declared:

```
RUNTIME INSTANCE
├── task            ├── nomination schema   ├── argument schemas    ├── admission rules
├── scope           ├── permitted verbs     ├── canonical-state scope└── receipt contract
        │
        ▼   MODEL  ──(MUST EMIT VALID NOMINATION)──▶  GATE ─(validate│authorize│affect)─▶  CANONICAL STATE
```

Declared in **YAML** — which moves the boundary out of code and makes it inspectable/configurable.
Same runtime machinery hosts different tasks by swapping the declaration (a `security_assessment` with
`RUN_SCAN`/`STORE_EVIDENCE`/`CREATE_FINDING` today; a `maintain_inventory` with `CREATE_ASSET`/`UPDATE_ASSET`/
`RETIRE_ASSET` tomorrow) — **change the boundary without changing the agent.**

> **Crucial:** YAML *defines* the boundary; it does not *become* it. The runtime **compiles** the
> declaration into deterministic machinery (`YAML → schema-validate → boundary-compile → runtime`),
> otherwise you've just moved the trust problem into a config file. The compiler is then the new trust
> root — it should emit an **attestation** that the instance enforces exactly the declared rules/scope, as
> the first receipt in the chain.

The model only ever needs to know: *here is the task; here is the nomination language; emit one valid
nomination.* Everything else it says is rationale. **The labor moves to verb-vocabulary design per task**
(expressive enough to finish, narrow enough to bound) — now inspectable in YAML instead of buried in scaffolding.

## The recursive property (bounded generality)

A runtime can **nominate the creation of a new boundary without gaining authority to redefine its own.**
Boundary-creation is itself a scoped, declared verb (e.g. `INSTANTIATE_BOUNDARY`, args = a boundary spec
from an allowlist/templates) that passes through its *own* gate. So:

- The recursion **terminates** — a runtime can only spawn the boundaries its declaration permits; no
  "redefine self" verb exists.
- Child state scope is **carved from the parent** — authority delegates *down*, never up or sideways →
  safe composition and concurrency (disjoint scopes, one gate each, no cross-runtime shadowstate).
- It's the safe pressure-release for a too-narrow verb set: the model **nominates a broader boundary**
  (a governed request Warden admits and instantiates) rather than jailbreaking the current one.

**Declarative boundary selection, not autonomous boundary creation** — preserves the one-degree separation
while letting the runtime become more general without becoming an unbounded blob of agent permissions.

---

## Relationship to the empirical work

warden's v0 (`warden.py`) is a first-draft, single-instance sketch of this kernel — one gate at the
`report_finding` boundary, deny-default, an evidence-gated `what`, `cannot_verify` as a first-class terminal.
In live runs on a deliberately buggy engine it **validated the shape**: across three models that fabricated
~83% of the time in the raw benchmark, warden's gate either *rejected the fabrication outright* (see
`evidence/warden_yi.log`) or the model *abstained honestly*. Governance couldn't make a small model
competent, but it converted the failure mode from **confident-wrong to honest-uncertain**. See
`SESSION_SUMMARY.md` for the full three-layer study and `~/Projects/experiments/benchmarks/` for the
Layer-1 data.

### Known gaps between v0 and the kernel
- v0 **extracts** a nomination (parses JSON) instead of requiring a greppable schema → it broke on a model
  that emitted example JSON. **Fix:** a required nomination grammar + deny-on-non-match.
- v0's `run` (shell) side-steps the gate with a denylist. **Fix:** every side-effect is a verb through
  `affect`; only pure reads bypass (observers can't shadowstate).
- v0 has no YAML boundary, no verb-authorization, no attested compilation, no recursive `INSTANTIATE_BOUNDARY`.
- The gate verifies evidence *existence*, not claim *correctness*. **Next frontier:** a "prove-it-by-running-it"
  `what` whose validation is a repro the harness executes.
