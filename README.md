# warden

A deny-by-default governance gate for LLM agents, and a live demo you can attack.

The claim is not that the agent is safe. It is that **what it can and cannot cause
is declared, enforced, and receipted** — and that the limits of that enforcement
are demonstrable rather than asserted.

## Layout

    ARCHITECTURE.md   the kernel design: nomination, admission, receipt, task boundary
    warden.py         v0 agent harness (2026-09-15), Ollama-native
    evidence/         preserved run logs from the original execution-integrity study
    demo/             the current reference implementation + live demo

## demo/

    boundary.yaml     the task boundary. Declares the entire action space,
                      argument bounds, preconditions, and state invariants.
                      Nothing in the kernel knows what an "order" is.
    kernel.py         the gate. One door, deny by default. Ordered pipeline:
                      schema -> what -> verb-auth -> args -> precondition ->
                      invariant -> decision -> execute. Effects apply to a copy
                      and commit only if every invariant holds.
    tools.py          the verbs. The only code that touches canonical state.
    agent.py          the chatbot. Its prompt is COMPILED FROM boundary.yaml,
                      so what it is told it can do cannot drift from what is enforced.
    invariants.py     an INDEPENDENT audit. Re-derives the rules from boundary.yaml
                      without calling kernel code, because a gate that grades itself
                      is worthless.
    server.py         live demo server (stdlib only)
    ui.html           the demo page

## Proofs

    python3 check.py          every pipeline stage refusing, deterministically
    python3 gap.py            the cumulative-limit case, by construction
    python3 adversarial.py <model> <n>   n reps of the attack suite + audit

`check.py` and `gap.py` need no model. `adversarial.py` calls LM Studio.

## Run the demo

    python3 server.py     # http://127.0.0.1:8077

Needs LM Studio serving an OpenAI-compatible endpoint at `http://10.77.0.1:1234`
(set in `demo/lm.py`). Nothing on the page is pre-recorded.

## Known limits, deliberately unfixed

- **A precondition is an incentive.** `send_message` requires an `issue_refund`
  immediately prior. The model issues a token refund purely to unlock the verb,
  and says so. Transcript: `demo/evidence/one_cent_key.json`.
- **No time dimension.** Velocity and rate limits are not expressible.
- **No entitlements.** `what` is matched against a scope pattern, not against a
  relationship, so object-level authorization is not checked.
- **Content semantics.** Solved for outbound by removing free text rather than by
  inspecting it. That does not generalise to a verb that needs prose.

`demo/evidence/gap_before_invariants.py` is the preserved version of a proof that
used to fail. Do not edit it — it is the baseline the fix is measured against.
