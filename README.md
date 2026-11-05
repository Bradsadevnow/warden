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
    server.py         live demo server, plus the approval endpoints
    ui.html           the demo page
    approve.html      the approval device: holds a non-extractable Ed25519 key in the
                      browser, shows the exact bytes to sign, signs on a held press
    testsigner.py     a stand-in for that device, for tests and scripts

## Proofs

    python3 check.py          every pipeline stage refusing, deterministically
    python3 gap.py            the cumulative-limit case, by construction
    python3 test_hardening.py   regressions for every hole that was found and closed
    python3 test_policy.py      identity, inheritance, precedence, holds, compile-time refusal
    python3 test_authz.py       the signature tier: replay, expiry, wrong action, forged key
    python3 adversarial.py <model> <n>   n reps of the attack suite + audit

`check.py` and `gap.py` need no model. `adversarial.py` calls LM Studio.

## Install

    pip install -r demo/requirements.txt

## Identity, policy and HOLD

`boundary.yaml` declares `groups` (which inherit through `includes`), `principals` (each an
agent or a human) and a `policy` of allow / hold / deny rules. The boundary stays the outer
ceiling: policy can narrow it per actor but never permit a verb the boundary does not. Deny
beats everything, no matching allow is a deny, and the gate compiles all of it to flat sets.
The acting principal is set by the runtime that authenticated the session. The model has no
way to name it.

A **hold** rule says: this action is allowed, but only with a human. The nomination is not
executed and not denied; it is held with a challenge. A human in the rule's approver set
signs the exact action (principal, target, verb, args, nonce, expiry, and a hash of the whole
declaration, policy included) on a device the agent cannot reach. An acting principal can
never approve its own action. Soft limits hold; hard limits (the invariants) deny. The gate holds only the PUBLIC key; the signature arrives out of band
through `/approve`, never inside model output, and the same nomination then goes back
through every other check. The audit re-verifies each signature from the receipts alone.

    python3 server.py     # then open http://127.0.0.1:8077/approve and enroll the device

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
