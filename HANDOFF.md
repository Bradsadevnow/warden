# Warden: handoff for agents joining the lab

Read this first. It is the state of the project and the plan, for any agent (Claude, Codex, other) working on a lab machine.

## What Warden is

A deny-by-default governance kernel for LLM agents. The model never acts. It writes one literal line:

    NOMINATE what=<target> verb=<verb> args=<k:v;k:v>

plus a free-text rationale (recorded verbatim, never parsed). The gate adjudicates it and every attempt produces a receipt, including denials and failed effects.

Commercial direction: a licensable, model-independent authorization kernel. The guarantee holds only for execution paths Warden controls.

## Pipeline (each stage may only refuse: DENY, or HOLD)

schema -> what (scope) -> verb auth -> args -> bind -> policy -> precondition -> hold -> effect on a deep copy -> footprint -> invariant -> commit

- `what` must match the verb's template (`orders/{order_id}`) built from args.
- Effects run on a copy first, then commit. Footprint check: the effect may only write declared paths.
- Invariants fail closed on missing fields. Compile-time errors raise `BoundaryError`.

## Identity, policy, HOLD (all done)

`demo/boundary.yaml` declares groups (with `includes`), principals (`agent` or `human`), and a policy of `allow | hold | deny` rules (`to`, `verbs`, optional `what` globs, optional `when {arg, op, value}`).

- Deny beats everything. No allow means deny. The boundary is the outer ceiling.
- HOLD means the action is allowed only with a human signature from a named approver (never the actor), via the approval device. Holds are conjunctive.
- Human authorization: Ed25519 over `canonical_action(boundary_hash, principal, what, verb, args, nonce, expires)`, header `warden-authz-v2`. Grants are single-use, expire (`AUTHZ_TTL=120`), and are bound to the boundary hash.
- Enrollment is trust-on-first-use (known limit; Android key attestation is the planned fix).
- The acting principal is hardcoded (`support_bot`) until slice C.

## Code map (`demo/`)

- `kernel.py` core gate; `invariants.py` independent audit and replay from `tools.seed()`
- `tools.py` seed data and verbs; `agent.py` prompt compiled from the boundary; `lm.py` LM Studio client (`LM_ENDPOINT`)
- `server.py` demo HTTP server (127.0.0.1:8077); `approve.html` approval device page; `ui.html` main page
- tests: `test_hardening.py`, `test_authz.py`, `test_policy.py` (all pass). Also `check.py`, `gap.py`, `adversarial.py`
- Run from `demo/`. Deps: `pip install -r requirements.txt` (pyyaml, cryptography).

## Roadmap

- B: signed capability grants (narrowing-only delegation, budgets, revocation)
- C: Warden as a network service; agent authentication on nominations (DONE for the service and signed nominations: `agentauth.py`, `client.py`, `remote_agent.py`, `test_network.py`; agent keys are provisioned in `agents.json` on the Warden host, never enrolled over the network; `/reset`, `/enroll`, `/turn` are loopback-only). Still open: a separate protected resource that only honors Warden-signed calls (that is D)
- D: Warden-signed hash-chained receipts (attestation as receipt 0); a resource that only honors Warden-signed calls
- E: approver adapters (Ed25519 device, ES256), Pixel 10 Pro native app with Keystore and key attestation
- F: cross-machine adversarial tests (cloned agent, replay, escalation) and the evidence demo

## Lab (flat 10.77.77.0/24 behind a Linksys E2500)

| Host | Role |
|---|---|
| 10.77.77.10 | main PC: agent runtime + LM Studio |
| 10.77.77.11 | Windows laptop: second/cloned agent host |
| 10.77.77.12 | Linux laptop: Warden service + protected resource |

The resource binds to 127.0.0.1 on .12 so agent hosts can reach only Warden's port. A managed switch for VLAN practice is on its way.

## Working rules

- Prototype. No theatrics. Don't claim what the code doesn't enforce.
- Never write "this is retracted because..." annotations; just don't make the claim.
- Commit and push only when the owner asks. Don't touch another agent's files without coordinating.
- Known limits: precondition is an incentive; no clock for rate limits; no object-level conditions; TOFU enrollment; content semantics are not checked.
