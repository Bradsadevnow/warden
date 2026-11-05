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

## What Warden is, as a product

A CRM-style system for governing agents. The main object is the **agent**: it has a job, a domain, an **owner** (the person responsible for it), and a plain-language list of what it may do. Held actions go to the owner, who approves with a key on their own device after logging in through an identity service. One console covers every domain. Every message on screen must make sense to a non-technical person (Karen from HR, Darrel from accounting).

Decisions made with the owner of this project: one approver per hold (the agent's owner; no two-person rule); an owner may approve their own agent's held action; tools stay inside the Warden service (agents run on other machines and cannot reach them); domains, not roles, decide how agents are divided.

## Plan

DONE
- Gate, policy, HOLD, human signatures (Ed25519), independent audit and replay
- Warden as a network service; signed agent nominations; replay/stale/impersonation refused (`agentauth.py`, `client.py`, `test_network.py`)
- Dashboard rebuilt around agents: agent list, agent page with generated plain-language permissions, "waiting for you" inbox, activity

NEXT, in order
1. **Owner is the approver.** A hold rule can name "the agent's owner"; the compiler resolves it per agent.
2. **Approver identity, no trust-on-first-use.** Login through an OIDC/OAuth provider (token signature, issuer, audience, expiry, verified email, mapped to the owner; reject `none`/HS256). Enrollment of the device key happens only after a successful login. Approval = login (who) + device key (which device) + signature over the exact action. Tested against a stand-in identity provider; a real provider (Google, GitHub or Microsoft) is plugged in later.
3. **Door log.** Requests refused before the gate (unsigned, forged, replayed, unknown agent) are recorded and shown on the dashboard.
4. **Domains.** Each domain is a rulebook + tool module + seed data hosted by the one service, with its own agent and owner. Order: Accounting, IT, then Clinic.
5. **Record-level rule** ("only its own assigned patients"), then Clinic.
6. **Dashboard**: domain filter; approvals merged into the console.
7. **Attack tests**, run from this PC against the laptop: out-of-privilege requests, prompt injection naming another agent, replayed requests, borrowed keys, splitting a large refund into small ones, racing requests, self-approval, enrollment hijack, stolen or wrong-person login tokens, tokens for another app.
8. **Windows laptop** (SSH to it is still not working) as a second agent host for clone/impersonation tests.

LATER
- Turn-an-agent-off (revoke its key) button
- Signed, hash-chained receipts
- Signed capability grants that can only narrow
- Pixel 10 Pro native approval app with key attestation
- A separate protected resource that only honors Warden-signed calls, if Warden should protect external systems

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
