# Session Summary — 2026-09-15

Two things got built today, and they turned out to be one thing.

---

## 1 — The Chelys gapped test rig (built, working, parked on source)

A wiped-and-reimaged Kali laptop (`chelys-rig`, `10.77.0.2` over an isolated Cat6 link), running the full
Chelys stack — the agent swarm, the Safety Oracle, and the React UI with a **live real-time provenance feed**
— grounded on a local model, attacking an isolated OWASP Juice Shop target. Brad watched his product work
for the first time, months into building it.

- Model inference runs on the desktop GPU; the gapped laptop calls it over Cat6 (grounded, no internet on
  the attack box).
- The Safety Oracle fired and scored actions in the live logs (`nuclei`/`sqlmap` → APPROVED with
  safety/detection/blast).
- The in-app UI works: login, jobs, the live Kali sandbox terminal, and the provenance/audit stream (a 403
  on the terminal panel was traced to an unregistered router and fixed).

**Status:** staged for the 12-category trust-validation the moment Alejandro's updated source lands.
**Lives at:** `~/Projects/products/chelys/trust-validation/` (frozen brief, validation matrix, `rig/` runbook +
setup/airgap/bootstrap scripts). Full state in memory: `project_chelys_trust_validation.md`.

---

## 2 — The execution-integrity study → the Warden kernel

It moved in a clean line, and Brad's insistence on keeping the layers separate is what made it legible.

### Layer 1 — Direct model evaluation (controlled prompting)
Extending Brad's own honesty benchmark to coding models. The headline: local models **fabricate ~83% of the
time** when told "there's a bug" in code that's actually correct, and confidently *miss* subtle real bugs.
The failure mode is dishonesty under pressure, not stupidity.
- Forcing "explain your reasoning" is a **double-edged sword**: it *helps* on genuine defects but *amplifies*
  premise-compliance fabrication (the model rationalizes the false premise).
- A ctx-variance sweep returned a clean **null result** — the per-run verdict variation is decoding
  stochasticity, not a context-length effect (proven by holding ctx fixed and reproducing the same spread).
- Real-code cases were built from **actual fixed bugs in the MTG engine** (`~/Projects/products/mtg-core`
  git history). Data: `~/Projects/experiments/benchmarks/` (`cases/magic_real.json`, `results/`).

### Layer 2 — Harness evaluation (Codex / Claude-CLI / Goose driving local models)
Off-the-shelf agent harnesses **can't drive a fitting local model on a 16GB card without patching**, and a
rich harness *amplifies* the failure by drowning small models in meta-tooling.
- **Root cause:** the `tools` capability flag lies — qwen2.5-coder emits tool calls as *text*, not structured;
  mistral-nemo structures them correctly.
- Codex 0.154 hangs on local models (dropped chat API, demands Responses API). Claude-CLI 400s on a `thinking`
  param. **Goose** works only after `GOOSE_TOOLSHIM=true` (parse text tool-calls) **and** `--no-profile
  --with-builtin developer` (strip the 200+ agent-roles that hijack a small model into meta-delegation).
- Evidence: `evidence/goose_l3.log` (drowned in meta-tooling), `evidence/goose_l3b.log` (stripped harness →
  investigated, but `cat`'d a 4,400-line file and blew its 16k context).

### Layer 3 — Real execution under governance (Warden)
Built **warden** (`warden.py`) — a lean, governed, Ollama-native harness: minimal tools, output budgeted to
context, **evidence-gated findings** (the harness verifies the cited source line actually exists, or rejects
the finding), `cannot_verify` as a first-class terminal. Same models that fabricated 83% in Layer 1:
- **yi-coder** tried to report a shell error as a source bug → **the evidence-gate REJECTED it**, and the
  model then abstained honestly. *Governance converting fabrication into honesty, live.* (`evidence/warden_yi.log`)
- **gpt-oss** investigated the real stack bug carefully, never fabricated, ran out of turns. (`evidence/warden_oss2.log`)
- **qwen** read past a real bug, missed it, and abstained rather than fabricate. (`evidence/warden_mtg.log`)

**Result (Brad's hypothesis, confirmed): zero fabricated findings landed across three models.** You can't
harness a small model into *competence* — but you can harness it into *honesty*. Governance flips the failure
mode from confident-wrong to honest-uncertain.

### Then — the architecture
That single result generalized into a real governance kernel: one gate, deny-by-default, `affect` as the sole
writer, greppable nominations (not extracted), verbatim-immutable rationale as receipt, instantiated around a
declared task boundary in *compiled* YAML, with recursive-but-bounded boundary nomination. See
**`ARCHITECTURE.md`**.

---

## The through-line

**The Warden kernel is Chelys, abstracted.** The gate is the oracle; `affect` is authorized execution; the
receipt is the decision receipt; deny-default is fail-closed. The pentest product, the benchmark, and the
runtime aren't three projects — they're three instances of one governance primitive. The bench proved *why*
it's needed (models fabricate); warden proved the *shape* works; the kernel *is* the shape; Chelys is it in
the wild.

## What's open (see HANDOFF.md)
- **warden → kernel:** greppable nomination grammar + deny-on-non-match; YAML boundary → compiled+attested
  machinery; the two-why receipt; the recursive `INSTANTIATE_BOUNDARY` verb.
- **The gate frontier:** "prove-it-by-running-it" — a `what` validated by an executed repro.
- **Chelys:** the 12-category validation, on the rig, when the source arrives.

## Where everything lives
- **This folder** (`~/Projects/products/warden/`): `ARCHITECTURE.md`, `SESSION_SUMMARY.md`, `HANDOFF.md`,
  `warden.py`, `evidence/` (preserved run logs).
- **Memory** (auto-loads each session): `project_warden_governance_kernel.md`, `project_execution_integrity_bench.md`,
  `project_chelys_trust_validation.md`, `project_chelys_pilots.md`.
- **Benchmark data:** `~/Projects/experiments/benchmarks/` · **Chelys:** `~/Projects/products/chelys/trust-validation/`.
