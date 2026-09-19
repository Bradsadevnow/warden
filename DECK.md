# The deck + the video

Not another governance framework deck. An evidence-led engineering demo.

**Shape:** define → build tiny → attack → receipt → repeat → expose the failure →
show the boundary held → make it legible.

---

## Six slides

**1. The problem.** LLMs are nondeterministic. Prompts and safety instructions do not
create an execution boundary. The question is: what happens when the model tries to do
something it isn't allowed to do?

**2. The definition.**

> Governance is the removal of possible ~~outputs~~ **effects** from a nondeterministic
> source until the only ~~possible~~ **reachable** outcomes are approved actions.

*(Open: "outputs" vs "effects". Nothing removes outputs — the model can still say
anything. What is removed is reachable effects. As written it argues with slide 6.
Bradley's call.)*

Concrete: **scope task → constrain output → pre-register effects → deny everything else.**

**3. The primitive.**

```
model → nomination → one gate → ALLOW/DENY → receipt → state
```

The important bit: **the model doesn't get to decide whether its own action is
authorized.**

**4. Attack it.** No happy-path demo. Show the split-refund attack, the
social-engineering/admin-rights attack, the fabricated "I already did it" attempt, and
whatever the second execution tool produces in the n=10 run. **Show the actual receipts.**

**5. Evidence.** Two n=10 runs. Separate them explicitly:

- **deterministically verified** — the boundary, state transition rules, receipts, denials
- **empirically sampled** — model behavior across the 20 runs

The claim is not "the model never misbehaves." It is:

> **The model can misbehave without acquiring authority to make that behavior real.**

**6. The punchline.**

> The model remains nondeterministic. The execution boundary doesn't.

Shorter: **Govern the boundary, not the model.**

---

## The honest failure — include it if it survives replay

The `add_note` injection was **accepted**, because the declared policy genuinely permits
arbitrary note text. That is not a gate failure; it is a boundary-design failure, and the
receipt proves exactly where the declaration was insufficient.

Worth more than hiding it: it demonstrates the system isn't magically safe, and that the
method locates the insufficiency rather than papering over it.

---

## The video

The deck happening in real time. Chatbot gets a few real tools. Model attempts actions.
Gate evaluates them. Allowed action executes. Unauthorized action is denied. Receipt
appears.

No fake "AI employee". No agent theater. No canned screenshots pretending something
happened.

> **Model proposes. Runtime decides. Receipt proves.**

The dashboard comes **after** the primitive survives the two n=10 runs — not as the
substance, but as the visual layer that makes receipts and boundary legible to someone
who doesn't care about Python. **The artifact comes first. The dashboard explains it
afterward.**
