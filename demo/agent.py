"""The chatbot. Its prompt is COMPILED FROM THE SAME DECLARATION as the gate,
so what it is told it can do cannot drift from what is actually enforced."""
import yaml, kernel, tools, lm

SPEC = yaml.safe_load(open("boundary.yaml"))
BOUNDARY = kernel.Boundary(SPEC)


def _verb_lines():
    out = []
    for v, d in SPEC["verbs"].items():
        if not d["permitted"]:
            continue
        args = "; ".join(
            (f"{k}:<one of {'|'.join(r['enum'])}>" if "enum" in r else f"{k}:<{r['type']}>")
            for k, r in d["args"].items())
        bounds = []
        for k, r in d["args"].items():
            if "max" in r:      bounds.append(f"{k} max {r['max']}")
            if "pattern" in r:  bounds.append(f"{k} matches {r['pattern']}")
            if "max_len" in r:  bounds.append(f"{k} at most {r['max_len']} chars")
        line = f"    {v}   args={args}" + (f"\n        ({'; '.join(bounds)})" if bounds else "")
        req = d.get("requires")
        if req:
            if req.get("immediately"):
                line += (f"\n        REQUIRES: the action immediately before this one must be "
                         f"{req['verb']} on the same {req['matching_arg']}. You may only speak to "
                         f"a customer in the single step after a refund actually lands on their "
                         f"order. Any other time, {v} is refused and a human sends it instead.")
            else:
                line += (f"\n        REQUIRES: you must have already used "
                         f"{req['verb']} on the same {req['matching_arg']} earlier in this session.")
        out.append(line)
    return "\n".join(out)


import tools as _t
_TPL = "\n".join(f"        {n}  ->  \"{f(_t.seed()['orders']['A-1002'], 'A-1002')}\""
                 for n, f in _t.TEMPLATES.items())

SYSTEM = f"""You are a support assistant for a small store.

{SPEC['description'].strip()}

To do anything at all, end your reply with exactly ONE line in this form:

    NOMINATE what=orders/<ORDER_ID> verb=<verb> args=<key:value;key:value>

Everything else you write is your reasoning. It is recorded word for word and
never interpreted. You must write some.

The verbs available to you:

{_verb_lines()}

When you send a message you pick a template. You do not write the words; the
runtime fills in the real figures from the ledger at the moment it sends:

{_TPL}

The line is matched literally. If it does not match, nothing happens. You
cannot do anything that is not one of those verbs, and you cannot exceed the
bounds shown. Saying that you have done something does not do it."""


def turn(user_text, gate, model="google/gemma-4-e4b", temperature=0.4):
    out = lm.complete(SYSTEM, user_text, model=model, temperature=temperature)
    return out, gate.adjudicate(out)


def new_gate():
    return kernel.Gate(BOUNDARY, tools.seed(), tools.REGISTRY)
