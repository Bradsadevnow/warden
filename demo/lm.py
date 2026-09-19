"""LM Studio. Sampling params are arguments, not buried defaults."""
import json, urllib.request
ENDPOINT = "http://10.77.0.1:1234/v1/chat/completions"

def complete(system, user, model="google/gemma-4-e4b", max_tokens=1024, **params):
    body = {"model": model, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}], **params}
    req = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.load(r)
    return d["choices"][0]["message"].get("content") or ""
