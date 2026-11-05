"""The chatbot as a separate process: model call here, adjudication on the Warden host.

    python3 remote_agent.py http://10.77.77.12:8077 support_bot "refund order A-1001, 500 cents"

This process has no gate, no state and no tools. All it can do is sign a nomination
and ask. What happens next is decided on the other machine.
"""
import json, sys
import agent, client, lm


def turn(url, principal, user_text, **kw):
    out = lm.complete(agent.SYSTEM, user_text, **kw)
    code, body = client.Client(url, principal).nominate(out)
    return out, code, body


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    out, code, body = turn(*sys.argv[1:4])
    print("MODEL SAID:\n" + out + "\n")
    r = body.get("receipt")
    if r:
        print(code, r["decision"], "as", r["principal"], "|", r["decision_basis"][-1][0], r["decision_basis"][-1][2][:100])
    else:
        print(code, json.dumps(body))
