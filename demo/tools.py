"""The tiny toolset. Four verbs, and only the gate may call them.

Each is a plain function over canonical state. None of them validates anything
-- validation already happened at the gate, and duplicating it here would put a
second decision point in the system. One door means one door.
"""

def seed():
    return {"orders": {
        "A-1001": {"customer": "dana",  "total_cents": 4200, "status": "shipped",
                   "notes": [], "refunded_cents": 0},
        "A-1002": {"customer": "mateo", "total_cents": 19900, "status": "processing",
                   "notes": [], "refunded_cents": 0}},
            "outbox": []}

def _order(state, what):
    return state["orders"][what.split("/", 1)[1]]

def lookup_order(state, what, args):
    o = _order(state, what)
    return {"order_id": args["order_id"], "status": o["status"],
            "total_cents": o["total_cents"], "notes": len(o["notes"])}

def add_note(state, what, args):
    _order(state, what)["notes"].append(args["text"])
    return {"noted": args["text"]}

def issue_refund(state, what, args):
    o = _order(state, what)
    o["refunded_cents"] += args["amount_cents"]
    return {"refunded_cents": args["amount_cents"], "total_refunded": o["refunded_cents"]}

# The runtime owns the words. Each template is a function of canonical state,
# so the sentence cannot disagree with the ledger -- there is no path by which
# a number reaches the customer without coming from state.
TEMPLATES = {
    "refund_processed": lambda o, oid: (
        f"We have refunded ${o['refunded_cents']/100:,.2f} on order {oid}. "
        f"The order status is {o['status']}."),
    "order_status": lambda o, oid: (
        f"Order {oid}: status {o['status']}, order total ${o['total_cents']/100:,.2f}, "
        f"refunded to date ${o['refunded_cents']/100:,.2f}."),
}


def render(state, order_id, template):
    return TEMPLATES[template](state["orders"][order_id], order_id)


def send_message(state, what, args):
    oid = args["order_id"]
    text = render(state, oid, args["template"])
    state["outbox"].append({"to_order": oid, "template": args["template"], "text": text})
    return {"sent_to": oid, "template": args["template"], "text": text}

def cancel_order(state, what, args):          # never reachable: permitted=false
    _order(state, what)["status"] = "cancelled"
    return {"cancelled": args["order_id"]}

REGISTRY = {"lookup_order": lookup_order, "add_note": add_note,
            "issue_refund": issue_refund, "send_message": send_message,
            "cancel_order": cancel_order}
