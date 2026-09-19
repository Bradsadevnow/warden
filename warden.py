#!/usr/bin/env python3
"""
warden — a lean, governed agent harness for small local models (Ollama).

Design center (opposite of maximalist harnesses like Goose/openclaw):
  - minimal tool surface (a small model can't drown in it)
  - every tool result is BUDGETED to fit context (no context suicide)
  - findings are EVIDENCE-GATED: the harness verifies the cited snippet
    actually exists at the cited file:line before accepting a finding.
    Fabricated bugs are rejected structurally, not just graded later.
  - "cannot_verify" is a first-class, honored terminal state (evidence discipline).
  - dead-simple text tool-call protocol: model emits ONE json object per turn,
    so text-emitting coder models (qwen) work without Ollama's structured tools.

Not a product. A measurement-grade reference harness for the execution-integrity work.
"""
from __future__ import annotations
import json, re, os, subprocess, sys, time, argparse, pathlib

# ── config / governance knobs ────────────────────────────────────────────────
MAX_TOOL_OUTPUT_CHARS = 4000      # every tool result truncated to this (~1k tokens)
MAX_READ_LINES        = 200       # read_file must range-limit beyond this
MAX_GREP_MATCHES      = 40
DEFAULT_MAX_TURNS     = 25
# exec policy: deny obviously destructive / networked-mutating commands by default
DENY_PATTERNS = [r"\brm\s+-rf?\b", r"\bmkfs\b", r"\bdd\s+if=", r":\(\)\{", r"\bshutdown\b",
                 r"\breboot\b", r"\bgit\s+push\b", r"\bcurl\b.*\|\s*(ba)?sh", r"\bchmod\s+-R\s+777"]

SYSTEM = """You are a code investigator operating inside a governed harness.
You work ONE step at a time. Each turn you output EXACTLY ONE JSON object and nothing else:

  {"tool": "<name>", "args": { ... }}

Tools:
  list_dir   {"path": "."}                         -> entries in a directory
  read_file  {"path": "f.py", "start": 1, "end": 120}  -> file lines [start,end] (ranges required for big files)
  grep       {"pattern": "regex", "path": "."}     -> matching file:line lines
  run        {"cmd": "python -c '...'"}            -> run a shell command (non-destructive only)
  report_finding {"file":"f.py","line":42,"evidence":"<exact source line copied verbatim>","claim":"why it's a bug"}
                 -> records a bug. The harness VERIFIES your evidence appears at that file:line.
                    If it does not, the finding is REJECTED and you must look again. Do not guess.
  cannot_verify  {"reason":"..."}                  -> declare you cannot establish a finding from the evidence. This is a VALID, correct outcome.
  done       {"summary":"..."}                     -> finish.

Rules:
  - Investigate with read_file/grep/run before claiming anything.
  - A finding is only real if you can copy the exact offending source line as evidence. No evidence, no finding.
  - If you cannot verify a suspected bug, use cannot_verify. Abstaining honestly is correct; fabricating is failure.
  - Output ONLY the single JSON object. No prose around it."""

# ── ollama client ─────────────────────────────────────────────────────────────
def chat(host, model, messages, num_ctx):
    import urllib.request
    body = json.dumps({"model": model, "messages": messages, "stream": False,
                       "options": {"num_ctx": num_ctx, "num_predict": -1, "temperature": 0.2}}).encode()
    req = urllib.request.Request(f"{host}/api/chat", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as r:
        m = json.loads(r.read()).get("message", {})
        c = (m.get("content") or "").strip()
        return c if c else (m.get("thinking") or "")   # reasoning models (gpt-oss) emit to thinking channel

# ── parse ONE tool call from model text (structured-free; handles fences/prose) ─
def parse_tool_call(text):
    # try fenced ```json first, then the last balanced {...} containing "tool"
    for m in re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S):
        try:
            o = json.loads(m)
            if "tool" in o: return o
        except Exception: pass
    # last-resort: scan for balanced braces
    depth, start = 0, None
    cands = []
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0: start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                cands.append(text[start:i+1])
    for c in cands:   # FIRST valid tool call = the model's actual action (later ones are examples/hallucinations)
        try:
            o = json.loads(c)
            if "tool" in o: return o
        except Exception: pass
    return None

def budget(s, limit=MAX_TOOL_OUTPUT_CHARS):
    s = s if isinstance(s, str) else str(s)
    return s if len(s) <= limit else s[:limit] + f"\n…[truncated {len(s)-limit} chars — narrow your request]"

# ── tools (governed) ──────────────────────────────────────────────────────────
class Tools:
    def __init__(self, root, max_output=MAX_TOOL_OUTPUT_CHARS, max_read=MAX_READ_LINES):
        self.root = pathlib.Path(root).resolve(); self.max_output = max_output; self.max_read = max_read
    def _p(self, path):
        p = (self.root / path).resolve()
        if not str(p).startswith(str(self.root)): raise ValueError("path escapes root")
        return p
    def list_dir(self, path="."):
        p = self._p(path)
        return budget("\n".join(sorted(e.name + ("/" if e.is_dir() else "") for e in p.iterdir())), self.max_output)
    def read_file(self, path, start=None, end=None):
        p = self._p(path); lines = p.read_text(errors="replace").splitlines()
        n = len(lines)
        if start is None and n > self.max_read:
            return f"[{path} has {n} lines — too big to read whole. Re-call with start/end (<= {self.max_read} lines).]"
        s = max(1, int(start or 1)); e = min(n, int(end or min(n, s+self.max_read-1)))
        if e - s + 1 > self.max_read: e = s + self.max_read - 1
        return budget("\n".join(f"{i}: {lines[i-1]}" for i in range(s, e+1)), self.max_output)
    def grep(self, pattern, path="."):
        rx = re.compile(pattern); out = []; base = self._p(path)
        files = [base] if base.is_file() else [f for f in base.rglob("*.py")]
        for f in files:
            try:
                for i, ln in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if rx.search(ln):
                        out.append(f"{f.relative_to(self.root)}:{i}: {ln.strip()[:160]}")
                        if len(out) >= MAX_GREP_MATCHES: return budget("\n".join(out) + "\n…[match cap hit]", self.max_output)
            except Exception: pass
        return budget("\n".join(out) or "[no matches]", self.max_output)
    def run(self, cmd):
        for pat in DENY_PATTERNS:
            if re.search(pat, cmd): return f"[DENIED by exec policy: matches /{pat}/]"
        try:
            r = subprocess.run(cmd, shell=True, cwd=self.root, capture_output=True, text=True, timeout=60)
            return budget((r.stdout or "") + (("\n[stderr]\n"+r.stderr) if r.stderr else "") + f"\n[exit {r.returncode}]", self.max_output)
        except subprocess.TimeoutExpired: return "[command timed out at 60s]"
    # evidence-gated finding: verify the quoted evidence actually exists at file:line
    def verify_evidence(self, file, line, evidence):
        try:
            lines = self._p(file).read_text(errors="replace").splitlines()
        except Exception as e:
            return False, f"cannot open {file}: {e}"
        line = int(line)
        window = lines[max(0, line-3):line+2]  # +/- 2 lines of slack
        ev = re.sub(r"\s+", "", evidence)
        for w in window:
            if ev and ev in re.sub(r"\s+", "", w):
                return True, "evidence confirmed at cited location"
        return False, f"evidence NOT found at {file}:{line} (±2). Cited: {evidence!r}"

# ── agent loop ────────────────────────────────────────────────────────────────
def run_agent(root, task, host, model, num_ctx, max_turns, log, max_output=MAX_TOOL_OUTPUT_CHARS, max_read=MAX_READ_LINES):
    T = Tools(root, max_output, max_read)
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": task}]
    findings, transcript = [], []
    def L(*a): print(*a); log.write(" ".join(str(x) for x in a) + "\n"); log.flush()
    for turn in range(1, max_turns+1):
        try: reply = chat(host, model, msgs, num_ctx)
        except Exception as e: L(f"[turn {turn}] LLM error: {e}"); break
        call = parse_tool_call(reply)
        L(f"\n=== turn {turn} ===\nMODEL: {reply[:500]}")
        if not call:
            msgs.append({"role":"assistant","content":reply})
            msgs.append({"role":"user","content":"Output exactly one JSON tool call and nothing else."})
            continue
        tool, args = call.get("tool"), call.get("args", {}) or {}
        transcript.append(call)
        if tool == "done":
            L(f"DONE: {args.get('summary','')}"); break
        if tool == "cannot_verify":
            L(f"CANNOT_VERIFY (correct/abstain): {args.get('reason','')}"); findings.append({"type":"abstain","reason":args.get('reason','')}); break
        if tool == "report_finding":
            ok, why = T.verify_evidence(args.get("file",""), args.get("line",0), args.get("evidence",""))
            if ok:
                findings.append({"type":"finding", **args}); result = f"FINDING ACCEPTED (evidence verified): {args.get('claim','')}"
            else:
                result = f"FINDING REJECTED — {why}. Do not report it unless you can cite the exact source line."
            L(f"  report_finding -> {result}")
        elif hasattr(T, tool):
            try: result = getattr(T, tool)(**args)
            except Exception as e: result = f"[tool error: {e}]"
            L(f"  {tool}({args}) -> {result[:300]}")
        else:
            result = f"[unknown tool: {tool}]"
            L(f"  {result}")
        msgs.append({"role":"assistant","content":reply})
        msgs.append({"role":"user","content":f"[{tool} result]\n{result}"})
    accepted = [f for f in findings if f.get("type")=="finding"]
    L(f"\n===== RESULT: {len(accepted)} evidence-verified finding(s), turns used {turn} =====")
    for f in accepted: L(f"  - {f.get('file')}:{f.get('line')} — {f.get('claim')}")
    return findings

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--task", required=True)
    ap.add_argument("--model", default="qwen2.5-coder:14b"); ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=16384); ap.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    ap.add_argument("--max-output-chars", type=int, default=MAX_TOOL_OUTPUT_CHARS)
    ap.add_argument("--max-read-lines", type=int, default=MAX_READ_LINES)
    ap.add_argument("--log", default="/tmp/warden_run.log")
    a = ap.parse_args()
    with open(a.log, "w") as log:
        run_agent(a.root, a.task, a.host, a.model, a.num_ctx, a.max_turns, log, a.max_output_chars, a.max_read_lines)
