"""triage_agent.py  (version 1)

Reads alerts.json, checks each alert's indicators with threat_intel.py, then asks an
AI model for a verdict. It only SUGGESTS. The human approval step comes in the next version.

The AI part is a plain HTTPS request to an "OpenAI-compatible" chat API. Groq, OpenRouter,
Gemini and a local Ollama all speak this same format, so switching provider only means
changing LLM_BASE_URL, LLM_MODEL and LLM_API_KEY in .env. No code changes.

Run it:
    python triage_agent.py --check      test that your AI key and model work
    python triage_agent.py A-005        triage one alert
    python triage_agent.py              triage every alert and save results.json
    python triage_agent.py --approve    same, but YOU approve or reject each suggested action
                                        (works with alert IDs too: --approve A-001 A-002)

Note: the prompt below is simple on purpose. In Project 4 we attack this agent and
then harden it, so we want a plain "before" version to compare against.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import requests
from dotenv import load_dotenv
from pydantic import BaseModel

import threat_intel

load_dotenv()

LLM_BASE_URL = (os.getenv("LLM_BASE_URL") or "https://api.groq.com/openai/v1").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY")
MODEL = os.getenv("LLM_MODEL") or "llama-3.3-70b-versatile"

ALERTS_FILE = Path("alerts.json")
CACHE_FILE = Path("intel_cache.json")
RESULTS_FILE = Path("results.json")
DECISIONS_FILE = Path("decisions.jsonl")


class Verdict(BaseModel):
    """The shape of the answer we force the AI to give. No free-form rambling."""
    verdict: Literal["false_positive", "true_positive", "escalate"]
    confidence: Literal["low", "medium", "high"]
    reasoning: str
    recommended_action: str


SYSTEM_PROMPT = """You are a Tier 1 SOC analyst. You get one security alert and the threat intelligence results for its indicators.

Pick one verdict:
- false_positive: harmless activity that triggered a rule by mistake
- true_positive: real malicious or unauthorised activity
- escalate: you cannot be sure, or it is serious enough that a senior analyst should look

Explain your reasoning in 2 to 4 sentences and mention the specific evidence you used.

Rules of thumb:
- A clean reputation score does not prove something is safe.
- One detection out of 90+ engines on a very popular service is usually noise.
- A brand new domain (under 90 days old) used right before suspicious activity is a strong warning sign.
- If the evidence is weak or mixed, choose escalate.

Recommend one concrete action, for example: isolate the host, block the domain, reset the password, or close the alert. A human will approve it before anything happens.

Reply with JSON only, using exactly these keys:
{"verdict": "false_positive" or "true_positive" or "escalate",
 "confidence": "low" or "medium" or "high",
 "reasoning": "...",
 "recommended_action": "..."}"""


def _has_error(result):
    """True if any lookup inside this result failed (so we do not save a broken result)."""
    return any(isinstance(v, dict) and "error" in v for v in result.values())


def get_intel(indicators):
    """Look up each indicator, saving answers in a file so reruns are fast."""
    cache = json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
    results = []
    for ind in indicators:
        if ind not in cache:
            result = threat_intel.lookup(ind)
            if not _has_error(result):
                cache[ind] = result
                CACHE_FILE.write_text(json.dumps(cache, indent=2))
            results.append(result)
        else:
            results.append(cache[ind])
    return results


def call_llm(system, user, json_mode=True):
    """Send one chat request and return the text of the reply."""
    if not LLM_API_KEY:
        raise RuntimeError("LLM_API_KEY is missing in .env")
    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    for attempt in range(4):
        r = requests.post(
            LLM_BASE_URL + "/chat/completions",
            headers={"Authorization": "Bearer " + LLM_API_KEY},
            json=body,
            timeout=60,
        )
        if r.status_code == 429 and attempt < 3:  # free plans have speed limits, so wait and retry
            wait = float(r.headers.get("retry-after", 20))
            time.sleep(min(wait, 60))
            continue
        if r.status_code != 200:
            raise RuntimeError(f"AI service error {r.status_code}: {r.text[:200]}")
        return r.json()["choices"][0]["message"]["content"]


def ask_model(alert, intel):
    prompt = ("ALERT:\n" + json.dumps(alert, indent=2) +
              "\n\nTHREAT INTEL RESULTS:\n" + json.dumps(intel, indent=2))
    text = call_llm(SYSTEM_PROMPT, prompt)
    start, end = text.find("{"), text.rfind("}")  # in case the model adds extra words around the JSON
    return Verdict.model_validate_json(text[start:end + 1])


def triage(alert, intel):
    """If anything goes wrong, fail towards a human, never towards 'all clear'."""
    try:
        return ask_model(alert, intel)
    except Exception as e:
        return Verdict(
            verdict="escalate",
            confidence="low",
            reasoning=f"The agent could not finish, so a human must review. ({type(e).__name__}: {str(e)[:150]})",
            recommended_action="Review this alert manually.",
        )


def check_llm():
    reply = call_llm("You are a helpful assistant.", "Reply with the single word OK.", json_mode=False)
    print(f"Model {MODEL} replied: {reply.strip()}")


def run(alert):
    print(f"\n[{alert['id']}] {alert['rule']}  (host {alert['host']}, user {alert['user']})")
    intel = get_intel(alert.get("indicators", []))
    for item in intel:
        threat_intel.show(item)
    v = triage(alert, intel)
    print(f"\n  VERDICT: {v.verdict.upper()}  (confidence: {v.confidence})")
    print(f"  Why: {v.reasoning}")
    print(f"  Suggested action: {v.recommended_action}")
    return {"id": alert["id"], **v.model_dump()}


def ask_human(alert, v):
    """Human in the loop. The agent only suggests. Nothing happens until a person says yes."""
    print("\n  Approve this action?")
    print("    y = approve   n = reject   e = escalate to senior   (anything else asks again)")
    while True:
        choice = input("  Your decision [y/n/e]: ").strip().lower()
        if choice in ("y", "n", "e"):
            break
    decision = {"y": "approved", "n": "rejected", "e": "escalated_by_human"}[choice]
    note = input("  Optional note (press Enter to skip): ").strip()
    if decision == "approved":
        # Simulated on purpose. A real version would call the EDR or firewall API here.
        print(f"  SIMULATED ACTION: {v.recommended_action}")
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "alert_id": alert["id"],
        "agent_verdict": v.verdict,
        "agent_confidence": v.confidence,
        "suggested_action": v.recommended_action,
        "human_decision": decision,
        "human_note": note,
    }
    with DECISIONS_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return decision


if __name__ == "__main__":
    if "--check" in sys.argv:
        check_llm()
        sys.exit(0)
    alerts = json.loads(ALERTS_FILE.read_text())
    approve = "--approve" in sys.argv
    wanted = [a for a in sys.argv[1:] if not a.startswith("--")]
    if wanted:
        alerts = [a for a in alerts if a["id"] in wanted]
    results = []
    for a in alerts:
        r = run(a)
        if approve:
            r["human_decision"] = ask_human(a, Verdict(**{k: r[k] for k in Verdict.model_fields}))
        results.append(r)
    if not wanted:
        RESULTS_FILE.write_text(json.dumps(results, indent=2))
        print(f"\nSaved {len(results)} results to {RESULTS_FILE}. Now run: python evaluate.py")
