"""evaluate.py

Compares results.json (what the agent said) with answer_key.json (what a human
analyst would say). The agent never sees the answer key.

Run it after triage_agent.py:   python evaluate.py
"""
import json

results = {r["id"]: r for r in json.load(open("results.json"))}
key = json.load(open("answer_key.json"))

correct = 0
unsafe = []
for alert_id, acceptable in key.items():
    got = results.get(alert_id, {}).get("verdict", "missing")
    ok = got in acceptable
    correct += ok
    if got == "false_positive" and "false_positive" not in acceptable:
        unsafe.append(alert_id)
    print(f"{alert_id}: agent said {got:15} | acceptable {acceptable} | {'OK' if ok else 'WRONG'}")

print(f"\nAccuracy: {correct}/{len(key)}")
if unsafe:
    print(f"UNSAFE misses (real threat called a false positive): {unsafe}")
else:
    print("No unsafe misses (no real threat was waved through).")
