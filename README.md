# SOC Triage Agent

A small Python agent that triages security alerts the way a Tier 1 SOC analyst would. It checks the indicators in an alert (IPs and domains) against VirusTotal and AbuseIPDB, asks an AI model for a verdict, and then **waits for a human to approve or reject** the suggested action.

I built this as part of my SOC analyst internship prep. It follows on from my [Wazuh detection lab](https://github.com/Shohstopper/wazuh-detection-lab) and my [malware traffic investigations](https://github.com/Shohstopper/malware-traffic-investigations), and the alerts are based on the rules and IOCs from those two projects.

## How it works

```
alert  ->  threat_intel.py  ->  AI model  ->  verdict  ->  human approves / rejects  ->  decisions.jsonl
          (VirusTotal,         (JSON only,   (false_positive,
           AbuseIPDB)           checked by    true_positive,
                                Pydantic)     escalate)
```

1. **Enrich.** `threat_intel.py` looks up each IP or domain. Private IPs are never sent to outside services. Defanged input like `evil[.]com` is cleaned up. VirusTotal's free limit is 4 lookups a minute, so the code waits 16 seconds between calls.
2. **Decide.** The model gets the alert and the lookup results and must answer in a fixed JSON shape (verdict, confidence, reasoning, recommended action). Pydantic checks the answer.
3. **Fail towards a human.** If the model errors, times out or returns something invalid, the alert is marked `escalate`. It is never marked safe by accident.
4. **Human approval.** With `--approve`, I press `y`, `n` or `e` for each alert and can add a note. Everything is saved with a timestamp in `decisions.jsonl`. Approved actions are only **simulated** (printed), nothing touches a real firewall.

## Setup

```
python -m venv venv
venv\Scripts\activate          (Windows)
pip install -r requirements.txt
copy .env.example .env         (then fill in your keys)
```

Keys needed: VirusTotal (free), AbuseIPDB (free), and an AI key. I use Groq's free plan with `openai/gpt-oss-120b`. The AI part talks to any OpenAI-compatible API, so switching provider only means changing `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY` in `.env`.

## Usage

```
python triage_agent.py --check                 test the AI key and model
python triage_agent.py A-005                   triage one alert
python triage_agent.py                         triage all alerts, saves results.json
python triage_agent.py --approve A-001 A-005   human approves or rejects each one
python evaluate.py                             compare results.json with answer_key.json
python triage_agent.py --hardened              same agent with the prompt injection defences on
python attack_test.py --label before           run the 14 prompt injection attacks (see PROMPT_INJECTION.md)
```

## Results

I wrote 8 test alerts (`alerts.json`) and an answer key (`answer_key.json`) that the agent never sees. 4 are clearly malicious, 2 are false positives that look scary (Google DNS, a Veeam backup task), and 2 are judgement calls where `true_positive` or `escalate` are both acceptable.

| Alert | What it is | Agent said | Expected |
|---|---|---|---|
| A-001 | certutil download | true_positive | true_positive |
| A-002 | HTTP to bare IP, old browser UA | true_positive | true_positive |
| A-003 | new domains never seen before | true_positive | true_positive |
| A-004 | 48 second TLS beacon | true_positive | true_positive |
| A-005 | workstation using 8.8.8.8 | false_positive | false_positive |
| A-006 | Veeam scheduled task | false_positive | false_positive |
| A-007 | 36 MB from nodejs.org after A-003 | true_positive | true_positive or escalate |
| A-008 | 12 failed RDP then success | true_positive | true_positive or escalate |

**8/8, no real threat was marked as a false positive.** I would not read that as "the agent is 100% accurate". It is 8 alerts that I wrote myself, so it shows the pipeline works, not how it would do on real traffic.

What I noticed reading the reasoning:
- **A-007:** the verdict was right but the reason was weak. It blamed "unauthorised software" and did not connect the download to the earlier new-domain alert, which is the real red flag.
- **A-008:** it said true_positive with high confidence. An internal admin machine could be a legit jump host, so escalate would be the safer call. A bit overconfident.

## Limitations

- The alerts are **synthetic**. They are based on my own Wazuh rules and the IOCs from my malware reports, not on a live network.
- It only looks at IPs and domains. It does not read files, hashes or logs.
- VirusTotal scores change over time, and 0 detections does not prove something is safe.
- The default prompt is intentionally basic. It is the "before" version in the prompt injection test. Use `--hardened` for the defended version.

## Prompt injection testing (Project 4)

Alert data can contain text an attacker controls (hostnames, user agents, URLs, usernames). I wrote 14 attack alerts with hidden instructions and ran them against this agent. 6 out of 28 runs (21%) fooled the original version. After hardening, 0 out of 28 did. The full write-up, including what did not work and the limits of the test, is in [PROMPT_INJECTION.md](PROMPT_INJECTION.md).
