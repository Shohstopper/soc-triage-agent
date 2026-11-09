"""threat_intel.py

Looks up IP addresses and domains on VirusTotal and AbuseIPDB.
This is the "eyes" of the triage agent. The AI part comes later.

Try it:
    python threat_intel.py 194.26.135.119 623start.site 8.8.8.8
"""
import ipaddress
import os
import sys
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()  # reads the keys from the .env file

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

TIMEOUT = 20      # give up on a lookup after 20 seconds
VT_MIN_GAP = 16   # VirusTotal free plan allows 4 lookups per minute
_last_vt_call = 0.0


def _problem(response):
    """Turn a bad HTTP status code into a short message. None means all good."""
    code = response.status_code
    if code in (401, 403):
        return f"API key rejected ({code}). Check your .env file"
    if code == 404:
        return "not found (404)"
    if code == 429:
        return "rate limit hit (429). Wait a minute and try again"
    if code >= 400:
        return f"server error ({code})"
    return None


def _vt_get(path):
    """Ask VirusTotal for something, but never faster than the free limit."""
    global _last_vt_call
    if not VT_KEY:
        return {"error": "VT_API_KEY is missing in .env"}
    wait = VT_MIN_GAP - (time.time() - _last_vt_call)
    if wait > 0:
        time.sleep(wait)
    _last_vt_call = time.time()
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/" + path,
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return {"error": f"network problem: {e}"}
    bad = _problem(r)
    if bad:
        return {"error": bad}
    return r.json()


def check_ip_virustotal(ip):
    data = _vt_get(f"ip_addresses/{ip}")
    if "error" in data:
        return data
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total_engines": sum(stats.values()),
        "owner": a.get("as_owner"),
        "country": a.get("country"),
        "reputation": a.get("reputation"),
    }


def check_domain_virustotal(domain):
    data = _vt_get(f"domains/{domain}")
    if "error" in data:
        return data
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    created = a.get("creation_date")
    age_days = None
    if created:
        made = datetime.fromtimestamp(created, tz=timezone.utc)
        age_days = (datetime.now(timezone.utc) - made).days
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total_engines": sum(stats.values()),
        "registrar": a.get("registrar"),
        "age_days": age_days,
        "reputation": a.get("reputation"),
        "tags": a.get("tags", []),
    }


def check_ip_abuseipdb(ip):
    if not ABUSE_KEY:
        return {"error": "ABUSEIPDB_API_KEY is missing in .env"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return {"error": f"network problem: {e}"}
    bad = _problem(r)
    if bad:
        return {"error": bad}
    d = r.json()["data"]
    return {
        "abuse_score": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
    }


def lookup(indicator):
    """Work out if it is an IP or a domain, then check it in the right places."""
    indicator = indicator.strip().replace("[.]", ".")  # handles defanged text
    try:
        ip = ipaddress.ip_address(indicator)
    except ValueError:
        ip = None

    if ip is not None:
        if not ip.is_global:
            # Private addresses mean nothing to the outside world, and we should
            # not send our internal network details to a website.
            return {"indicator": indicator, "type": "ip",
                    "note": "private or reserved address, not sent to outside services"}
        return {
            "indicator": indicator,
            "type": "ip",
            "virustotal": check_ip_virustotal(indicator),
            "abuseipdb": check_ip_abuseipdb(indicator),
        }
    return {
        "indicator": indicator,
        "type": "domain",
        "virustotal": check_domain_virustotal(indicator.lower()),
    }


def show(result):
    """Print one result in a way a person can read quickly."""
    print(f"\n=== {result['indicator']} ({result['type']}) ===")
    if "note" in result:
        print("  " + result["note"])
        return
    vt = result.get("virustotal", {})
    if "error" in vt:
        print("  VirusTotal: " + vt["error"])
    else:
        line = f"  VirusTotal: {vt['malicious']}/{vt['total_engines']} malicious, {vt['suspicious']} suspicious"
        if result["type"] == "domain":
            line += f" | age {vt['age_days']} days | tags {vt['tags']}"
        else:
            line += f" | owner {vt['owner']} | country {vt['country']}"
        print(line)
    ab = result.get("abuseipdb")
    if ab is not None:
        if "error" in ab:
            print("  AbuseIPDB: " + ab["error"])
        else:
            print(f"  AbuseIPDB: score {ab['abuse_score']}/100, {ab['reports']} reports"
                  f" | {ab['isp']} | {ab['usage_type']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python threat_intel.py <ip or domain> [more ...]")
        sys.exit(1)
    for item in sys.argv[1:]:
        show(lookup(item))
