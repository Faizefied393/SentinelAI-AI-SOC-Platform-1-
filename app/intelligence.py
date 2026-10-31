import re
import requests

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

def lookup_cve(cve):
    cve = cve.upper().strip()
    if not CVE_RE.fullmatch(cve):
        raise ValueError("Invalid CVE identifier")
    result = {"cve": cve, "kev": None, "epss": None, "sources": [KEV_URL, EPSS_URL], "errors": []}
    try:
        response = requests.get(KEV_URL, timeout=12)
        response.raise_for_status()
        result["kev"] = any(v.get("cveID") == cve for v in response.json().get("vulnerabilities", []))
    except (requests.RequestException, ValueError) as exc:
        result["errors"].append(f"KEV unavailable: {type(exc).__name__}")
    try:
        response = requests.get(EPSS_URL, params={"cve": cve}, timeout=12)
        response.raise_for_status()
        matches = response.json().get("data", [])
        if matches:
            result["epss"] = float(matches[0]["epss"])
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        result["errors"].append(f"EPSS unavailable: {type(exc).__name__}")
    return result
