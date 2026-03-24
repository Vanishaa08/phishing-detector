import requests
from datetime import datetime

PHISHTANK_APP_KEY = ""
VIRUSTOTAL_API_KEY = "a72a2ff976f49a60c37232a37ff2facaf26302a2872e8c68999f945d16519d8f"  # paste your key here

def check_phishtank(url):
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json",
                  "app_key": PHISHTANK_APP_KEY}, timeout=5)
        result = response.json().get("results", {})
        return {
            "in_database": result.get("in_database", False),
            "verified_phish": result.get("verified", False),
            "phish_id": result.get("phish_id", None)
        }
    except:
        return {"in_database": False, "verified_phish": False, "phish_id": None}

def check_virustotal(url):
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=8)

        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            return {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "is_malicious": malicious >= 3,
                "vt_score": f"{malicious}/{total}"
            }
        elif r.status_code == 404:
            # URL not in VT database — submit it
            r2 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}, timeout=8)
            return {
                "malicious_engines": 0,
                "suspicious_engines": 0,
                "total_engines": 0,
                "is_malicious": False,
                "vt_score": "not scanned yet"
            }
    except Exception as e:
        return {
            "malicious_engines": 0,
            "suspicious_engines": 0,
            "total_engines": 0,
            "is_malicious": False,
            "vt_score": f"error: {str(e)[:30]}"
        }

def check_domain_age(url):
    try:
        import whois
        from tldextract import extract
        ext = extract(url)
        domain = ext.registered_domain
        if not domain:
            return {"domain": None, "age_days": None, "is_new": None}
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            return {"domain": domain, "age_days": age_days,
                    "is_new": age_days < 180}
    except:
        pass
    return {"domain": None, "age_days": None, "is_new": None}

def get_reputation(url):
    phishtank = check_phishtank(url)
    virustotal = check_virustotal(url)
    domain_age = check_domain_age(url)

    reputation_score = 0
    if phishtank["verified_phish"]:    reputation_score += 40
    if virustotal["is_malicious"]:     reputation_score += 40
    if virustotal["malicious_engines"] >= 1: reputation_score += 10
    if domain_age["is_new"]:           reputation_score += 20

    return {
        "phishtank": phishtank,
        "virustotal": virustotal,
        "domain_age": domain_age,
        "reputation_score": reputation_score,
        "is_dangerous": reputation_score >= 40
    }