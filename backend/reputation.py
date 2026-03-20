import requests
import whois
from datetime import datetime

PHISHTANK_APP_KEY = ""  # free key from phishtank.com/api_info

def check_phishtank(url):
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
                "app_key": PHISHTANK_APP_KEY
            }, timeout=5)
        data = response.json()
        result = data.get("results", {})
        return {
            "in_database": result.get("in_database", False),
            "verified_phish": result.get("verified", False),
            "phish_id": result.get("phish_id", None)
        }
    except:
        return {"in_database": False, "verified_phish": False, "phish_id": None}

def check_domain_age(url):
    try:
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
            return {
                "domain": domain,
                "age_days": age_days,
                "is_new": age_days < 180
            }
    except:
        pass
    return {"domain": None, "age_days": None, "is_new": None}

def get_reputation(url):
    phishtank = check_phishtank(url)
    domain_age = check_domain_age(url)
    reputation_score = 0
    if phishtank["verified_phish"]: reputation_score += 40
    if domain_age["is_new"]: reputation_score += 20
    return {
        "phishtank": phishtank,
        "domain_age": domain_age,
        "reputation_score": reputation_score
    }