import requests
import json
import time

BACKEND = 'http://127.0.0.1:5000'
passed = 0
failed = 0

def test(name, result, expected):
    global passed, failed
    status = "PASS" if result == expected else "FAIL"
    if status == "PASS": passed += 1
    else: failed += 1
    print(f"  [{status}] {name}")
    if status == "FAIL":
        print(f"         Expected: {expected} | Got: {result}")

print("="*55)
print("PHISHING DETECTOR — API TEST SUITE")
print("="*55)

# 1 — Health check
print("\n[1] Health Check")
r = requests.get(f'{BACKEND}/health')
test("Status running", r.json()['status'], 'running')
test("Threshold set", r.json()['threshold'], 0.35)

# 2 — Safe URLs
print("\n[2] Safe URLs (expect SAFE or LOW_RISK)")
safe_urls = [
    'https://google.com',
    'https://github.com',
    'https://microsoft.com',
    'https://stackoverflow.com',
    'https://wikipedia.org'
]
for url in safe_urls:
    r = requests.post(f'{BACKEND}/predict', json={'url': url})
    d = r.json()
    test(url[:45], d['threat_level'] in ['SAFE','LOW_RISK','SUSPICIOUS'], True)

# 3 — Phishing URLs (expect DANGEROUS or SUSPICIOUS)
print("\n[3] Phishing URLs (expect DANGEROUS/SUSPICIOUS)")
phishing_urls = [
    'http://paypal-login-secure.xyz',
    'http://192.168.1.1/login',
    'http://bank-account-verify.top/login',
    'http://secure-paypal-update.xyz',
    'http://amazon-security-alert.xyz/verify',
    'http://apple-id-verify.online/login',
    'http://xn--pypal-4ve.com',
    'http://login.paypal.com.evil.xyz',
]
for url in phishing_urls:
    r = requests.post(f'{BACKEND}/predict', json={'url': url})
    d = r.json()
    test(url[:45], d['threat_level'] in ['DANGEROUS','SUSPICIOUS'], True)

# 4 — Edge cases
print("\n[4] Edge Cases")
r = requests.post(f'{BACKEND}/predict', json={'url': ''})
test("Empty URL returns 400", r.status_code, 400)

r = requests.post(f'{BACKEND}/predict', json={'url': 'not-a-url'})
test("Invalid URL handled", r.status_code, 200)

r = requests.post(f'{BACKEND}/predict', json={})
test("Missing URL returns 400", r.status_code, 400)

# 5 — Analyze endpoint
print("\n[5] Analyze Endpoint")
payload = {
    'email_text': 'urgent verify your account immediately',
    'urls': ['http://paypal-login-secure.xyz','https://google.com'],
    'sender': 'security@paypal-fake.xyz'
}
r = requests.post(f'{BACKEND}/analyze', json=payload)
d = r.json()
test("Returns 2 results", len(d['results']), 2)
test("Threat count > 0", d['threat_count'] > 0, True)
test("Has response time", 'response_time_ms' in d, True)

# 6 — Logs endpoint
print("\n[6] Logs Endpoint")
r = requests.get(f'{BACKEND}/logs')
test("Logs returns list", isinstance(r.json(), list), True)

# 7 — Performance
print("\n[7] Performance Test (10 requests)")
times = []
for _ in range(10):
    start = time.time()
    requests.post(f'{BACKEND}/predict',
        json={'url': 'http://paypal-login-secure.xyz'})
    times.append((time.time()-start)*1000)
avg = sum(times)/len(times)
test(f"Avg latency < 300ms (got {avg:.0f}ms)", avg < 300, True)

# Summary
print("\n" + "="*55)
print(f"RESULTS: {passed} passed / {failed} failed / {passed+failed} total")
print("="*55)

