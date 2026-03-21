import requests
import time

BACKEND = 'http://127.0.0.1:5000'

test_urls = [
    'http://paypal-login-secure.xyz',
    'https://google.com',
    'http://192.168.1.1/login',
    'https://amazon-security-update.xyz/verify',
    'https://github.com',
    'http://bank-account-verify.top/login',
    'https://netflix.com',
    'http://secure-paypal-update.xyz',
    'https://microsoft.com',
    'http://xn--pypal-4ve.com/login'
]

print("=" * 55)
print(f"{'URL':<40} {'Time':>8} {'Result':>10}")
print("=" * 55)

times = []
for url in test_urls:
    start = time.time()
    r = requests.post(f'{BACKEND}/predict', json={'url': url}, timeout=10)
    ms = round((time.time() - start) * 1000, 1)
    times.append(ms)
    data = r.json()
    level = data['threat_level']
    short_url = url[:38] + '.' if len(url) > 38 else url
    print(f"{short_url:<40} {ms:>6}ms {level:>12}")

print("=" * 55)
print(f"Average latency : {sum(times)/len(times):.1f}ms")
print(f"Min latency     : {min(times):.1f}ms")
print(f"Max latency     : {max(times):.1f}ms")
print("=" * 55)